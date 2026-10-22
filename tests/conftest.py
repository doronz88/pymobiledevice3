import asyncio
import contextlib
import dataclasses
import logging
import os
import socket
import stat
import time
import weakref
from collections.abc import AsyncGenerator, Generator
from typing import Any, Optional, Union

import pytest
import pytest_asyncio

# Must precede the other first-party imports (isort keeps it first): on Python 3.15+ this makes
# pymobiledevice3-internal imports lazy for the whole test run, exercising the mode the CLI ships.
import pymobiledevice3._lazy_imports  # noqa: F401
from pymobiledevice3.exceptions import (
    ConnectionFailedToUsbmuxdError,
    DeviceNotFoundError,
    InvalidServiceError,
    NoDeviceConnectedError,
)
from pymobiledevice3.lockdown import UsbmuxLockdownClient, create_using_usbmux
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.testmanaged.xcuitest import XCUITestService
from pymobiledevice3.tunneld.api import get_tunneld_devices

pytest_plugins = ["pytester"]

logging.getLogger("quic").setLevel(logging.CRITICAL + 1)
logging.getLogger("asyncio").setLevel(logging.CRITICAL + 1)
logging.getLogger("parso").setLevel(logging.CRITICAL + 1)
logging.getLogger("blib2to3").setLevel(logging.CRITICAL + 1)
logging.getLogger("urllib3").setLevel(logging.CRITICAL + 1)


# Opened by the system resolver on the process's first name lookup and kept for its lifetime.
_SYSTEM_SOCKET_PEERS = ("/var/run/mDNSResponder",)


def _open_fds() -> Optional[set[int]]:
    """The fds this process has open, or None where the platform does not list them (Windows)."""
    for fd_dir in ("/dev/fd", "/proc/self/fd"):
        try:
            listed = {int(name) for name in os.listdir(fd_dir)}
        except (FileNotFoundError, NotADirectoryError):
            continue
        open_fds = set()
        for fd in listed:
            kind = _fd_kind(fd)
            # drop the fd listdir() itself held while listing, and the system's own sockets
            if kind is not None and not kind.endswith(tuple(f"-> {peer!r}" for peer in _SYSTEM_SOCKET_PEERS)):
                open_fds.add(fd)
        return open_fds
    return None


def _fd_kind(fd: int) -> Optional[str]:
    """What fd is (a socket with its addresses, or another kind of fd), or None if it is closed."""
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        return None
    if not stat.S_ISSOCK(mode):
        return "fd"
    try:
        sock = socket.socket(fileno=fd)  # raises for a family it can't describe (AF_ROUTE, AF_SYSTEM)
    except OSError:
        return "socket"
    try:
        local = sock.getsockname()
        try:
            peer: Any = sock.getpeername()
        except OSError:
            peer = None
    except OSError:
        return "socket"
    finally:
        sock.detach()  # the fd stays its owner's
    return f"socket {local!r} -> {peer!r}"


class _SocketRecording:
    """The sockets created while it is active (every platform, every event loop), held weakly."""

    def __init__(self) -> None:
        self._sockets: list[weakref.ref[socket.socket]] = []

    def add(self, sock: socket.socket) -> None:
        self._sockets.append(weakref.ref(sock))

    def open_sockets(self) -> list[socket.socket]:
        sockets = (ref() for ref in list(self._sockets))
        return [sock for sock in sockets if sock is not None and sock.fileno() != -1]


# Compared by identity, so ending one recording never ends another.
_socket_recordings: list[_SocketRecording] = []


_socket_init = socket.socket.__init__


def _recorded_socket_init(self: socket.socket, *args: Any, **kwargs: Any) -> None:
    # Here rather than an audit hook: Windows raises no socket.__new__ event for a socket made
    # from an existing fd (accept(), socketpair()).
    _socket_init(self, *args, **kwargs)
    # Only the innermost recording takes a socket: once it ends, the socket was closed or
    # reported, and the recordings around it (a fixture's around a test's) never see it.
    if _socket_recordings:
        _socket_recordings[-1].add(self)


socket.socket.__init__ = _recorded_socket_init


@contextlib.contextmanager
def _recording_sockets() -> Generator[_SocketRecording, None, None]:
    recording = _SocketRecording()
    _socket_recordings.append(recording)
    try:
        yield recording
    finally:
        _socket_recordings.remove(recording)


@dataclasses.dataclass
class _WideFixture:
    """A module- or session-scoped fixture alive now, with what it may hold until its teardown."""

    fixturedef: Any
    recording: _SocketRecording
    fds_before: Optional[set[int]]
    fds_opened: frozenset[int]


_wide_fixtures: list[_WideFixture] = []


def _leaks(
    recording: _SocketRecording, fds_before: Optional[set[int]], held_fds: frozenset[int] = frozenset()
) -> dict[int, str]:
    """By fd: the sockets in a recording still open, and the fds opened since ``fds_before``
    (where listable) other than ``held_fds``."""
    leaks = {sock.fileno(): f"socket left open: {sock!r}" for sock in recording.open_sockets()}
    if fds_before is not None:
        for fd in sorted((_open_fds() or set()) - fds_before - held_fds - leaks.keys()):
            leaks[fd] = f"leaked {_fd_kind(fd)} fd {fd}"
    return leaks


def _reported(leaks: dict[int, str]) -> list[str]:
    """Mark leaks as reported, so the wider-scoped fixtures still alive around them don't report them again."""
    for fixture in _wide_fixtures:
        if fixture.fds_before is not None:
            fixture.fds_before.update(leaks)
    return list(leaks.values())


_FD_SETTLE_SECONDS = 1.0


async def _loop_tick(loop: asyncio.AbstractEventLoop, delay: float = 0) -> None:
    """Yield to the loop without asyncio.sleep, which a test may have monkeypatched."""
    waiter = loop.create_future()
    loop.call_later(delay, lambda: waiter.done() or waiter.set_result(None))
    await waiter


@pytest.fixture
async def socket_hygiene() -> AsyncGenerator[None, None]:
    """Fail the test if it leaves a socket behind: a socket object it created still open (on any
    loop, or none: an unclosed loop keeps its self-pipe sockets), an fd it opened still open, a
    transport not closing, or the loop still watching an fd (a stale registration, which wakes
    nothing once the number is reused). A socket dropped without close() is caught too: it warned
    as it was finalized, inside the test."""
    loop = asyncio.get_running_loop()
    with _recording_sockets() as recording:
        before = _open_fds()
        yield
        problems = await _loop_problems(loop)
        # A server or portal thread may close its socket a moment after the test returns; a leak
        # is a socket that is still open once that settles.
        deadline = loop.time() + _FD_SETTLE_SECONDS
        leaks = _leaks(recording, before)
        while leaks and loop.time() < deadline:
            await _loop_tick(loop, 0.01)
            leaks = _leaks(recording, before)
    problems.extend(_reported(leaks))
    assert not problems, "; ".join(problems)


async def _loop_problems(loop: asyncio.AbstractEventLoop) -> list[str]:
    """Transports the test left open on its loop, and fds the loop still watches."""
    for _ in range(5):
        await _loop_tick(loop)  # let close callbacks run
    problems: list[str] = []
    for fd, transport in list(getattr(loop, "_transports", {}).items()):
        if not transport.is_closing():
            problems.append(f"transport still open on fd {fd}: {transport!r}")
    # (a proactor loop has no selector, though it calls its proactor _selector)
    if isinstance(loop, asyncio.SelectorEventLoop):
        selector = loop._selector  # pyright: ignore[reportAttributeAccessIssue]
        wakeup = loop._ssock.fileno()  # pyright: ignore[reportAttributeAccessIssue]
        problems.extend(
            f"loop still watches fd {fd} ({_fd_kind(fd) or 'closed'})" for fd in selector.get_map() if fd != wakeup
        )
    return problems


@pytest.hookimpl(wrapper=True)
def pytest_fixture_setup(fixturedef: Any, request: pytest.FixtureRequest) -> Generator[None, object, object]:
    """Record what a wider-scoped fixture opens: its sockets outlive each test by design, so
    `socket_hygiene` leaves them alone, and they are checked at the fixture's own teardown."""
    if fixturedef.scope == "function":
        return (yield)
    recording = _SocketRecording()
    _socket_recordings.append(recording)
    before = _open_fds()
    try:
        result = yield
    except BaseException:
        _socket_recordings.remove(recording)
        raise
    after = _open_fds()
    opened = frozenset(after - before) if after is not None and before is not None else frozenset()
    _wide_fixtures.append(_WideFixture(fixturedef, recording, before, opened))
    return result


def pytest_fixture_post_finalizer(fixturedef: Any, request: pytest.FixtureRequest) -> None:
    """Fail a wider-scoped fixture's teardown if it leaves a socket behind."""
    index = next((i for i, fixture in enumerate(_wide_fixtures) if fixture.fixturedef is fixturedef), None)
    if index is None:
        return
    fixture = _wide_fixtures.pop(index)
    _socket_recordings.remove(fixture.recording)
    # A wider fixture set up after this one (a session fixture first requested inside a module)
    # is still alive, and so are the fds it opened.
    held_fds = frozenset(fd for later in _wide_fixtures[index:] for fd in later.fds_opened)
    deadline = time.monotonic() + _FD_SETTLE_SECONDS
    leaks = _leaks(fixture.recording, fixture.fds_before, held_fds)
    while leaks and time.monotonic() < deadline:
        time.sleep(0.01)
        leaks = _leaks(fixture.recording, fixture.fds_before, held_fds)
    assert not leaks, f"fixture {fixturedef.argname!r} left: " + "; ".join(_reported(leaks))


def pytest_addoption(parser):
    parser.addoption("--rsd", default=None, type=str, nargs=2, action="store")
    parser.addoption("--tunnel", default=None, type=str, action="store")
    parser.addoption("--udid", default=None, help="The device to test (default: the first USB device)")
    parser.addoption(
        "--xcuitest-config",
        default=None,
        metavar="PATH",
        help="Path to xcuitest JSON config file",
    )


NO_DEVICE_SKIP_REASON = "No test device is available through usbmuxd"

# Fixtures that open a connection to a physical device. Tests reaching a device any
# other way must carry an explicit ``@pytest.mark.device``.
DEVICE_FIXTURES = frozenset({"lockdown", "service_provider", "dvt", "xcuitest_service"})


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-mark every test whose fixture closure reaches a physical device.

    CI runs ``pytest -m "not device"``, so the device-free portion of the suite is
    exercised on every merge without test authors having to remember a marker: using
    one of the device-backed fixtures (directly or through a derived fixture) is what
    makes a test a device test.

    Every test also runs under `socket_hygiene`, so a leaked socket, an open transport or a stale
    loop watch fails the test that caused it.
    """
    for item in items:
        fixturenames = getattr(item, "fixturenames", None)
        if fixturenames is None:
            continue
        if DEVICE_FIXTURES.intersection(fixturenames):
            item.add_marker(pytest.mark.device)
        if "socket_hygiene" not in fixturenames:
            # Ahead of the other function-scoped fixtures, so it is torn down after them (once they
            # closed what they opened), but behind the wider-scoped ones, whose sockets outlive
            # the test by design.
            fixturenames.insert(_first_function_scoped(item, fixturenames), "socket_hygiene")


def _first_function_scoped(item: pytest.Item, fixturenames: list[str]) -> int:
    name2fixturedefs = getattr(getattr(item, "_fixtureinfo", None), "name2fixturedefs", {})
    for index, name in enumerate(fixturenames):
        definitions = name2fixturedefs.get(name)
        if not definitions or definitions[-1].scope == "function":
            return index
    return len(fixturenames)


def _skip_unless_tunneled(item: pytest.Item, e: InvalidServiceError) -> None:
    funcargs = item.funcargs if isinstance(item, pytest.Function) else {}
    provider = funcargs.get("service_provider") or funcargs.get("lockdown")
    if isinstance(provider, RemoteServiceDiscoveryService):
        raise e
    # service_provider brings a tunnel up on its own, so reaching here means none was available
    # for this device at all - not that the run forgot to ask for one.
    pytest.skip(f"Service requires an RSD tunnel, and none could be established: {e}")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_setup(item: pytest.Item) -> Generator[None, object, object]:
    """Extend the same skip to fixture setup (services opened by fixtures error out here)."""
    try:
        return (yield)
    except InvalidServiceError as e:
        _skip_unless_tunneled(item, e)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Generator[None, object, object]:
    """
    Skip tests that fail solely because an RSD-only service was used without a tunnel.

    iOS 17+ exposes many developer/instruments/relay services only through an RSD
    tunnel. When the suite runs over plain usbmux (no ``--rsd``/``--tunnel``), starting
    such a service raises ``InvalidServiceError``; treat that as a skip. If we are already
    connected through a tunnel, re-raise so genuine regressions still surface.
    """
    try:
        return (yield)
    except InvalidServiceError as e:
        _skip_unless_tunneled(item, e)


async def _create_usbmux_client(udid: Optional[str]) -> UsbmuxLockdownClient:
    try:
        return await create_using_usbmux(serial=udid)
    except (ConnectionFailedToUsbmuxdError, DeviceNotFoundError, NoDeviceConnectedError):
        pytest.skip(NO_DEVICE_SKIP_REASON)


@pytest.fixture(scope="function")
def rsd_option(request):
    """
    Get --rsd option
    """
    return request.config.getoption("--rsd")


@pytest.fixture(scope="function")
def tunnel_option(request):
    """
    Get --tunnel option
    """
    return request.config.getoption("--tunnel")


@pytest.fixture(scope="function")
def udid_option(request):
    """
    Get --udid option
    """
    return request.config.getoption("--udid")


@pytest_asyncio.fixture(scope="function")
async def service_provider(
    rsd_option, tunnel_option, udid_option
) -> AsyncGenerator[Union[RemoteServiceDiscoveryService, UsbmuxLockdownClient, Any]]:
    """
    Creates a new LockdownServiceProvider client for each test.
    """
    if rsd_option is not None:
        async with RemoteServiceDiscoveryService(rsd_option) as rsd:
            yield rsd
    elif tunnel_option is not None:
        rsds = await get_tunneld_devices()
        try:
            if tunnel_option == "":
                try:
                    selected_rsd = rsds[0]
                except IndexError as e:
                    raise DeviceNotFoundError(tunnel_option, "Device not found: tunneld serves no tunnel") from e
            else:
                selected_rsd = next((rsd for rsd in rsds if rsd.udid == tunnel_option), None)
                if selected_rsd is None:
                    raise DeviceNotFoundError(
                        tunnel_option, f"Device not found: tunneld serves no tunnel for udid {tunnel_option}"
                    )

            yield selected_rsd
        finally:
            for rsd in rsds:
                await rsd.close()
    else:
        # No transport asked for: establish one. Every RSD-requiring service is reachable
        # in-process without root - the userspace tunnel (the native one for iOS 17.0-17.3 on
        # macOS) - so those tests run by default instead of skipping until someone supplies tunneld.
        # Per test rather than per session on purpose: the tunnel's asyncio objects belong to the
        # loop that opened them, and the suite runs each test on a loop of its own.
        tunnel = PreferredRsdTunnel(serial=udid_option)
        try:
            rsd = await tunnel.aopen()
        except Exception:
            # No tunnel for this device (pre-iOS 17, unpaired, no usable transport). Lockdown
            # services still work over usbmux; the RSD-only ones skip as they did before.
            await tunnel.aclose()
            async with await _create_usbmux_client(udid_option) as client:
                yield client
        else:
            try:
                yield rsd
            finally:
                await tunnel.aclose()


@pytest_asyncio.fixture(scope="function")
async def dvt(service_provider) -> AsyncGenerator[DvtProvider, Any]:
    """
    Creates a new DVT provider for each test.
    """
    try:
        async with DvtProvider(service_provider) as dvt:
            yield dvt
    except InvalidServiceError:
        pytest.skip("Skipping DVT-based test since the DVT provider service isn't accessible")


@pytest_asyncio.fixture(scope="function")
async def lockdown(udid_option) -> AsyncGenerator[UsbmuxLockdownClient, Any]:
    """
    Creates a new lockdown client for each test.
    """
    client = await _create_usbmux_client(udid_option)
    async with client:
        yield client


@pytest_asyncio.fixture(scope="function")
async def xcuitest_service(service_provider) -> XCUITestService:
    """
    Creates a new XCUITestService client for each test.
    """
    try:
        # check manually, as the XCUITestService currently connect to the needed services
        # only when starting the test ( shall we change this? )
        async with DvtProvider(service_provider):
            pass
        return XCUITestService(service_provider)
    except InvalidServiceError:
        pytest.skip("Skipping XCUITest-based test since the service isn't accessible")
