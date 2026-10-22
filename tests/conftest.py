import asyncio
import gc
import logging
import os
import stat
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

logging.getLogger("quic").setLevel(logging.CRITICAL + 1)
logging.getLogger("asyncio").setLevel(logging.CRITICAL + 1)
logging.getLogger("parso").setLevel(logging.CRITICAL + 1)
logging.getLogger("blib2to3").setLevel(logging.CRITICAL + 1)
logging.getLogger("urllib3").setLevel(logging.CRITICAL + 1)


def _open_fds() -> Optional[set[int]]:
    """The fds this process has open, or None where the platform does not list them (Windows)."""
    for fd_dir in ("/dev/fd", "/proc/self/fd"):
        try:
            listed = {int(name) for name in os.listdir(fd_dir)}
        except (FileNotFoundError, NotADirectoryError):
            continue
        # drop the fd listdir() itself held while listing
        return {fd for fd in listed if _fd_kind(fd) is not None}
    return None


def _fd_kind(fd: int) -> Optional[str]:
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        return None
    return "socket" if stat.S_ISSOCK(mode) else "fd"


@pytest.fixture
async def socket_hygiene() -> AsyncGenerator[None, None]:
    """Fail the test if it leaves a socket behind: an fd it opened still open, a transport not
    closing, or the loop still watching an fd (a stale registration, which wakes nothing once the
    number is reused). Collects garbage first, so an unclosed object's ResourceWarning lands here."""
    loop = asyncio.get_running_loop()
    before = _open_fds()
    yield
    for _ in range(5):
        await asyncio.sleep(0)  # let close callbacks run
    gc.collect()
    problems: list[str] = []
    for fd, transport in list(getattr(loop, "_transports", {}).items()):
        if not transport.is_closing():
            problems.append(f"transport still open on fd {fd}: {transport!r}")
    selector = getattr(loop, "_selector", None)
    if selector is not None:
        wakeup = loop._ssock.fileno()  # pyright: ignore[reportAttributeAccessIssue]
        problems.extend(
            f"loop still watches fd {fd} ({_fd_kind(fd) or 'closed'})" for fd in selector.get_map() if fd != wakeup
        )
    after = _open_fds()
    if before is not None and after is not None:
        problems.extend(f"leaked {_fd_kind(fd)} fd {fd}" for fd in sorted(after - before))
    assert not problems, "; ".join(problems)


def pytest_addoption(parser):
    parser.addoption("--rsd", default=None, type=str, nargs=2, action="store")
    parser.addoption("--tunnel", default=None, type=str, action="store")
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
    """
    for item in items:
        if DEVICE_FIXTURES.intersection(getattr(item, "fixturenames", ())):
            item.add_marker(pytest.mark.device)


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


async def _create_usbmux_client() -> UsbmuxLockdownClient:
    try:
        return await create_using_usbmux()
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


@pytest_asyncio.fixture(scope="function")
async def service_provider(
    rsd_option, tunnel_option
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
        tunnel = PreferredRsdTunnel()
        try:
            rsd = await tunnel.aopen()
        except Exception:
            # No tunnel for this device (pre-iOS 17, unpaired, no usable transport). Lockdown
            # services still work over usbmux; the RSD-only ones skip as they did before.
            await tunnel.aclose()
            async with await _create_usbmux_client() as client:
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
async def lockdown() -> AsyncGenerator[UsbmuxLockdownClient, Any]:
    """
    Creates a new lockdown client for each test.
    """
    client = await _create_usbmux_client()
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
