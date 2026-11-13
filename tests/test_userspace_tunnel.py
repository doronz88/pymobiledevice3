"""Tests for the userspace tunnel: throughput tuning and relay-teardown behavior.

The tuning rides pmd-pytcp's public ``tcp.rcv_wnd_max`` / ``tcp.snd_mss_max`` sysctls; these
tests pin that :func:`throughput_sysctls` emits values the installed pmd-pytcp actually accepts
(and silently omits any a too-old pmd-pytcp lacks). The cross-platform/portability concerns that
used to live in a host-side compatibility layer are now handled inside pmd-pytcp itself.

The relay tests drive :class:`UserspaceDialPlane` against a fake of pmd-pytcp's pure-asyncio
TCP socket (``recv``/``send``/``connect`` are coroutines; ``shutdown``/``close`` are sync).
They keep the issue #1756 regressions meaningful in the asyncio world: EOF propagation in both
directions, prompt dial-plane exit with a parked relay, and — since the stack no longer uses
threads at all — that relaying spawns none.
"""

import asyncio
import socket
import struct
import sys
import threading
from contextlib import AsyncExitStack, suppress
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest

from pymobiledevice3.exceptions import (
    ConnectionFailedToUsbmuxdError,
    DeviceNotFoundError,
    InvalidServiceError,
    NoDeviceConnectedError,
    PasswordRequiredError,
    UserspaceTunnelUnavailableError,
)

# pmd-pytcp supports Python >= 3.9; skip the whole module when it's absent.
pytest.importorskip("pmd_pytcp")

from pmd_pytcp.stack import sysctl

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.remote.userspace_tunnel import UserspaceDialPlane, UserspaceTun
from pymobiledevice3.service_connection import close_stream_writer


def test_throughput_sysctls_only_emits_registered_knobs():
    # Every emitted key must be accepted by stack.init's sysctl bag — i.e. its (base) knob is
    # registered in the installed pmd-pytcp. This is what keeps an older fork from crashing.
    registered = sysctl.list_keys()
    for key in userspace_tunnel.throughput_sysctls():
        base = key.replace(".default.", ".") if ".default." in key else key
        assert base in registered, f"{key!r} emitted but {base!r} is not a registered sysctl"


def test_throughput_sysctls_values_when_supported():
    knobs = userspace_tunnel.throughput_sysctls()
    if "tcp.rcv_wnd_max" not in sysctl.list_keys():
        pytest.skip("installed pmd-pytcp predates the throughput sysctls")
    assert knobs["tcp.rcv_wnd_max"] == userspace_tunnel.MAX_RECV_WINDOW
    assert knobs["tcp.default.base_mss"] == userspace_tunnel.BASE_MSS_SEED
    assert knobs["tcp.default.mtu_probing"] == 2
    if "tcp.delayed_ack.delay_ms" in sysctl.list_keys():
        assert knobs["tcp.delayed_ack.delay_ms"] == userspace_tunnel.ACK_DELAY_MS


def test_throughput_sysctls_round_trip_through_sysctl_set():
    # The emitted entries must apply cleanly the way stack.init(sysctls=...) applies them.
    for key, value in userspace_tunnel.throughput_sysctls().items():
        sysctl.set(key, value)
    sysctl.reset_to_defaults()


# --- relay behavior (regressions for issue #1756, asyncio edition) ------------------------

DEVICE_ADDR = "fd00::1"


class FakePyTcpSocket:
    """The pmd-pytcp pure-asyncio TCP socket surface the relay uses: ``recv``/``send`` are
    coroutines; ``shutdown``/``close`` are sync. ``recv()`` waits until inbound data/EOF; a
    ``shutdown(SHUT_RD/SHUT_RDWR)`` wakes a parked recv with EOF."""

    def __init__(self) -> None:
        self._rx: list[Any] = []
        self._eof = False
        self._readable = asyncio.Event()
        self.sent: list[Any] = []
        self.shutdown_calls: list[Any] = []
        self.closed = asyncio.Event()

    # --- device-side test controls ---
    def feed(self, data: bytes) -> None:
        self._rx.append(data)
        self._readable.set()

    def feed_eof(self) -> None:
        self._eof = True
        self._readable.set()

    # --- relay-facing surface ---
    async def recv(self, bufsize: int, timeout=None) -> bytes:
        while not (self._rx or self._eof):
            self._readable.clear()
            if timeout is None:
                await self._readable.wait()
            else:
                try:
                    await asyncio.wait_for(self._readable.wait(), timeout)
                except asyncio.TimeoutError:
                    raise TimeoutError("TCP Socket - Receive operation timed out.") from None
        if self._rx:
            return self._rx.pop(0)
        return b""

    async def send(self, data: bytes) -> int:
        self.sent.append(bytes(data))
        return len(data)

    def shutdown(self, how) -> None:
        self.shutdown_calls.append(int(how))
        if int(how) in (0, 2):  # SHUT_RD / SHUT_RDWR wake a parked recv() with EOF
            self.feed_eof()

    def close(self) -> None:
        self.closed.set()
        # pmd-pytcp >= 0.3.4: the session's death (close/RST/reap) wakes a
        # parked recv(), which then reports EOF or a connection error
        # instead of sleeping forever.
        self.feed_eof()


class FakeTun:
    """Just enough of :class:`UserspaceTun` for :class:`UserspaceDialPlane`."""

    def __init__(self) -> None:
        self.socks: list[Any] = []

    async def connect_tcp(self, addr: str, port: int) -> FakePyTcpSocket:
        sock = FakePyTcpSocket()
        self.socks.append(sock)
        return sock


async def _poll_until(predicate, timeout: float = 5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        value = predicate()
        if value:
            return value
        await asyncio.sleep(0.01)
    raise AssertionError("condition not met within timeout")


async def test_relay_full_conversation_and_clean_completion():
    # ping/pong through the relay, then a client-initiated close: the client's EOF must fully
    # close the pytcp socket (the FIN still reaches the device; the session becomes an orphan
    # the stack's FIN_WAIT_2 reaper owns) and the handler must finish on its own — with no
    # task left behind and WITHOUT requiring any further device action.
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        reader, writer = await dial_plane.dial(DEVICE_ADDR, 1234)
        psock = (await _poll_until(lambda: tun.socks))[0]

        writer.write(b"ping")
        await writer.drain()
        await _poll_until(lambda: psock.sent == [b"ping"])
        psock.feed(b"pong")
        assert await reader.readexactly(4) == b"pong"

        writer.close()
        await asyncio.wait_for(psock.closed.wait(), timeout=5)
        await _poll_until(lambda: not dial_plane._relay_tasks)  # handler completed unaided


async def test_abandoned_client_with_silent_device_leaks_nothing():
    # The dominant real-world leak (measured live: 24 of 30 abandoned service connections):
    # the client vanishes while the device neither sends a byte nor FINs. A half-close kept
    # the pytcp socket open — a reader existed — so the stack's orphan-only FIN_WAIT_2 reaper
    # never armed and the handler parked at recv() until tunnel teardown. The relay must fully
    # close the socket on client EOF so the session is orphaned (reaper territory) and the
    # handler finishes promptly.
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        _reader, writer = await dial_plane.dial(DEVICE_ADDR, 4321)
        psock = (await _poll_until(lambda: tun.socks))[0]

        writer.close()  # the client is gone; the device stays silent

        await asyncio.wait_for(psock.closed.wait(), timeout=5)
        await _poll_until(lambda: not dial_plane._relay_tasks)


async def test_device_eof_reaches_client():
    # The device closing its side must propagate to the client as EOF (write_eof), otherwise
    # the client never learns the stream ended and the pair idles forever.
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        reader, writer = await dial_plane.dial(DEVICE_ADDR, 1111)
        psock = (await _poll_until(lambda: tun.socks))[0]
        psock.feed(b"data")
        psock.feed_eof()
        assert await asyncio.wait_for(reader.read(), timeout=5) == b"data"  # read() to EOF
        writer.close()


async def test_dial_plane_exit_cancels_parked_relay():
    # Regression for the #1756 hang: with a relay parked on device traffic (recv awaiting, no
    # EOF in sight), __aexit__ used to hang in Server.wait_closed() (which waits for in-flight
    # handlers since Python 3.12.1). Exit must complete promptly, leave no relay task behind,
    # and still tear the pytcp socket down.
    tun = FakeTun()
    dial_plane = UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR)
    await dial_plane.__aenter__()
    _reader, writer = await dial_plane.dial(DEVICE_ADDR, 5678)
    await _poll_until(lambda: tun.socks)

    await asyncio.wait_for(dial_plane.__aexit__(None, None, None), timeout=5)

    assert not dial_plane._relay_tasks
    await asyncio.wait_for(tun.socks[0].closed.wait(), timeout=5)
    writer.close()


async def test_relaying_spawns_no_threads():
    # The pure-asyncio relay must not create ANY thread — the #1756 pile-up (120 parked
    # rx_pump threads) is structurally impossible now, and this pins it that way.
    baseline = set(threading.enumerate())
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        writers = []
        for _ in range(5):
            _reader, writer = await dial_plane.dial(DEVICE_ADDR, 9999)
            writers.append(writer)
        await _poll_until(lambda: len(tun.socks) == 5)
        assert set(threading.enumerate()) == baseline
    for writer in writers:
        writer.close()


async def test_dial_plane_exit_completes_when_dial_races_teardown():
    # Teardown right after a dial — e.g. the dialer's caller raised during connection setup —
    # cancels the relay before it has run a single step, so its own cleanup never runs. Exit must
    # still complete promptly with no relay task left behind, and the caller's stream must end.
    class StallingTun:
        async def connect_tcp(self, addr: str, port: int) -> FakePyTcpSocket:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    dial_plane = UserspaceDialPlane(cast(UserspaceTun, StallingTun()), DEVICE_ADDR)
    await dial_plane.__aenter__()
    reader, writer = await dial_plane.dial(DEVICE_ADDR, 3333)

    # No yield to the loop between dial and teardown: the relay must not have started yet.
    await asyncio.wait_for(dial_plane.__aexit__(None, None, None), timeout=5)

    assert not dial_plane._relay_tasks
    assert await asyncio.wait_for(reader.read(), timeout=5) == b""
    await close_stream_writer(writer)


async def test_dial_after_close_raises():
    # A dial racing (or following) teardown must fail loudly: letting it through started a
    # relay nothing would ever cancel and handed the caller a stream that only ever yields EOF.
    # The window is real since the transport watcher runs teardown concurrently with dials.
    tun = FakeTun()
    dial_plane = UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR)
    async with dial_plane:
        pass
    with pytest.raises(ConnectionError):
        await dial_plane.dial(DEVICE_ADDR, 5555)
    assert not tun.socks


@pytest.mark.skipif(sys.platform == "win32", reason="CPython emulates socketpair() over loopback TCP on Windows")
async def test_relay_has_no_listener():
    # Each dial is a socketpair: an unbound AF_UNIX socket no other process can connect to, so the
    # device's services are never reachable through the relay from outside this process.
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        _reader, writer = await dial_plane.dial(DEVICE_ADDR, 2222)
        sock = writer.get_extra_info("socket")
        assert sock.family == socket.AF_UNIX
        assert not sock.getsockname()

        await close_stream_writer(writer)
        await _poll_until(lambda: not dial_plane._relay_tasks)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS defaults unix stream sockets to 8 KiB buffers")
async def test_unix_relay_buffers_are_raised(monkeypatch):
    # With macOS's 8 KiB defaults the relay moved 8 KiB per event-loop pass and capped device->host
    # streams at a few MB/s, so both ends of the connection must have the larger buffers.
    relay_buffers = []
    relay_handler = UserspaceDialPlane._relay_handler

    async def recording_relay_handler(self, port, creader, cwriter):
        sock = cwriter.get_extra_info("socket")
        relay_buffers.append((
            sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
            sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
        ))
        await relay_handler(self, port, creader, cwriter)

    monkeypatch.setattr(UserspaceDialPlane, "_relay_handler", recording_relay_handler)
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        _reader, writer = await dial_plane.dial(DEVICE_ADDR, 2222)
        sock = writer.get_extra_info("socket")
        for option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
            assert sock.getsockopt(socket.SOL_SOCKET, option) >= userspace_tunnel.RELAY_SOCKET_BUFFER_SIZE
        server_buffers = (await _poll_until(lambda: relay_buffers))[0]
        assert min(server_buffers) >= userspace_tunnel.RELAY_SOCKET_BUFFER_SIZE

        await close_stream_writer(writer)
        await _poll_until(lambda: not dial_plane._relay_tasks)


async def test_transport_watcher_tears_down_on_transport_death():
    # Device unplug: usbmuxd closes the outer CoreDeviceProxy connection, the transport read
    # task ends (wait_closed returns) and nothing else wakes blocked service reads — the pytcp
    # sessions stay ESTABLISHED and relay pumps park forever (keep-alive can't cover it: a
    # relay's peer is this very process). The watcher must react by running aclose(), whose
    # relay teardown surfaces EOF/errors to every blocked caller. Reproduced live: `dvt oslog`
    # parked forever on USB unplug; with the watcher it exits within a second.
    tunnel = userspace_tunnel.UserspaceRsdTunnel()
    tunnel._exit_stack = AsyncExitStack()

    class FakeTunnelClient:
        async def wait_closed(self) -> None:
            return  # the transport read task has ended

    await asyncio.wait_for(tunnel._watch_transport_closed(cast(Any, FakeTunnelClient())), timeout=5)
    assert tunnel._exit_stack is None  # aclose() ran


class _ParkedTransportClient:
    """Mirrors RemotePairingTcpTunnel.wait_closed(): it awaits the transport read task and
    suppresses that task's CancelledError — which also swallows a cancellation aimed at the
    awaiting task itself."""

    def __init__(self) -> None:
        self.read_task = asyncio.create_task(asyncio.Event().wait())

    async def wait_closed(self) -> None:
        with suppress(asyncio.CancelledError):
            await self.read_task


def test_transport_watcher_quiet_when_asyncio_run_shuts_down(caplog: pytest.LogCaptureFixture) -> None:
    # An embedder returns normally from asyncio.run(main()) with the tunnel still open: the
    # loop teardown cancels every leftover task, including the watcher and the transport read
    # task. That is an orderly shutdown, not a device disconnect — the watcher must neither
    # log the disconnection warning nor skip releasing the tunnel's resources.
    released = []
    tunnel = userspace_tunnel.UserspaceRsdTunnel()

    async def main() -> None:
        async def release() -> None:
            released.append(True)

        tunnel._exit_stack = AsyncExitStack()
        tunnel._exit_stack.push_async_callback(release)
        tunnel._transport_watcher = asyncio.create_task(
            tunnel._watch_transport_closed(cast(Any, _ParkedTransportClient()))
        )
        await asyncio.sleep(0.01)  # watcher parked in wait_closed()

    with caplog.at_level("WARNING", logger=userspace_tunnel.logger.name):
        asyncio.run(main())
    assert "transport closed" not in caplog.text
    assert released
    assert tunnel._exit_stack is None


async def test_transport_watcher_quiet_on_explicit_aclose(caplog: pytest.LogCaptureFixture) -> None:
    tunnel = userspace_tunnel.UserspaceRsdTunnel()
    tunnel._exit_stack = AsyncExitStack()
    client = _ParkedTransportClient()
    tunnel._transport_watcher = asyncio.create_task(tunnel._watch_transport_closed(cast(Any, client)))
    await asyncio.sleep(0.01)
    with caplog.at_level("WARNING", logger=userspace_tunnel.logger.name):
        await asyncio.wait_for(tunnel.aclose(), timeout=5)
        await asyncio.sleep(0.01)
    assert "transport closed" not in caplog.text
    client.read_task.cancel()


async def test_transport_watcher_warns_on_unexpected_transport_loss(caplog: pytest.LogCaptureFixture) -> None:
    tunnel = userspace_tunnel.UserspaceRsdTunnel()
    tunnel._exit_stack = AsyncExitStack()
    client = _ParkedTransportClient()
    watcher = asyncio.create_task(tunnel._watch_transport_closed(cast(Any, client)))
    await asyncio.sleep(0.01)
    with caplog.at_level("WARNING", logger=userspace_tunnel.logger.name):
        client.read_task.cancel()  # the transport read task ends on its own (cable pulled)
        await asyncio.wait_for(watcher, timeout=5)
    assert "transport closed" in caplog.text
    assert tunnel._exit_stack is None


async def test_teardown_waits_for_closed_connections_to_emit_their_fin():
    # close() only queues the FIN, and the stack stops right after the dial plane exits: teardown
    # must hold on until the stack has sent it, or the device keeps the connection open.
    class State:
        name = "ESTABLISHED"

    tun = FakeTun()
    dial_plane = UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR)
    await dial_plane.__aenter__()
    _, writer = await dial_plane.dial(DEVICE_ADDR, 1234)
    psock = (await _poll_until(lambda: tun.socks))[0]
    psock.state = State()
    writer.close()
    await asyncio.wait_for(psock.closed.wait(), timeout=5)
    await _poll_until(lambda: not dial_plane._relay_tasks)

    def emit_fin() -> None:
        psock.state.name = "FIN_WAIT_1"

    loop = asyncio.get_running_loop()
    loop.call_later(0.05, emit_fin)
    started = loop.time()
    await asyncio.wait_for(dial_plane.__aexit__(None, None, None), timeout=5)

    assert psock.state.name == "FIN_WAIT_1"
    assert loop.time() - started >= 0.05
    await close_stream_writer(writer)


async def test_aclose_waits_for_watcher_teardown():
    # An explicit aclose() while the transport watcher is mid-unwind (device just
    # disconnected) must wait for that unwind, not return early — aclose() returning is the
    # signal that the process-global pytcp stack is really stopped and a tunnel may be
    # reopened.
    released = []

    async def slow_release() -> None:
        await asyncio.sleep(0.1)
        released.append(True)

    tunnel = userspace_tunnel.UserspaceRsdTunnel()
    tunnel._exit_stack = AsyncExitStack()
    tunnel._exit_stack.push_async_callback(slow_release)

    class FakeTunnelClient:
        async def wait_closed(self) -> None:
            return  # the transport read task has ended

    watcher = asyncio.create_task(tunnel._watch_transport_closed(cast(Any, FakeTunnelClient())))
    await asyncio.sleep(0.02)  # watcher is now inside slow_release
    await asyncio.wait_for(tunnel.aclose(), timeout=5)
    assert released  # aclose returned only after the watcher's unwind completed
    await watcher


async def test_tun_address_usable_when_up_returns():
    # The stack installs the interface address from its own tasks shortly AFTER stack.start()
    # returns, so up() must not return before the address is usable: a connect issued right
    # after tunnel-up would find no local source address and fail with gaierror. The relay
    # dial path happens to add enough event-loop round trips to win that race today, but an
    # embedder calling connect_tcp() straight after aopen() has no such slack.
    from pmd_net_addr import Ip6Address
    from pmd_pytcp import stack

    from pymobiledevice3.remote.userspace_tunnel import UserspaceTun

    tun = UserspaceTun()
    tun.addr = "fd57:6e64:6572:7761::1"
    try:
        await tun.up()
        target = Ip6Address(tun.addr)
        assert any(host.address == target for host in stack.local_ip6_hosts()), (
            "up() returned before the stack address was usable for source-address selection"
        )
    finally:
        await tun.close()


# --- _create_no_root_tunnel_provider transport selection ----------------------


@pytest.fixture
def mock_tunnel_provider():
    """Mock the external dependencies of _create_no_root_tunnel_provider."""

    class Mocks:
        def __init__(self) -> None:
            self.create_using_usbmux = AsyncMock()
            self.core_device_proxy_create = AsyncMock()

    mocks = Mocks()

    with (
        patch.object(userspace_tunnel, "create_using_usbmux", mocks.create_using_usbmux),
        patch.object(
            userspace_tunnel.tunnel_service,
            "CoreDeviceTunnelProxy",
            type("P", (), {"create": staticmethod(mocks.core_device_proxy_create)}),
        ),
    ):
        yield mocks


async def test_no_root_tunnel_usb_succeeds(mock_tunnel_provider):
    """USB device with CoreDeviceProxy — the happy path."""
    fake_lockdown = object()
    fake_proxy = object()
    mock_tunnel_provider.create_using_usbmux.return_value = fake_lockdown
    mock_tunnel_provider.core_device_proxy_create.return_value = fake_proxy

    provider, lockdown = await userspace_tunnel._create_no_root_tunnel_provider(serial=None, autopair=True)
    assert provider is fake_proxy
    assert lockdown is fake_lockdown


@pytest.mark.parametrize("serial", [None, "TEST-UDID-1234"], ids=["no-serial", "with-serial"])
@pytest.mark.parametrize(
    "error",
    [
        NoDeviceConnectedError("no device"),
        DeviceNotFoundError("not found"),
        ConnectionFailedToUsbmuxdError("no usbmuxd"),
    ],
    ids=["no-device", "not-found", "no-usbmuxd"],
)
async def test_usbmux_lookup_failure_propagates(mock_tunnel_provider, error, serial):
    """A device usbmux cannot serve fails right here, with or without a serial.

    Reaching it over Wi-Fi has to be asked for explicitly (``--mobdev2``); browsing bonjour on
    every miss would turn "nothing is connected" into a multi-second wait and could serve a
    device the user never named.
    """
    mock_tunnel_provider.create_using_usbmux.side_effect = error

    with pytest.raises(type(error), match=str(error)):
        await userspace_tunnel._create_no_root_tunnel_provider(serial=serial, autopair=True)


async def test_pairing_error_from_usb_propagates_unchanged(mock_tunnel_provider):
    """A lockdown pairing error from a USB-attached device must propagate untouched."""
    mock_tunnel_provider.create_using_usbmux.side_effect = PasswordRequiredError("unlock", None, "17.0")

    with pytest.raises(PasswordRequiredError, match="unlock"):
        await userspace_tunnel._create_no_root_tunnel_provider(serial="TEST-UDID", autopair=True)


async def test_remotepairing_fallback_disabled_with_invalid_service(mock_tunnel_provider):
    """USB device with no CoreDeviceProxy + remotepairing_fallback=False → UserspaceTunnelUnavailableError."""

    class FakeLockdown:
        async def close(self):
            pass

    mock_tunnel_provider.create_using_usbmux.return_value = FakeLockdown()
    mock_tunnel_provider.core_device_proxy_create.side_effect = InvalidServiceError("no CoreDeviceProxy", None, "17.0")

    with pytest.raises(UserspaceTunnelUnavailableError, match="RemotePairing fallback was disabled"):
        await userspace_tunnel._create_no_root_tunnel_provider(serial=None, autopair=True, remotepairing_fallback=False)


async def test_remotepairing_asks_for_the_device_it_handshook_with(mock_tunnel_provider, monkeypatch):
    """With no --udid, the RemotePairing lookup must still name the USB device we just talked to.

    Otherwise every paired device on the network is contacted and the first answer wins, which can
    be a different phone than the command targeted.
    """

    class FakeLockdown:
        udid = "USB-DEVICE-UDID"

        async def close(self):
            pass

    asked = []

    async def get_remote_pairing_tunnel_services(udid=None, **kwargs):
        asked.append(udid)
        return ["service-for-" + str(udid)]

    mock_tunnel_provider.create_using_usbmux.return_value = FakeLockdown()
    mock_tunnel_provider.core_device_proxy_create.side_effect = InvalidServiceError("no CoreDeviceProxy", None, "17.0")
    monkeypatch.setattr(
        userspace_tunnel.tunnel_service, "get_remote_pairing_tunnel_services", get_remote_pairing_tunnel_services
    )

    provider, lockdown = await userspace_tunnel._create_no_root_tunnel_provider(serial=None, autopair=True)

    assert asked == ["USB-DEVICE-UDID"]
    assert provider == "service-for-USB-DEVICE-UDID"
    assert lockdown is None


# --- explicit Wi-Fi (--wifi) device selection ---------------------------------


class _FakeRemotePairing:
    """A connected RemotePairingTunnelService stand-in: only its identity and close() matter here."""

    def __init__(self, remote_identifier: str) -> None:
        self.remote_identifier = remote_identifier
        self.closed = False

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def wifi_lookup(monkeypatch):
    """Fake the pair records on disk and the bonjour lookup; expose what was asked for."""

    class State:
        def __init__(self) -> None:
            self.records: list[str] = []
            self.found: list[_FakeRemotePairing] = []
            self.asked: list[Any] = []

    state = State()

    def iter_records():
        for identifier in state.records:
            yield identifier, None, {}

    async def get_remote_pairing_tunnel_services(bonjour_timeout=None, udid=None, requery=False, **kwargs):
        state.asked.append((udid, requery))
        return [service for service in state.found if udid is None or service.remote_identifier == udid]

    monkeypatch.setattr(userspace_tunnel, "iter_remote_pair_records_by_identifier", iter_records)
    monkeypatch.setattr(
        userspace_tunnel.tunnel_service, "get_remote_pairing_tunnel_services", get_remote_pairing_tunnel_services
    )
    return state


async def test_wifi_with_a_pairing_identifier_asks_bonjour_for_that_device(wifi_lookup):
    wifi_lookup.records = ["PAIRING-ID", "OTHER"]
    wifi_lookup.found = [_FakeRemotePairing("PAIRING-ID"), _FakeRemotePairing("OTHER")]

    provider = await userspace_tunnel._create_wifi_tunnel_provider("PAIRING-ID")

    # the explicit Wi-Fi path is the one browse that re-queries
    assert wifi_lookup.asked == [("PAIRING-ID", True)]
    assert provider.remote_identifier == "PAIRING-ID"


async def test_wifi_refuses_a_device_udid_without_browsing(wifi_lookup):
    # A UDID names no record and only a device's RSD reports it: finding it would mean a tunnel to
    # every paired device, so it is refused and the known pairing identifiers are listed instead.
    wifi_lookup.records = ["PAIRING-ID", "OTHER"]

    with pytest.raises(UserspaceTunnelUnavailableError, match="OTHER, PAIRING-ID"):
        await userspace_tunnel._create_wifi_tunnel_provider("DEVICE-UDID")
    assert wifi_lookup.asked == []


async def test_wifi_without_a_serial_uses_the_only_pair_record(wifi_lookup):
    # One record narrows the browse to it, so the lookup stops at its first answer.
    wifi_lookup.records = ["PAIRING-ID"]
    wifi_lookup.found = [_FakeRemotePairing("PAIRING-ID")]

    provider = await userspace_tunnel._create_wifi_tunnel_provider(None)

    assert wifi_lookup.asked == [("PAIRING-ID", True)]
    assert provider.remote_identifier == "PAIRING-ID"


async def test_wifi_without_a_serial_takes_the_one_device_that_answers(wifi_lookup):
    wifi_lookup.records = ["A", "B"]
    wifi_lookup.found = [_FakeRemotePairing("B")]

    provider = await userspace_tunnel._create_wifi_tunnel_provider(None)

    assert wifi_lookup.asked == [(None, True)]
    assert provider.remote_identifier == "B"


async def test_wifi_without_a_serial_refuses_to_guess_between_devices(wifi_lookup):
    found = [_FakeRemotePairing("A"), _FakeRemotePairing("B")]
    wifi_lookup.records = ["A", "B"]
    wifi_lookup.found = found

    with pytest.raises(UserspaceTunnelUnavailableError, match="--udid"):
        await userspace_tunnel._create_wifi_tunnel_provider(None)
    assert all(service.closed for service in found)


async def test_wifi_keeps_one_service_per_device(wifi_lookup):
    # A device answering on two addresses is connected twice; the extra connection is closed.
    first, second = _FakeRemotePairing("PAIRING-ID"), _FakeRemotePairing("PAIRING-ID")
    wifi_lookup.records = ["PAIRING-ID"]
    wifi_lookup.found = [first, second]

    assert await userspace_tunnel._create_wifi_tunnel_provider(None) is first
    assert second.closed and not first.closed


async def test_wifi_with_no_answer_is_unavailable(wifi_lookup):
    wifi_lookup.records = ["PAIRING-ID"]

    with pytest.raises(UserspaceTunnelUnavailableError):
        await userspace_tunnel._create_wifi_tunnel_provider("PAIRING-ID")


async def test_wifi_establishes_through_the_named_device_without_usbmux(wifi_lookup, mock_tunnel_provider, monkeypatch):
    device = _FakeRemotePairing("PAIRING-ID")
    wifi_lookup.records = ["PAIRING-ID", "OTHER"]
    wifi_lookup.found = [device, _FakeRemotePairing("OTHER")]
    tunnel = userspace_tunnel.UserspaceRsdTunnel(serial="PAIRING-ID", wifi=True)
    established: list[Any] = []

    async def establish(provider, lockdown):
        established.append((provider, lockdown))
        return AsyncExitStack(), "rsd", "result"

    monkeypatch.setattr(tunnel, "_establish", establish)

    _, rsd, _ = await tunnel._establish_over_wifi()

    assert rsd == "rsd"
    assert established == [(device, None)]
    mock_tunnel_provider.create_using_usbmux.assert_not_called()


async def test_remotepairing_prefers_an_explicit_serial(mock_tunnel_provider, monkeypatch):
    """An explicit --udid wins over the handshake, so the caller's choice is never second-guessed."""

    class FakeLockdown:
        udid = "HANDSHAKE-UDID"

        async def close(self):
            pass

    asked = []

    async def get_remote_pairing_tunnel_services(udid=None, **kwargs):
        asked.append(udid)
        return ["service"]

    mock_tunnel_provider.create_using_usbmux.return_value = FakeLockdown()
    mock_tunnel_provider.core_device_proxy_create.side_effect = InvalidServiceError("no CoreDeviceProxy", None, "17.0")
    monkeypatch.setattr(
        userspace_tunnel.tunnel_service, "get_remote_pairing_tunnel_services", get_remote_pairing_tunnel_services
    )

    await userspace_tunnel._create_no_root_tunnel_provider(serial="EXPLICIT-UDID", autopair=True)

    assert asked == ["EXPLICIT-UDID"]


async def test_a_burst_from_the_device_reaches_the_stack_whole():
    # Without root, Linux caps the socketpair buffers at net.core.rmem_max (~416 KiB): a burst
    # sent through them lost every packet past that. A 4 KiB buffer stands in for the cap here.
    from pmd_pytcp import stack

    tun = UserspaceTun()
    for s in (tun._peer, tun._pend):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    tun.addr = "fd57:6e64:6572:7761::1"
    try:
        await tun.up()
        assert tun._ifidx is not None
        link = stack.link.interface(tun._ifidx)
        before = link.stats.rx_packets
        for i in range(64):
            tun.write(userspace_tunnel.LOOPBACK_HEADER + b"\x60" + bytes([i]) * 999)
        assert link.stats.rx_packets - before == 64
    finally:
        await tun.close()


async def test_write_after_close_is_ignored():
    tun = UserspaceTun()
    tun.addr = "fd57:6e64:6572:7761::1"
    await tun.up()
    await tun.close()
    tun.write(userspace_tunnel.LOOPBACK_HEADER + b"\x60" + b"\x00" * 39)


# --- device-silence nudge -----------------------------------------------------------------

_HOST_ADDR = "fd57:6e64:6572:7761::2"


def _tun_with_nudge(monkeypatch: pytest.MonkeyPatch) -> UserspaceTun:
    monkeypatch.setattr(userspace_tunnel, "NUDGE_DELAY", 0.02)
    tun = UserspaceTun()
    tun._pend.setblocking(False)
    tun._nudge_frame = userspace_tunnel._ETH_HDR_TO_PEER + userspace_tunnel._icmp6_echo_request(_HOST_ADDR, DEVICE_ADDR)
    return tun


def _stack_sends(tun: UserspaceTun, ipv6: bytes) -> None:
    tun._pend.send(userspace_tunnel._ETH_HDR_TO_PEER + ipv6)


def _pending_egress(tun: UserspaceTun) -> list[bytes]:
    frames: list[bytes] = []
    while True:
        try:
            frames.append(tun._peer.recv(65535))
        except BlockingIOError:
            return frames


def test_icmp6_echo_request_is_valid() -> None:
    packet = userspace_tunnel._icmp6_echo_request(_HOST_ADDR, DEVICE_ADDR)
    assert packet[0] >> 4 == 6
    assert packet[6] == 58  # next header: ICMPv6
    assert struct.unpack("!H", packet[4:6])[0] == len(packet) - 40
    body = packet[40:]
    assert body[0] == 128  # echo request
    data = packet[8:40] + struct.pack("!IxxxB", len(body), 58) + body
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    assert total == 0xFFFF


async def test_a_silent_device_is_nudged_once(monkeypatch: pytest.MonkeyPatch) -> None:
    tun = _tun_with_nudge(monkeypatch)
    try:
        _stack_sends(tun, b"\x60" + b"\x01" * 59)
        assert await tun.async_read_batch() == [b"\x60" + b"\x01" * 59]
        await asyncio.sleep(0.1)
        nudge = tun._nudge_frame
        assert nudge is not None
        assert await asyncio.wait_for(tun.async_read_batch(), 1) == [nudge[14:]]
        # The nudge's own batch does not re-arm the watchdog: an unanswered nudge is sent once.
        await asyncio.sleep(0.1)
        assert _pending_egress(tun) == []
    finally:
        await tun.close()


async def test_a_device_that_answers_is_not_nudged(monkeypatch: pytest.MonkeyPatch) -> None:
    tun = _tun_with_nudge(monkeypatch)
    try:
        _stack_sends(tun, b"\x60" + b"\x01" * 59)
        await tun.async_read_batch()
        tun.write(b"\x60" + b"\x02" * 59)  # the device's reply
        await asyncio.sleep(0.1)
        assert _pending_egress(tun) == []
    finally:
        await tun.close()


async def test_no_nudge_while_the_host_keeps_sending(monkeypatch: pytest.MonkeyPatch) -> None:
    tun = _tun_with_nudge(monkeypatch)
    try:
        for i in range(10):
            _stack_sends(tun, b"\x60" + bytes([i]) * 59)
            assert await tun.async_read_batch() == [b"\x60" + bytes([i]) * 59]
            tun.write(b"\x60" + b"\x02" * 59)
            await asyncio.sleep(0.01)
        assert _pending_egress(tun) == []
    finally:
        await tun.close()


async def test_close_cancels_the_nudge(monkeypatch: pytest.MonkeyPatch) -> None:
    tun = _tun_with_nudge(monkeypatch)
    _stack_sends(tun, b"\x60" + b"\x01" * 59)
    await tun.async_read_batch()
    assert tun._nudge_timer is not None
    await tun.close()
    assert tun._nudge_timer is None
