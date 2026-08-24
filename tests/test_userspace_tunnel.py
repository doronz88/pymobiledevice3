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
import os
import socket
import threading
from contextlib import AsyncExitStack
from typing import Any, cast

import pytest

# pmd-pytcp supports Python >= 3.9; skip the whole module when it's absent.
pytest.importorskip("pmd_pytcp")

from pmd_pytcp.stack import sysctl

from pymobiledevice3.osu.os_utils import get_os_utils
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
    # A dial's connect completes in the kernel before the server's accept callback has
    # spawned the handler. If teardown then begins — e.g. the dialer's caller raised during
    # connection setup — __aexit__'s cancel loop snapshots _relay_tasks before that handler
    # registers, so nothing cancelled it: its pumps parked forever on an abandoned client
    # connection and __aexit__ hung in Server.wait_closed() (which waits for all attached
    # connections since Python 3.12.1). Reproduced live against a device; exit must complete
    # promptly with no relay task left behind.
    class StallingTun:
        async def connect_tcp(self, addr: str, port: int) -> FakePyTcpSocket:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    dial_plane = UserspaceDialPlane(cast(UserspaceTun, StallingTun()), DEVICE_ADDR)
    await dial_plane.__aenter__()
    _reader, writer = await dial_plane.dial(DEVICE_ADDR, 3333)

    # No yield to the loop between dial and teardown: the handler must not be registered yet.
    await asyncio.wait_for(dial_plane.__aexit__(None, None, None), timeout=5)

    assert not dial_plane._relay_tasks
    await close_stream_writer(writer)
    # Drain the loop so the gate handler for the raced connection finishes closing its
    # transport; otherwise the accepted socket is finalized by GC and flagged unraisable.
    for _ in range(5):
        await asyncio.sleep(0)


async def test_dial_after_close_raises():
    # A dial racing (or following) teardown must fail loudly: letting it through re-created
    # the socket dir and registered a live relay server after teardown had cleared both —
    # leaked until process exit — and handed the caller a stream that only ever yields EOF.
    # The window is real since the transport watcher runs teardown concurrently with dials.
    tun = FakeTun()
    dial_plane = UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR)
    async with dial_plane:
        pass
    with pytest.raises(ConnectionError):
        await dial_plane.dial(DEVICE_ADDR, 5555)
    assert dial_plane._socket_dir is None
    assert dial_plane._server is None


@pytest.mark.skipif(not get_os_utils().supports_unix_sockets, reason="platform has no AF_UNIX")
async def test_relay_uses_unix_sockets_and_removes_them_on_exit():
    # Where AF_UNIX exists the relay must listen on unix sockets, not loopback TCP: the
    # socket dir's 0700 mode decides who may connect, instead of exposing the device's
    # services on a port any local process can reach. Also pin the cleanup: asyncio only
    # unlinks unix server sockets from 3.13, so the dial plane removes its socket directory
    # itself.
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        _reader, writer = await dial_plane.dial(DEVICE_ADDR, 2222)
        assert writer.get_extra_info("socket").family == socket.AF_UNIX
        socket_dir = dial_plane._socket_dir
        assert socket_dir is not None and os.path.isdir(socket_dir)

        await close_stream_writer(writer)
        await _poll_until(lambda: not dial_plane._relay_tasks)
    assert not os.path.exists(socket_dir)


async def test_tcp_relay_forced_by_env_var(monkeypatch):
    # PYMOBILEDEVICE3_USERSPACE_TCP_RELAY reproduces the Windows relay path on any platform:
    # the relay must bind loopback TCP and never create a socket directory. This also gives the
    # TCP relay path POSIX CI coverage (it is otherwise exercised only on Windows runners).
    monkeypatch.setenv(userspace_tunnel.TCP_RELAY_ENV_VAR, "1")
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        reader, writer = await dial_plane.dial(DEVICE_ADDR, 4444)
        assert writer.get_extra_info("socket").family == socket.AF_INET
        assert dial_plane._socket_dir is None

        psock = (await _poll_until(lambda: tun.socks))[0]
        writer.write(b"ping")
        await writer.drain()
        await _poll_until(lambda: psock.sent == [b"ping"])
        psock.feed(b"pong")
        assert await reader.readexactly(4) == b"pong"
        writer.close()


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


async def test_stray_connection_without_header_is_shed(monkeypatch):
    # Only dial() speaks the 2-byte port-header protocol; a stray local connection that
    # sends nothing (trivial on the TCP fallback, where any local process can connect) must
    # be shed by the header timeout instead of pinning a handler and its transport until
    # tunnel close.
    monkeypatch.setattr(userspace_tunnel, "RELAY_HEADER_TIMEOUT", 0.2)
    tun = FakeTun()
    async with UserspaceDialPlane(cast(UserspaceTun, tun), DEVICE_ADDR) as dial_plane:
        assert dial_plane._opener is not None
        reader, writer = await dial_plane._opener()  # no header
        assert await asyncio.wait_for(reader.read(), timeout=5) == b""  # shed with EOF
        assert not tun.socks  # never touched the stack
        await _poll_until(lambda: not dial_plane._relay_tasks)
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
