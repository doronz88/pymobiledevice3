"""Tests for the userspace tunnel: throughput tuning and relay-teardown behavior.

The tuning rides pmd-pytcp's public ``tcp.rcv_wnd_max`` / ``tcp.snd_mss_max`` sysctls; these
tests pin that :func:`throughput_sysctls` emits values the installed pmd-pytcp actually accepts
(and silently omits any a too-old pmd-pytcp lacks). The cross-platform/portability concerns that
used to live in a host-side compatibility layer are now handled inside pmd-pytcp itself.

The relay-teardown tests are regressions for issue #1756 (userspace tunnel cleanup hanging the
event loop / leaking one parked rx_pump thread per relayed connection). They drive
:class:`UserspaceDialPlane` against a fake PyTCP socket reproducing the semantics that caused
the hang: a blocking ``recv()`` that does NOT unblock on ``close()``.
"""

import asyncio
import threading
import time

import pytest

# pmd-pytcp ships only on Python >= 3.14; skip the whole module when it's absent.
pytest.importorskip("pmd_pytcp")

from pmd_pytcp.stack import sysctl

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.remote.userspace_tunnel import UserspaceDialPlane


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
    assert knobs["tcp.default.snd_mss_max"] == userspace_tunnel.MAX_SEND_MSS


def test_throughput_sysctls_round_trip_through_sysctl_set():
    # The emitted entries must apply cleanly the way stack.init(sysctls=...) applies them.
    for key, value in userspace_tunnel.throughput_sysctls().items():
        sysctl.set(key, value)
    sysctl.reset_to_defaults()


# --- relay teardown regressions (issue #1756) ---------------------------------------------

DEVICE_ADDR = "fd00::1"


class FakePyTcpSocket:
    """The pmd-pytcp TCP socket surface the relay uses, with the semantics that caused #1756:
    ``recv()`` blocks (optionally with a timeout) and does NOT unblock on ``close()`` — only
    inbound data/EOF or a ``shutdown(SHUT_RD/SHUT_RDWR)`` wakes it."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._rx: list = []
        self._eof = False
        self.sent: list = []
        self.shutdown_calls: list = []
        self.closed = threading.Event()

    # --- device-side test controls ---
    def feed(self, data: bytes) -> None:
        with self._cond:
            self._rx.append(data)
            self._cond.notify_all()

    def feed_eof(self) -> None:
        with self._cond:
            self._eof = True
            self._cond.notify_all()

    # --- relay-facing surface ---
    def recv(self, bufsize: int, timeout=None) -> bytes:
        with self._cond:
            if not self._cond.wait_for(lambda: self._rx or self._eof, timeout=timeout):
                raise TimeoutError("TCP Socket - Receive operation timed out.")
            if self._rx:
                return self._rx.pop(0)
            return b""

    def send(self, data: bytes) -> int:
        self.sent.append(bytes(data))
        return len(data)

    def shutdown(self, how) -> None:
        self.shutdown_calls.append(int(how))
        if int(how) in (0, 2):  # SHUT_RD / SHUT_RDWR wake a parked recv() with EOF
            self.feed_eof()

    def close(self) -> None:
        self.closed.set()


class FakeTun:
    """Just enough of :class:`UserspaceTun` for :class:`UserspaceDialPlane`."""

    def __init__(self) -> None:
        self.socks: list = []

    def connect_tcp(self, addr: str, port: int) -> FakePyTcpSocket:
        sock = FakePyTcpSocket()
        self.socks.append(sock)
        return sock


async def _poll_until(predicate, timeout: float = 5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        await asyncio.sleep(0.01)
    raise AssertionError("condition not met within timeout")


def _relay_rx_threads() -> list:
    return [t for t in threading.enumerate() if t.name.startswith("userspace-relay-rx-")]


async def test_relay_full_conversation_and_clean_completion():
    # ping/pong through the relay, then a client-initiated close: the client EOF must reach
    # the device as a half-close (SHUT_WR), and once the device answers with its own EOF the
    # handler must finish on its own — with the pytcp socket closed and no task left behind.
    tun = FakeTun()
    async with UserspaceDialPlane(tun, DEVICE_ADDR) as dial_plane:
        reader, writer = await dial_plane.dial(DEVICE_ADDR, 1234)
        psock = (await _poll_until(lambda: tun.socks))[0]

        writer.write(b"ping")
        await writer.drain()
        await _poll_until(lambda: psock.sent == [b"ping"])
        psock.feed(b"pong")
        assert await reader.readexactly(4) == b"pong"

        writer.close()
        # client EOF -> device half-close (SHUT_WR=1 or SHUT_RDWR=2)
        await _poll_until(lambda: any(how in (1, 2) for how in psock.shutdown_calls))
        psock.feed_eof()  # the device finishes its side
        await _poll_until(lambda: not dial_plane._relay_tasks)  # handler completed unaided
        assert psock.closed.wait(timeout=5)


async def test_device_eof_reaches_client():
    # The device closing its side must propagate to the client as EOF (write_eof), otherwise
    # the client never learns the stream ended and the pair idles forever.
    tun = FakeTun()
    async with UserspaceDialPlane(tun, DEVICE_ADDR) as dial_plane:
        reader, writer = await dial_plane.dial(DEVICE_ADDR, 1111)
        psock = (await _poll_until(lambda: tun.socks))[0]
        psock.feed(b"data")
        psock.feed_eof()
        assert await asyncio.wait_for(reader.read(), timeout=5) == b"data"  # read() to EOF
        writer.close()


async def test_dial_plane_exit_cancels_parked_relay():
    # Regression for the #1756 hang: with a relay parked on device traffic (recv blocked, no
    # EOF in sight), __aexit__ used to hang in Server.wait_closed() (which waits for in-flight
    # handlers since Python 3.12.1) and left the handler task to be cancelled at loop close —
    # where its inline psock cleanup wedged the loop. Exit must complete promptly, leave no
    # relay task behind, and still tear the pytcp socket down.
    tun = FakeTun()
    dial_plane = UserspaceDialPlane(tun, DEVICE_ADDR)
    await dial_plane.__aenter__()
    _reader, writer = await dial_plane.dial(DEVICE_ADDR, 5678)
    await _poll_until(lambda: tun.socks)

    await asyncio.wait_for(dial_plane.__aexit__(None, None, None), timeout=5)

    assert not dial_plane._relay_tasks
    assert tun.socks[0].closed.wait(timeout=5)
    writer.close()


async def test_rx_pump_threads_exit_after_teardown():
    # Regression for the #1756 thread pile-up (120 parked rx_pump threads): after the dial
    # plane exits, every relay rx thread must unwind — the teardown SHUT_RDWR wakes parked
    # ones and the polling recv() lets the rest observe the closing flag.
    baseline = _relay_rx_threads()
    tun = FakeTun()
    async with UserspaceDialPlane(tun, DEVICE_ADDR) as dial_plane:
        writers = []
        for _ in range(5):
            _reader, writer = await dial_plane.dial(DEVICE_ADDR, 9999)
            writers.append(writer)
        await _poll_until(lambda: len(tun.socks) == 5)
        assert len(_relay_rx_threads()) >= 5
    await _poll_until(lambda: _relay_rx_threads() == baseline, timeout=10)
    for writer in writers:
        writer.close()
