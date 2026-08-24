"""Userspace (root-free) tunnel backend for iOS 17+ RSD/RemotePairing tunnels.

The standard tunnel writes raw IPv6 packets to a kernel ``utun``, which needs admin/root.
This backend replaces the kernel interface with a pure-Python TCP/IP stack (PyTCP) so the
tunnel and all host-initiated RSD developer services run as a normal user.

The public entry point is :class:`UserspaceRsdTunnel` — a closeable handle (async context manager
or ``aopen()``/``aclose()``) that owns the whole tunnel and exposes a connected RSD. The pieces it
wires together:

* :class:`UserspaceTun` — a drop-in for ``pytun_pmd3.TunTapDevice`` (same
  ``mtu``/``addr``/``up``/``write``/``read``/``close`` surface) that bridges packets to a
  PyTCP L2 stack over a datagram socketpair plus a 14-byte Ethernet shim. (PyTCP's mature
  path is L2; its L3/TUN egress is buggy.)
* :class:`UserspaceDialPlane` — an ``asyncio.open_connection``-compatible dialer (injected into the
  RSD via ``open_connection=``, NOT monkeypatched onto the global) that relays connections to the
  device's tunnel address through a unix socket (loopback TCP where AF_UNIX is unavailable) into a
  PyTCP socket. This covers the RSD HTTP/2 handshake and every ``ServiceConnection.create_using_tcp``
  while leaving the process-global ``asyncio.open_connection`` untouched for any other code sharing
  the process.
* :class:`UserspaceUdp` — a UDP socket on the stack for device-initiated inbound streams (the
  AV media behind ``display serve-web``): the device pushes RTP to the stack address rather
  than to an unreachable host kernel socket.

pmd-pytcp supports Python 3.9+ and is a regular pymobiledevice3 dependency, so this module
imports it at module level and ``cli_common`` establishes the userspace tunnel directly. Since
pmd-pytcp 0.1.0 the stack is pure asyncio — it runs entirely on this process's event loop (no
worker threads), its socket calls are awaited directly, and ``stack.start()``/``stack.stop()``
are coroutines — so this module contains no thread/executor bridging at all: every packet and
byte moves through plain ``await``.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import shutil
import socket
import struct
import tempfile
import weakref
from collections.abc import Coroutine
from contextlib import AsyncExitStack, suppress
from functools import partial
from typing import Any, Callable, Optional, Protocol, TypeVar, cast

from pmd_net_addr import Ip6Address, Ip6IfAddr, MacAddress
from pmd_pytcp import stack
from pmd_pytcp.lib.interface_layer import InterfaceLayer
from pmd_pytcp.lib.io_backend import register_interface_fd, unregister_interface_fd
from pmd_pytcp.socket import AF_INET6, SHUT_RDWR, SOCK_DGRAM, SOCK_STREAM
from pmd_pytcp.socket import socket as pytcp_socket

import pymobiledevice3.remote.tunnel_service as tunnel_service
from pymobiledevice3.exceptions import InvalidServiceError, PyMobileDevice3Exception, UserspaceTunnelUnavailableError
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.utils import get_asyncio_loop

logger = logging.getLogger(__name__)

# pmd-pytcp logs every enabled channel (SOCKET, TCP, ...) per packet at DEBUG through the
# 'pmd_pytcp' logger; under pmd3's own debug verbosity that would flood the output with the
# stack's internal traffic. Cap it at WARNING so the stack stays quiet inside pmd3 (raise it
# manually for stack-level debugging). This is the logging-module equivalent of the silencing
# the old pytcp_compat layer did.
logging.getLogger("pmd_pytcp").setLevel(logging.WARNING)

_ETH_IPV6 = 0x86DD
_STACK_MAC = "02:00:00:00:00:01"
_PEER_MAC = "02:00:00:00:00:02"

#: Ceiling on the PyTCP interface MTU. The tunnel negotiates 16000; a large interface MTU
#: makes downloads fast (the device sends big segments to us). Host->device segments are
#: governed separately by PLPMTUD (seeded at :data:`BASE_MSS_SEED`, raised only through
#: device-ACKed sizes), so a large value is safe here.
INTERFACE_MTU = 16000

#: Receive-window ceiling (PyTCP 'tcp.rcv_wnd_max'; default 65535). A download is bounded by
#: window / RTT, so 64 KB throttles it; 4 MiB keeps a full bandwidth-delay-product in flight and
#: stays within PyTCP's negotiated window-scale-7 reach (~8 MiB). Measured on an iOS 17+ DSC
#: fetch: 64 KB window -> 8 MB/s, 4 MiB window -> 40 MB/s (kernel-tunnel parity).
MAX_RECV_WINDOW = 4 * 1024 * 1024

#: PLPMTUD cold-start seed (PyTCP 'tcp.base_mss'): host->device segments START at
#: ``1400 - 60 = 1340`` payload — the proven-safe size across devices (= the static
#: ``tcp.snd_mss_max`` = 1340 cap this replaced) — and only grow through packet sizes the
#: device has actually ACKed, as
#: RFC 4821/8899 probing (PyTCP 'tcp.mtu_probing') walks the ladder upward. A failed probe
#: costs one RACK-repaired segment and narrows the search; it never stalls the transfer. So the
#: worst case on any device/transport equals the old fixed-1340 behaviour, while paths that
#: forward bigger packets (measured: USB CoreDeviceProxy drops host->device IPv6 packets over
#: 8192 bytes total but passes everything below) converge to their real limit and upload several
#: times faster. No per-device packet size is hardcoded anywhere.
BASE_MSS_SEED = 1400

#: RFC 8899 PROBE_TIMER (PyTCP 'tcp.plpmtud.probe_timer_ms'; RFC default 30000). The backstop
#: loss-declaration for an MTU probe that dies without triggering loss recovery. The tunnel RTT
#: is a few ms, so 30 s would park the search for a whole transfer; in-band signals
#: (fast-retransmit/RACK/TLP recovery entry) normally beat this timer by orders of magnitude.
PROBE_TIMER_MS = 1500

#: RTO floor (PyTCP 'tcp.rto.min_ms'; RFC 6298 default 1000). The tunnel RTT is single-digit
#: milliseconds, so the RFC's 1 s floor makes every genuine stall — including a PLPMTUD
#: black-hole revert, which fires exactly once per over-large probe rung — cost ~200x the RTT.
#: 200 ms matches Linux's floor and keeps MSS-search convergence under a second while staying
#: ~40x above the observed RTT (no spurious-RTO risk; RACK/TLP handle tail losses first).
MIN_RTO_MS = 200

#: Delayed-ACK timer (PyTCP 'tcp.delayed_ack.delay_ms'; RFC default 100). The device Nagle-holds
#: the tail segment of every multi-segment response until our ACK arrives, so each DTX/RemoteXPC
#: round-trip stalls one full timer: measured `dvt ls /` latency is delay + ~7 ms link RTT,
#: linear across 1..100 ms (110 ms at the default, 8 ms at 1 ms). 1 ms effectively ACKs
#: immediately; bulk transfers are unaffected either way (streams are governed by the
#: ACK-every-other-segment rule, not the timer — measured 38-39 MB/s at 1/10/100 ms alike).
ACK_DELAY_MS = 1

#: How long :class:`UserspaceDialPlane` waits for a relay connection's 2-byte port header.
#: dial() writes it before returning, so legitimate headers arrive within one loop tick;
#: this only sheds stray local connections that send nothing.
RELAY_HEADER_TIMEOUT = 10

#: Set (to any non-empty value) to force the dial plane's relays onto loopback TCP even where
#: AF_UNIX exists — reproduces the Windows relay path on any platform for debugging.
TCP_RELAY_ENV_VAR = "PYMOBILEDEVICE3_USERSPACE_TCP_RELAY"


def throughput_sysctls() -> dict[str, int]:
    """The ``stack.init(sysctls=...)`` entries that tune the tunnel for bulk transfer and latency.

    These ride pmd-pytcp's public sysctls: ``tcp.rcv_wnd_max`` raises the advertised receive
    window for fast downloads; ``tcp.delayed_ack.delay_ms`` drops the delayed-ACK timer so
    interactive request/response services are not stalled by it (:data:`ACK_DELAY_MS`);
    ``net.default.rx_cksum_validate`` turns off the software RX checksum pass (the tunnel is
    AEAD-authenticated, so the RFC 1071 checksum only re-verifies bytes that cannot have been
    corrupted) — measured ~+35% bulk-download throughput on an iOS 17+ DSC fetch.

    Host->device segment sizing is dynamic: RFC 4821/8899 PLPMTUD (``tcp.mtu_probing`` = 2)
    starts every connection at the proven-safe 1340-byte send MSS (``tcp.base_mss`` =
    :data:`BASE_MSS_SEED`) and raises it only through packet sizes the device has actually
    ACKed, so each device/transport converges to its own real forwarding limit with no
    hardcoded per-device size and a worst case equal to the old static 1340 cap.

    Every knob here is guaranteed by the pmd-pytcp version floor in pyproject.toml — no
    capability probing.
    """
    return {
        "tcp.rcv_wnd_max": MAX_RECV_WINDOW,
        "tcp.delayed_ack.delay_ms": ACK_DELAY_MS,
        "tcp.rto.min_ms": MIN_RTO_MS,
        "tcp.default.mtu_probing": 2,
        "tcp.default.base_mss": BASE_MSS_SEED,
        "tcp.plpmtud.default.probe_timer_ms": PROBE_TIMER_MS,
        # Software RX-checksum offload: every packet reaching the stack came through the
        # AEAD-authenticated tunnel and an in-memory socketpair, so the RFC 1071 checksum
        # verifies RAM. TX checksums stay on (the device kernel verifies them).
        "net.default.rx_cksum_validate": False,
    }


#: Datagram socketpair buffer, sized to hold a burst of a full receive window of packets.
SOCKET_BUFFER_SIZE = 6 * 1024 * 1024

#: Read/relay chunk size for the dial-plane bridge.
_CHUNK = 65536

#: pmd3's per-OS tun loopback header (macOS: b"\x00\x00\x00\x1e" = AF_INET6).
LOOPBACK_HEADER = get_os_utils().loopback_header


class _AsyncPytcpSocket(Protocol):
    """The async surface pmd-pytcp stack sockets actually expose at runtime.

    pmd-pytcp's public ``socket`` class types ``connect``/``send``/``recv``/``sendto`` as
    synchronous placeholders (they raise ``NotImplementedError`` on the base and are overridden as
    coroutines on the concrete stack sockets), so the awaited calls in this module type-check
    against this protocol rather than the base class."""

    async def connect(self, address: tuple[str, int]) -> None: ...

    async def send(self, data: bytes) -> int: ...

    async def recv(self, bufsize: int = ...) -> bytes: ...

    async def sendto(self, data: bytes, address: tuple[str, int]) -> None: ...

    def bind(self, address: tuple[str, int]) -> None: ...

    def getsockname(self) -> tuple[str, int]: ...

    def shutdown(self, how: int) -> None: ...

    def close(self) -> None: ...


def _mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _eth_header(dst_mac: str, src_mac: str) -> bytes:
    return _mac_to_bytes(dst_mac) + _mac_to_bytes(src_mac) + struct.pack("!H", _ETH_IPV6)


#: Hot-path constants: the (fixed) Ethernet header prepended to every inbound packet, and the
#: EtherType bytes checked on every outbound frame — precomputed so the per-packet paths do no
#: string parsing / struct packing.
_ETH_HDR_TO_STACK = _eth_header(_STACK_MAC, _PEER_MAC)
_ETH_IPV6_BYTES = struct.pack("!H", _ETH_IPV6)


def _packet_socketpair() -> tuple[socket.socket, socket.socket]:
    """A connected datagram socket pair preserving packet boundaries (one send == one recv).
    Unix uses an AF_UNIX SOCK_DGRAM socketpair; Windows (no such socketpair) uses a connected
    localhost UDP pair."""
    try:
        return socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    except (AttributeError, OSError):
        a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        a.bind(("127.0.0.1", 0))
        b.bind(("127.0.0.1", 0))
        a.connect(b.getsockname())
        b.connect(a.getsockname())
        return a, b


class UserspaceTun:
    """Tunnel interface backed by a PyTCP L2 stack — the userspace stand-in for
    ``pytun_pmd3.TunTapDevice`` (same ``mtu``/``addr`` attributes and ``write`` call; ``up`` and
    ``close`` are coroutines and reads go through ``async_read``, which
    :meth:`RemotePairingTunnel.start_tunnel` / ``tun_read_task`` handle).

    PyTCP's stack is a process-global singleton, so one tunnel per process is supported
    (the normal case)."""

    def __init__(self, interface_name: str = "utun-userspace") -> None:
        self.name = interface_name
        self._mtu = 1500
        self._addr: Optional[str] = None
        self._ifidx: Optional[int] = None
        self._closed = False
        self._peer, self._pend = _packet_socketpair()
        for s in (self._peer, self._pend):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
        # Both directions run on the event loop (async_read via loop.sock_recv, write via a
        # direct non-blocking send), so neither end may block the loop.
        self._peer.setblocking(False)

    # --- TunTapDevice-compatible surface ---
    @property
    def mtu(self) -> int:
        return self._mtu

    @mtu.setter
    def mtu(self, value: int) -> None:
        self._mtu = int(value)

    @property
    def addr(self) -> Optional[str]:
        return self._addr

    @addr.setter
    def addr(self, address: str) -> None:
        self._addr = address

    async def up(self) -> None:
        self._mtu = min(self._mtu, INTERFACE_MTU)

        if not getattr(stack, "_pmd3_inited", False):
            # accept_dad off (point-to-point link, no DAD peer) + the throughput sysctls
            # (public PyTCP knobs; omitted automatically on a PyTCP too old to have them).
            sysctls = {"icmp6.default.accept_dad": 0, **throughput_sysctls()}
            stack.init(sysctls=sysctls)
            stack._pmd3_inited = True  # type: ignore[attr-defined]
        register_interface_fd(self._pend)
        self._ifidx = stack.add_interface(
            fd=self._pend.fileno(),
            layer=InterfaceLayer.L2,
            mac_address=MacAddress(_STACK_MAC),
            mtu=self._mtu,
            ip6_support=True,
            ip6_host=Ip6IfAddr(f"{self._addr}/64"),
            ip6_lla_autoconfig=True,
            ip6_gua_autoconfig=False,
            ip4_support=False,
        )
        await stack.start()  # pyright: ignore[reportGeneralTypeIssues]  # pmd-pytcp types start() as sync; it is a coroutine at runtime
        # The interface address is installed by the stack's own tasks shortly AFTER start()
        # returns; until it lands, source-address selection finds no local host and a stack
        # connect fails with gaierror. Today the dial plane's localhost-relay hop happens to
        # add enough event-loop round trips to win that race, but nothing guarantees it — and
        # an embedder calling connect_tcp() right after aopen() has no such slack. The tun is
        # not "up" until its address is actually usable, so wait for it (yielding, not
        # sleeping: the install normally lands within a loop tick or two).
        target = Ip6Address(self._addr)
        deadline = asyncio.get_running_loop().time() + 5
        while not any(host.address == target for host in stack.local_ip6_hosts()):
            if asyncio.get_running_loop().time() > deadline:
                raise PyMobileDevice3Exception(f"userspace stack address {self._addr} was not assigned within 5s")
            await asyncio.sleep(0)
        logger.debug("userspace tunnel up: pytcp L2 iface=%s addr=%s/64 mtu=%s", self._ifidx, self._addr, self._mtu)

    def set_peer(self, device_addr: str) -> None:
        """Install a static neighbor for the device (point-to-point; skips ND)."""
        assert self._ifidx is not None
        stack.neighbor.interface(self._ifidx).add(ip=Ip6Address(device_addr), mac=MacAddress(_PEER_MAC))

    def write(self, data: bytes) -> None:
        # inbound (device -> stack): strip pmd3 loopback header, add Ethernet, enqueue. The
        # socket is non-blocking; a full buffer drops the packet (tunnel loss, TCP recovers).
        ipv6 = data[len(LOOPBACK_HEADER) :] if data[: len(LOOPBACK_HEADER)] == LOOPBACK_HEADER else data
        with suppress(OSError):
            self._peer.send(_ETH_HDR_TO_STACK + ipv6)

    async def async_read(self) -> bytes:
        # outbound (stack -> device): await an Ethernet frame off the stack's socketpair and
        # return its raw IPv6 payload (no loopback header — tun_read_task checks the version
        # nibble). Raises OSError once the socketpair is closed, which ends tun_read_task.
        while not self._closed:
            frame = await asyncio.get_running_loop().sock_recv(self._peer, 65535)
            if len(frame) < 14 or frame[12:14] != _ETH_IPV6_BYTES:
                continue
            return frame[14:]
        return b""

    async def async_read_batch(self) -> list[bytes]:
        """Await at least one outbound frame, then greedily drain every further frame already
        queued on the socketpair, returning their raw IPv6 payloads in arrival order.

        One event-loop wakeup services a whole egress burst — the userspace counterpart of the
        kernel tun's ``_tun_read_loop_via_reader`` batch-drain. Paying a loop reschedule per
        MSS-sized packet caps uploads at a few thousand packets/s, because the same loop also
        runs the pytcp stack. Raises OSError once the socketpair is closed, which ends
        ``tun_read_task``."""
        frame = await asyncio.get_running_loop().sock_recv(self._peer, 65535)
        packets: list[bytes] = []
        while True:
            if len(frame) > 14 and frame[12:14] == _ETH_IPV6_BYTES:
                packets.append(frame[14:])
            try:
                frame = self._peer.recv(65535)
            except (BlockingIOError, InterruptedError):
                return packets

    async def connect_tcp(self, addr: str, port: int) -> _AsyncPytcpSocket:
        """Open a PyTCP TCP socket connected to (addr, port) over this stack."""
        s = cast(_AsyncPytcpSocket, pytcp_socket(AF_INET6, SOCK_STREAM))
        await s.connect((addr, port))
        return s

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Stop the stack first (clean teardown against live fds: loop readers/writers are
        # removed, worker tasks cancelled and awaited), then release the socketpair. No
        # thread-wakeup gymnastics remain — the pure-asyncio stack has nothing parked off-loop.
        try:
            await stack.stop()  # pyright: ignore[reportGeneralTypeIssues]  # pmd-pytcp types stop() as sync; it is a coroutine at runtime
        except Exception:
            logger.debug("error stopping pytcp stack", exc_info=True)
        finally:
            # Clear the init marker even when stop() raised: a later open->close->open cycle
            # must re-run stack.init() rather than reuse a half-stopped stack.
            stack._pmd3_inited = False  # type: ignore[attr-defined]
        unregister_interface_fd(self._pend)
        for s in (self._peer, self._pend):
            with suppress(Exception):
                s.close()


#: Connects to a relay's listener, yielding the stream pair (`asyncio.open_connection`-shaped,
#: minus the address arguments — those are baked in when the listener is bound).
_RelayOpener = Callable[..., Coroutine[Any, Any, tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


_ServerT = TypeVar("_ServerT", bound=asyncio.AbstractServer)


async def _bind_listener(bind: Coroutine[Any, Any, _ServerT]) -> _ServerT:
    """Await a ``start_server``-style coroutine without orphaning its listener on cancellation.

    ``create_server``/``create_unix_server`` suspend once AFTER the socket is bound, serving,
    and registered with the loop's selector (their trailing ``sleep(0)``); a cancellation
    landing exactly there — e.g. ``create_using_tcp``'s connect timeout cancelling a dial
    mid-bind — discards the Server object while the selector keeps its socket alive forever.
    Shield the bind and close the listener when it lands if the awaiter was cancelled."""
    task = asyncio.ensure_future(bind)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:

        def _close_when_done(t: asyncio.Task[asyncio.AbstractServer]) -> None:
            if not t.cancelled() and t.exception() is None:
                t.result().close()

        task.add_done_callback(_close_when_done)
        raise


class UserspaceDialPlane:
    """Provides an ``asyncio.open_connection``-compatible :meth:`dial` that bridges device-bound
    connections to PyTCP sockets via local relays.

    The relays listen on unix sockets wherever AF_UNIX exists, falling back to loopback TCP
    (e.g. on Windows) — see :meth:`__aenter__` for why. Nothing outside this process
    ever legitimately connects to a relay (external-tool flows such as ``debugserver lldb``
    refuse userspace tunnels), so nothing is lost by keeping the listeners off the network
    stack.

    Pass :meth:`dial` to ``RemoteServiceDiscoveryService(open_connection=...)`` so ONLY connections
    made through that RSD are relayed. This deliberately does NOT monkeypatch the process-global
    ``asyncio.open_connection``: a library consumer who establishes a userspace tunnel keeps the
    stdlib function untouched, so unrelated connections elsewhere in their process are unaffected.

    Use as an async context manager so the relay servers are torn down on exit."""

    def __init__(self, tun: UserspaceTun, device_addr: str) -> None:
        self._tun = tun
        self._device_addr = str(device_addr)
        self._server: Optional[asyncio.AbstractServer] = None  # the single relay listener
        self._opener: Optional[_RelayOpener] = None  # connects to it (unix path or TCP port)
        self._relay_tasks: set[asyncio.Task[None]] = set()  # in-flight handlers, cancelled on exit
        self._socket_dir: Optional[str] = None  # holds the relay unix socket, removed on exit
        self._closing = False  # teardown began; late-spawning handlers must bail out
        self._inflight_dials = 0  # connects in progress; __aexit__ lets them land pre-close

    async def __aenter__(self) -> UserspaceDialPlane:
        """Bind the single relay listener. Binding eagerly — before any dial exists — is what
        keeps this class simple: nothing ever binds on the dial path, so no bind can race a
        dial timeout, a cancellation, or teardown.

        A unix socket is preferred: it lives in a 0700 temp directory, so the filesystem —
        not the network stack — decides who may connect, whereas a loopback TCP port is
        connectable by any local process for the tunnel's whole lifetime. TCP remains the
        fallback where AF_UNIX is unavailable (e.g. Windows), and can be forced anywhere via
        :data:`TCP_RELAY_ENV_VAR` to debug that path."""
        if get_os_utils().supports_unix_sockets and not os.getenv(TCP_RELAY_ENV_VAR):
            self._socket_dir = tempfile.mkdtemp(prefix="pmd3-")
            path = os.path.join(self._socket_dir, "relay.sock")
            try:
                self._server = await _bind_listener(asyncio.start_unix_server(self._handle, path))
            except OSError as e:
                # e.g. sun_path length exceeded by an unusually long TMPDIR. The fallback is a
                # loopback TCP port any local process can connect to — losing the unix socket's
                # filesystem access control — so say so visibly.
                logger.warning("unix-socket relay bind failed (%s); falling back to loopback TCP", e)
                shutil.rmtree(self._socket_dir, ignore_errors=True)
                self._socket_dir = None
            else:
                self._opener = partial(asyncio.open_unix_connection, path)
                logger.debug("userspace relay for %s -> %s", self._device_addr, path)
        if self._server is None:
            self._server = await _bind_listener(asyncio.start_server(self._handle, "127.0.0.1", 0))
            lport = self._server.sockets[0].getsockname()[1]
            self._opener = partial(asyncio.open_connection, "127.0.0.1", lport)
            logger.debug("userspace relay for %s -> 127.0.0.1:%s", self._device_addr, lport)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._closing = True
        # Let every connect that already passed dial()'s gate land against a still-open
        # Server, and give queued accept callbacks one more tick to attach: an accept
        # processed after close() dies on an internal assertion inside asyncio and the
        # accepted socket is abandoned unclosed (GC ResourceWarning). Attached transports
        # are owned — their gate handlers close them during wait_closed below. In-flight
        # dials settle within a few ticks (connect + nothing else); the deadline only guards
        # against a wedged loop.
        for _ in range(100):
            await asyncio.sleep(0)
            if not self._inflight_dials:
                break
        await asyncio.sleep(0)
        if self._server is not None:
            self._server.close()
        # Cancel the in-flight relay handlers BEFORE wait_closed(): since Python 3.12.1
        # Server.wait_closed() also waits for every active connection handler, and a relay
        # parked on device traffic never finishes on its own — teardown would hang until the
        # caller's timeout (issue #1756). Cancelling here (instead of leaving orphan tasks for
        # the loop's shutdown to cancel) also guarantees each handler's psock cleanup runs
        # while the stack is still up, and that no relay task outlives the dial plane.
        # Nothing can join _relay_tasks after the first snapshot (_closing was set before any
        # await in this method and handlers register in an await-free step after checking
        # it), but repeat the cancel a few times anyway: on Python <= 3.11 a cancellation
        # racing an inner future's completion can be swallowed (the old wait_for behavior),
        # and a survivor here would park __aexit__ forever.
        for _ in range(3):
            if not self._relay_tasks:
                break
            for task in list(self._relay_tasks):
                task.cancel()
            await asyncio.gather(*list(self._relay_tasks), return_exceptions=True)
        if self._server is not None:
            with suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        self._opener = None
        if self._socket_dir is not None:
            # asyncio only unlinks unix server sockets on close from Python 3.13; remove the
            # whole directory so every version leaves nothing behind.
            shutil.rmtree(self._socket_dir, ignore_errors=True)
            self._socket_dir = None

    async def _handle(self, creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter) -> None:
        """Per-connection server callback: read the 2-byte device-port header :meth:`dial`
        wrote, then bridge the stream to a pytcp socket."""
        if self._closing:
            # Accepted just as teardown began (see __aexit__): close the transport so
            # Server.wait_closed() can complete, and never touch the stack.
            cwriter.close()
            return
        # Track the handler task so __aexit__ can cancel any relay still in flight
        # (start_server's own task bookkeeping offers no cross-version cancel API).
        task = asyncio.current_task()
        assert task is not None
        self._relay_tasks.add(task)
        try:
            try:
                # dial() writes the header before returning, so a well-behaved client's header
                # arrives immediately; the timeout sheds strays that connect and send nothing
                # (on the TCP fallback any local process can), which would otherwise pin this
                # handler and its transport until tunnel close. Enforced via call_later rather
                # than wait_for: on Python <= 3.11 wait_for can swallow an external
                # cancellation that races the header's arrival, leaving teardown's cancel
                # lost and __aexit__ waiting on this handler forever (observed on slow CI).
                shed = asyncio.get_running_loop().call_later(RELAY_HEADER_TIMEOUT, cwriter.close)
                try:
                    port = int.from_bytes(await creader.readexactly(2), "big")
                finally:
                    shed.cancel()
            except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
                cwriter.close()
                return
            except BaseException:
                # Cancellation (teardown) while reading the header: still close the accepted
                # transport, or it stays attached and __aexit__ hangs in Server.wait_closed().
                cwriter.close()
                raise
            await self._relay_handler(port, creader, cwriter)
        finally:
            self._relay_tasks.discard(task)

    async def _relay_handler(self, port: int, creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter) -> None:
        try:
            psock = await self._tun.connect_tcp(self._device_addr, port)
        except Exception:
            logger.debug("relay connect_tcp(%s:%s) failed", self._device_addr, port, exc_info=True)
            cwriter.close()
            return
        except BaseException:
            # Cancellation (dial-plane teardown) while connecting: the accepted transport must
            # still be closed, or it stays attached to the relay server and __aexit__ hangs in
            # Server.wait_closed() (which waits for all attached connections since 3.12.1).
            cwriter.close()
            raise

        # Both pump directions are plain awaits on the same event loop the stack runs on: a
        # cancelled handler cancels the pumps at their await points, so nothing can stay
        # parked past teardown (the failure mode that used to require the rx-pump thread,
        # its 1 s poll and the daemon teardown thread — #1756).

        async def client_to_device() -> None:
            try:
                while True:
                    data = await creader.read(_CHUNK)
                    if not data:
                        break
                    await psock.send(data)
            except Exception:
                pass
            finally:
                # The client is gone — nothing in pymobiledevice3 half-closes its side
                # (every ServiceConnection teardown is a full close), so no device byte can
                # ever be delivered again. Fully close the pytcp socket: the FIN still goes
                # out (services that treat EOF as "finish and close" behave exactly as with
                # the previous SHUT_WR half-close), but the session is now ORPHANED, so a
                # device that neither answers nor FINs is reaped by pmd-pytcp's FIN_WAIT_2
                # orphan timer instead of pinning the session — and this handler — forever.
                # A mere half-close kept the socket open (a reader existed: device_to_client)
                # and the reaper is deliberately orphan-only, so abandoned relays accumulated
                # for the tunnel's lifetime (measured: 24 of 30 abandoned service connections
                # parked at psock.recv() until teardown). pmd-pytcp >= 0.3.4 wakes the pending
                # recv() on the session's death, letting the whole handler finish promptly.
                with suppress(Exception):
                    psock.close()

        async def device_to_client() -> None:
            try:
                while True:
                    data = await psock.recv(_CHUNK)
                    if not data:
                        break
                    cwriter.write(data)
                    await cwriter.drain()
            except Exception:
                pass
            finally:
                # Mirror of the half-close above: the device's EOF must reach the client, or
                # client_to_device keeps waiting on a client that has no reason to close.
                with suppress(Exception):
                    if cwriter.can_write_eof():
                        cwriter.write_eof()

        try:
            await asyncio.gather(client_to_device(), device_to_client())
        finally:
            with suppress(Exception):
                cwriter.close()
            # Socket teardown is sync and loop-safe now (no FSM lock to wedge on — the whole
            # stack runs on this loop).
            with suppress(Exception):
                psock.shutdown(SHUT_RDWR)
            with suppress(Exception):
                psock.close()

    async def dial(self, host: Optional[str] = None, port: Optional[int] = None, **kwargs: Any):
        """``asyncio.open_connection``-compatible dialer passed to the RSD via ``open_connection=``.

        Connections to the device's tunnel address are relayed through the userspace stack;
        everything else falls through to the stdlib ``asyncio.open_connection`` unchanged."""
        if host is not None and str(host) == self._device_addr:
            assert port is not None
            if self._closing or self._opener is None:
                # Post-teardown the connect would fail anyway (the listener is gone) — fail
                # with a clear error instead of a refused/missing-socket OSError.
                raise ConnectionError("userspace dial plane is closed")
            # Track in-flight connects: __aexit__ waits for them before closing the listener,
            # because a connect completing against a just-closed Server makes asyncio's accept
            # path abandon the accepted socket without closing it.
            self._inflight_dials += 1
            try:
                reader, writer = await self._opener(**kwargs)
            finally:
                self._inflight_dials -= 1
            if self._closing:
                writer.close()
                raise ConnectionError("userspace dial plane is closed")
            writer.write(port.to_bytes(2, "big"))  # header for _handle; flushed with first payload
            return reader, writer
        return await asyncio.open_connection(host, port, **kwargs)


# --- high-level in-process establishment (the no-root RSD path) --------------------------

#: The userspace tunnel active in this process, or None. PyTCP's stack is a process-global
#: singleton, so at most one exists; :class:`UserspaceRsdTunnel` sets this on open and clears
#: it on close. Device-initiated stream code (``screen_stream``) reads it through
#: :func:`userspace_stack_addr` / :data:`USERSPACE_ACTIVE` without holding a handle.
_active_tunnel: Optional[UserspaceRsdTunnel] = None

#: True while a userspace tunnel is active in this process. Mirrors ``_active_tunnel is not None``
#: (kept as a plain flag so callers can read it as an attribute).
USERSPACE_ACTIVE = False


def userspace_stack_addr() -> Optional[str]:
    """The host-side stack address on the active userspace tunnel (what a device should stream
    to), or None when no userspace tunnel is active."""
    if _active_tunnel is not None and _active_tunnel.tun is not None:
        return _active_tunnel.tun.addr
    return None


class UserspaceUdp:
    """An async UDP socket on the userspace pytcp stack.

    Device-initiated AV streams (serve-web/serve-vnc RTP) push UDP to a host endpoint. Over the
    userspace tunnel that endpoint must live on the pytcp stack — a host kernel socket is
    unreachable from the device. This binds a pytcp UDP socket on the stack address and presents
    the recv/sendto surface ``screen_stream`` needs. The pure-asyncio stack queues datagrams on
    the socket itself and ``recv`` is awaited directly — no reader thread, no relay queue.
    """

    def __init__(self) -> None:
        addr = userspace_stack_addr()
        if addr is None:
            raise PyMobileDevice3Exception("userspace tunnel is not active")
        self._sock = cast(_AsyncPytcpSocket, pytcp_socket(AF_INET6, SOCK_DGRAM))
        self._sock.bind((addr, 0))
        bound = self._sock.getsockname()
        self._local_ip, self._port = bound[0], bound[1]

    @property
    def local_ip(self) -> str:
        return self._local_ip

    @property
    def port(self) -> int:
        return self._port

    async def recv(self, bufsize: int = 65535) -> bytes:
        return await self._sock.recv(bufsize)

    async def sendto(self, data: bytes, ip: str, port: int) -> None:
        await self._sock.sendto(data, (ip, port))

    def close(self) -> None:
        with suppress(Exception):
            self._sock.close()


async def _create_no_root_tunnel_provider(serial: Optional[str], autopair: bool, remotepairing_fallback: bool = True):
    """Pick a tunnel provider that needs no root, mirroring ``remote start-tunnel``'s family:

    * iOS 17.4+ over USB: :class:`~pymobiledevice3.remote.tunnel_service.CoreDeviceTunnelProxy`
      (the ``com.apple.internal.devicecompute.CoreDeviceProxy`` lockdown service — no remoted).
    * iOS 17.0-17.3 / Wi-Fi: RemotePairing over bonjour
      (:func:`~pymobiledevice3.remote.tunnel_service.get_remote_pairing_tunnel_services`).

    The RSD/USB path (``get_core_device_tunnel_services``) is intentionally NOT attempted: it
    suspends remoted via :func:`stop_remoted`, which needs root on macOS — defeating the no-root
    purpose. Returns ``(provider, lockdown_or_None)``; the lockdown is kept alive for the
    CoreDeviceProxy provider and is ``None`` for the RemotePairing one.

    ``remotepairing_fallback`` controls the pre-17.4 path: when ``True`` (default) a device with no
    CoreDeviceProxy service falls back to RemotePairing over bonjour; when ``False`` it raises
    :class:`UserspaceTunnelUnavailableError` immediately (used when the caller prefers to route such
    devices elsewhere, e.g. a kernel tunnel). Either way, a device that cannot be served no-root
    raises :class:`UserspaceTunnelUnavailableError`.
    """
    lockdown = await create_using_usbmux(serial=serial, autopair=autopair)
    try:
        return await tunnel_service.CoreDeviceTunnelProxy.create(lockdown), lockdown
    except InvalidServiceError:
        # iOS < 17.4 has no CoreDeviceProxy lockdown service.
        await lockdown.close()
        if not remotepairing_fallback:
            raise UserspaceTunnelUnavailableError(
                "no-root userspace tunnel unavailable: the device has no CoreDeviceProxy service "
                "(needs iOS 17.4+) and the RemotePairing fallback was disabled."
            ) from None
        logger.info("CoreDeviceProxy unavailable (iOS < 17.4); falling back to RemotePairing over bonjour")
    except BaseException:
        await lockdown.close()
        raise

    services = await tunnel_service.get_remote_pairing_tunnel_services(udid=serial)
    if not services:
        raise UserspaceTunnelUnavailableError(
            "no-root userspace tunnel unavailable: the device exposes no CoreDeviceProxy lockdown "
            "service (needs iOS 17.4+) and no RemotePairing service was found over bonjour. Enable "
            "Wi-Fi for the device and host on the same network, or run a privileged kernel tunnel via "
            "`pymobiledevice3 remote tunneld`."
        )
    return services[0], None


class UserspaceRsdTunnel:
    """A no-root, in-process iOS 17+ RSD tunnel and its connected RSD, as one closeable handle.

    Replaces the kernel ``utun`` (which needs root/admin) with a pure-Python PyTCP stack, so the
    tunnel and every host-initiated developer service run as a normal user. Use it either way:

    Async context manager (closes automatically)::

        async with UserspaceRsdTunnel(serial=udid) as rsd:
            ...  # rsd is a connected RemoteServiceDiscoveryService

    Open / close handle::

        tunnel = UserspaceRsdTunnel(serial=udid)
        rsd = await tunnel.aopen()
        try:
            ...
        finally:
            await tunnel.aclose()

    ``serial`` selects the target device (``None`` => first USB device); ``autopair`` sets up the
    pairing on the fly if the device is not yet paired. Device selection (e.g. the CLI ``--udid`` /
    ``PYMOBILEDEVICE3_UDID`` resolution) and the usbmux socket location (incl. a remote usbmuxd)
    are resolved by the caller / usbmux layer, not here.

    Constraints:

    * **One tunnel per process.** PyTCP's stack is a process-global singleton; :meth:`aopen`
      raises if a userspace tunnel is already active. Not re-entrant or thread-safe.
    * **The device address is in-process only**, reachable only from this process's userspace
      stack — never by an external tool. The RSD reports this via
      :attr:`RemoteServiceDiscoveryService.is_in_process_tunnel`; don't hand its address to lldb.

    Host-initiated developer services all work. Device-initiated inbound UDP (the AV media streams
    behind ``display serve-web``) also works: the receiver is bound on the PyTCP stack via
    :class:`UserspaceUdp` and the stack address is advertised to the device, so its RTP terminates
    on the userspace stack instead of an unreachable host kernel socket.

    The tunnel provider is selected like ``remote start-tunnel`` but restricted to the root-free
    paths (see :func:`_create_no_root_tunnel_provider`): CoreDeviceTunnelProxy over lockdown on
    iOS 17.4+, falling back to RemotePairing over bonjour on iOS 17.0-17.3 / Wi-Fi.
    """

    def __init__(
        self, serial: Optional[str] = None, autopair: bool = True, remotepairing_fallback: bool = True
    ) -> None:
        self.serial = serial
        self.autopair = autopair
        self.remotepairing_fallback = remotepairing_fallback
        self.rsd: Optional[RemoteServiceDiscoveryService] = None
        self.tun: Optional[UserspaceTun] = None
        self._exit_stack: Optional[AsyncExitStack] = None
        self._transport_watcher: Optional[asyncio.Task[None]] = None

    async def aopen(self) -> RemoteServiceDiscoveryService:
        """Establish the tunnel and return the connected RSD. Idempotent on this handle; raises
        :class:`PyMobileDevice3Exception` if another userspace tunnel is already active."""
        global _active_tunnel, USERSPACE_ACTIVE
        if self.rsd is not None:
            return self.rsd
        async with _lifecycle_lock():
            return await self._aopen_locked()

    async def _aopen_locked(self) -> RemoteServiceDiscoveryService:
        global _active_tunnel, USERSPACE_ACTIVE
        if _active_tunnel is not None:
            raise PyMobileDevice3Exception(
                "a userspace tunnel is already active in this process (PyTCP's stack is a "
                "process-global singleton; only one userspace tunnel per process is supported)"
            )
        # pmd-pytcp presence was proven at import time (this module imports it at module level;
        # cli_common imports us inside a try/except that falls back to the kernel tunnel when that
        # fails). Select the userspace tun via the factory flag — no class is monkeypatched;
        # RemotePairingTunnel.start_tunnel() consults create_tun_device().
        tunnel_service.USE_USERSPACE_TUNNEL = True
        # Every resource is registered on one AsyncExitStack so aclose() unwinds them in LIFO
        # order; a failure mid-setup unwinds whatever was already acquired.
        stack = AsyncExitStack()
        try:
            provider, lockdown = await _create_no_root_tunnel_provider(
                self.serial, self.autopair, self.remotepairing_fallback
            )
            stack.push_async_callback(provider.close)
            if lockdown is not None:
                stack.push_async_callback(lockdown.close)
            tunnel_result = await stack.enter_async_context(provider.start_tcp_tunnel())
            # In the userspace path create_tun_device() always builds a UserspaceTun (the factory
            # flag is set above), so the loosely-typed client.tun is narrowed here.
            self.tun = cast(UserspaceTun, tunnel_result.client.tun)
            self.tun.set_peer(tunnel_result.address)
            dial_plane = await stack.enter_async_context(UserspaceDialPlane(self.tun, tunnel_result.address))
            # Inject the relay dialer into THIS rsd only (no global asyncio.open_connection patch),
            # so a library consumer's other connections in the same process stay on the stdlib default.
            rsd = RemoteServiceDiscoveryService(
                (tunnel_result.address, tunnel_result.port), open_connection=dial_plane.dial
            )
            stack.push_async_callback(rsd.close)
            await rsd.connect()
        except BaseException:
            await stack.aclose()
            tunnel_service.USE_USERSPACE_TUNNEL = False
            self.tun = None
            raise

        self._exit_stack = stack
        self.rsd = rsd
        _active_tunnel = self
        USERSPACE_ACTIVE = True
        self._transport_watcher = asyncio.create_task(
            self._watch_transport_closed(tunnel_result.client),
            name=f"userspace-tunnel-transport-watcher-{tunnel_result.address}",
        )
        logger.debug("userspace RSD established (no root): %s rsd_port=%s", tunnel_result.address, tunnel_result.port)
        return rsd

    async def _watch_transport_closed(self, client: tunnel_service.RemotePairingTunnel) -> None:
        """Tear the tunnel down when its outer transport dies (e.g. the USB cable is pulled:
        usbmuxd closes the CoreDeviceProxy connection and the transport read task just ends).

        Without this nothing wakes the pytcp sessions or the relay handlers — every in-flight
        service read parks forever. Keep-alive cannot cover it: a relay's peer is this very
        process, so loopback probes are always answered no matter what happened to the device.
        Closing the dial plane cancels the relay handlers, which surfaces EOF/connection errors
        to all blocked callers."""
        with suppress(Exception):
            await client.wait_closed()
        if self._exit_stack is None:
            return  # normal aclose() already ran
        logger.warning("userspace tunnel transport closed (device disconnected?); tearing down")
        try:
            await self.aclose()
        except Exception:
            # This task is fire-and-forget and it runs exactly when unwinding is most likely
            # to raise (the transport just died under the RSD); an unhandled exception here
            # would only surface as "Task exception was never retrieved" at GC.
            logger.warning("userspace tunnel teardown after transport death failed", exc_info=True)

    async def aclose(self) -> None:
        """Tear down the tunnel and its RSD, releasing every resource in LIFO order and restoring
        the kernel-tunnel factory default. Idempotent.

        After this returns, no background thread remains blocked (closing the tun wakes the parked
        reader), so the process can exit normally.

        Serialized with the transport watcher's teardown: an explicit aclose() during the
        watcher's unwind (device just disconnected) waits for that unwind instead of
        returning while resources are still being released — so aclose() returning means the
        process-global pytcp stack is really stopped and a new tunnel may be opened."""
        global _active_tunnel, USERSPACE_ACTIVE
        async with _lifecycle_lock():
            if self._exit_stack is None:
                return
            stack, self._exit_stack = self._exit_stack, None
            watcher, self._transport_watcher = self._transport_watcher, None
            if watcher is not None and watcher is not asyncio.current_task():
                # The watcher is parked in wait_closed() (it cannot be mid-aclose: that path
                # holds this lock) — safe to cancel.
                watcher.cancel()
            self.rsd = None
            self.tun = None
            if _active_tunnel is self:
                _active_tunnel = None
                USERSPACE_ACTIVE = False
                tunnel_service.USE_USERSPACE_TUNNEL = False
            await stack.aclose()

    #: ``open``/``close`` are aliases for :meth:`aopen`/:meth:`aclose` (still awaitable).
    open = aopen
    close = aclose

    async def __aenter__(self) -> RemoteServiceDiscoveryService:
        return await self.aopen()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()


_lifecycle_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = weakref.WeakKeyDictionary()


def _lifecycle_lock() -> asyncio.Lock:
    """The lock serializing every open/close transition of the process-global pytcp stack.

    aopen() checks the singleton guard and publishes _active_tunnel on opposite sides of the
    whole establishment, so without serialization two concurrent aopen() calls both pass the
    guard and drive the one stack at once (measured live: both handshakes die with
    IncompleteReadError and pmd-pytcp is left asserting "ARP Cache.start() called while a
    worker is still running"). It also serializes a new aopen() against a previous handle's
    still-unwinding teardown. One lock per event loop, created inside the loop (Python 3.9's
    primitives bind their loop at construction time)."""
    loop = asyncio.get_running_loop()
    lock = _lifecycle_locks.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _lifecycle_locks[loop] = lock
    return lock


#: Holds the CLI's tunnel for the process lifetime (closed at interpreter exit — the CLI has no
#: earlier teardown hook). Embedders hold their own UserspaceRsdTunnel.
_cli_tunnel: Optional[UserspaceRsdTunnel] = None


async def establish_userspace_rsd(
    serial: Optional[str] = None, autopair: bool = True, remotepairing_fallback: bool = True
) -> RemoteServiceDiscoveryService:
    """CLI convenience: establish a userspace tunnel, keep it alive, and return its connected RSD.

    Embedders should use :class:`UserspaceRsdTunnel` directly — it is a closeable handle / async
    context manager. This wrapper exists for the CLI, which has no teardown hook: it stashes the
    tunnel for the process lifetime and closes it at interpreter exit (a few ms).

    ``remotepairing_fallback=False`` makes a pre-17.4 device (no CoreDeviceProxy) raise
    :class:`UserspaceTunnelUnavailableError` instead of attempting RemotePairing, so the caller can
    route such devices elsewhere (the CLI uses this to fall back to ``tunneld``).
    """
    global _cli_tunnel
    # In-process retry (the CLI re-runs main() with the userspace env var set after an
    # InvalidServiceError): reuse the live tunnel — PyTCP's stack is a process-global
    # singleton, so a second establishment can only fail.
    if (
        _cli_tunnel is not None
        and _cli_tunnel.rsd is not None
        and (serial is None or serial in (_cli_tunnel.serial, _cli_tunnel.rsd.udid))
    ):
        return _cli_tunnel.rsd
    tunnel = UserspaceRsdTunnel(serial=serial, autopair=autopair, remotepairing_fallback=remotepairing_fallback)
    try:
        rsd = await tunnel.aopen()
    except PyMobileDevice3Exception:
        # Lost an establishment race (aopen serializes on the lifecycle lock, so by now the
        # winner has published): share its tunnel when it serves the requested device.
        winner = _cli_tunnel or _active_tunnel
        if (
            winner is not None
            and winner.rsd is not None
            and (serial is None or serial in (winner.serial, winner.rsd.udid))
        ):
            return winner.rsd
        raise
    _cli_tunnel = tunnel
    atexit.register(_close_cli_tunnel_at_exit)
    return rsd


def _close_cli_tunnel_at_exit() -> None:
    """Close the CLI's process-lifetime tunnel at interpreter exit (bounded; measured ~3 ms on
    a healthy tunnel — the device gets a clean FIN instead of an abandoned session).

    This replaced a hard ``os._exit`` whose reasons no longer exist: the pure-asyncio stack
    has no threads that could park exit, and the CLI's persistent loop is abandoned rather
    than closed, so there is no pending-task GC noise to mute either. Registration is
    idempotent in effect: aclose() is."""
    if _cli_tunnel is None or _cli_tunnel.rsd is None:
        return
    try:
        loop = get_asyncio_loop()
        if loop.is_running():
            return  # exiting from inside the loop; nothing safe to run here
        loop.run_until_complete(asyncio.wait_for(_cli_tunnel.aclose(), timeout=3))
    except Exception:
        logger.debug("closing the CLI tunnel at exit failed", exc_info=True)
