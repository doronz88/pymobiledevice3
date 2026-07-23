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
  device's tunnel address through a localhost socket into a PyTCP socket. This covers the RSD HTTP/2
  handshake and every ``ServiceConnection.create_using_tcp`` while leaving the process-global
  ``asyncio.open_connection`` untouched for any other code sharing the process.
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
import socket
import struct
import sys
from contextlib import AsyncExitStack, suppress
from typing import Any, Optional, Protocol, cast

from pmd_net_addr import Ip6Address, Ip6IfAddr, MacAddress
from pmd_pytcp import stack
from pmd_pytcp.lib.interface_layer import InterfaceLayer
from pmd_pytcp.lib.io_backend import register_interface_fd, unregister_interface_fd
from pmd_pytcp.socket import AF_INET6, SHUT_RDWR, SHUT_WR, SOCK_DGRAM, SOCK_STREAM
from pmd_pytcp.socket import socket as pytcp_socket

import pymobiledevice3.remote.tunnel_service as tunnel_service
from pymobiledevice3.exceptions import InvalidServiceError, PyMobileDevice3Exception, UserspaceTunnelUnavailableError
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

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
SOCKET_BUFFER_SIZE = 8 * 1024 * 1024

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
            stack._pmd3_inited = False  # type: ignore[attr-defined]
        except Exception:
            logger.debug("error stopping pytcp stack", exc_info=True)
        unregister_interface_fd(self._pend)
        for s in (self._peer, self._pend):
            with suppress(Exception):
                s.close()


class UserspaceDialPlane:
    """Provides an ``asyncio.open_connection``-compatible :meth:`dial` that bridges device-bound
    connections to PyTCP sockets via localhost relays.

    Pass :meth:`dial` to ``RemoteServiceDiscoveryService(open_connection=...)`` so ONLY connections
    made through that RSD are relayed. This deliberately does NOT monkeypatch the process-global
    ``asyncio.open_connection``: a library consumer who establishes a userspace tunnel keeps the
    stdlib function untouched, so unrelated connections elsewhere in their process are unaffected.

    Use as an async context manager so the localhost relay servers are torn down on exit."""

    def __init__(self, tun: UserspaceTun, device_addr: str) -> None:
        self._tun = tun
        self._device_addr = str(device_addr)
        self._relays: dict[tuple[str, int], int] = {}
        self._servers: list[asyncio.AbstractServer] = []  # kept referenced so relays stay alive
        self._relay_tasks: set[asyncio.Task[None]] = set()  # in-flight handlers, cancelled on exit

    async def __aenter__(self) -> UserspaceDialPlane:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        for srv in self._servers:
            srv.close()
        # Cancel the in-flight relay handlers BEFORE wait_closed(): since Python 3.12.1
        # Server.wait_closed() also waits for every active connection handler, and a relay
        # parked on device traffic never finishes on its own — teardown would hang until the
        # caller's timeout (issue #1756). Cancelling here (instead of leaving orphan tasks for
        # the loop's shutdown to cancel) also guarantees each handler's psock cleanup runs
        # while the stack is still up, and that no relay task outlives the dial plane.
        for task in list(self._relay_tasks):
            task.cancel()
        if self._relay_tasks:
            await asyncio.gather(*self._relay_tasks, return_exceptions=True)
        for srv in self._servers:
            with suppress(Exception):
                await srv.wait_closed()
        self._servers.clear()
        self._relays.clear()

    async def _relay_handler(self, port: int, creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter) -> None:
        try:
            psock = await self._tun.connect_tcp(self._device_addr, port)
        except Exception:
            logger.debug("relay connect_tcp(%s:%s) failed", self._device_addr, port, exc_info=True)
            cwriter.close()
            return

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
                # Propagate the client's EOF to the device as a FIN (half-close). The device
                # then finishes its side and its FIN ends device_to_client with b"", letting
                # the whole handler complete. Without this the handler waits on device
                # traffic forever after the client is gone (#1756).
                with suppress(Exception):
                    psock.shutdown(SHUT_WR)

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

    async def _ensure_relay(self, port: int) -> int:
        key = (self._device_addr, port)
        if key in self._relays:
            return self._relays[key]

        async def handle(creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter) -> None:
            # Track the handler task so __aexit__ can cancel any relay still in flight
            # (start_server's own task bookkeeping offers no cross-version cancel API).
            task = asyncio.current_task()
            assert task is not None
            self._relay_tasks.add(task)
            try:
                await self._relay_handler(port, creader, cwriter)
            finally:
                self._relay_tasks.discard(task)

        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        self._servers.append(srv)
        lport = srv.sockets[0].getsockname()[1]
        self._relays[key] = lport
        logger.debug("userspace relay %s:%s -> 127.0.0.1:%s", self._device_addr, port, lport)
        return lport

    async def dial(self, host: Optional[str] = None, port: Optional[int] = None, **kwargs: Any):
        """``asyncio.open_connection``-compatible dialer passed to the RSD via ``open_connection=``.

        Connections to the device's tunnel address are relayed through the userspace stack;
        everything else falls through to the stdlib ``asyncio.open_connection`` unchanged."""
        if host is not None and str(host) == self._device_addr:
            assert port is not None
            lport = await self._ensure_relay(port)
            return await asyncio.open_connection("127.0.0.1", lport, **kwargs)
        return await asyncio.open_connection(host, port, **kwargs)


# --- high-level in-process establishment (the no-root RSD path) --------------------------

#: The userspace tunnel active in this process, or None. PyTCP's stack is a process-global
#: singleton, so at most one exists; :class:`UserspaceRsdTunnel` sets this on open and clears
#: it on close. Device-initiated stream code (``screen_stream``) reads it through
#: :func:`userspace_stack_addr` / :data:`USERSPACE_ACTIVE` without holding a handle.
_active_tunnel: Optional[UserspaceRsdTunnel] = None

#: True while a userspace tunnel is active in this process. Mirrors ``_active_tunnel is not None``
#: (kept as a plain flag so callers can read it as an attribute). The CLI also uses it to gate the
#: hard exit in :func:`force_exit`.
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

    async def aopen(self) -> RemoteServiceDiscoveryService:
        """Establish the tunnel and return the connected RSD. Idempotent on this handle; raises
        :class:`PyMobileDevice3Exception` if another userspace tunnel is already active."""
        global _active_tunnel, USERSPACE_ACTIVE
        if self.rsd is not None:
            return self.rsd
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
        logger.debug("userspace RSD established (no root): %s rsd_port=%s", tunnel_result.address, tunnel_result.port)
        return rsd

    async def aclose(self) -> None:
        """Tear down the tunnel and its RSD, releasing every resource in LIFO order and restoring
        the kernel-tunnel factory default. Idempotent.

        After this returns, no background thread remains blocked (closing the tun wakes the parked
        reader), so the process can exit normally — embedders do NOT need :func:`force_exit`."""
        global _active_tunnel, USERSPACE_ACTIVE
        if self._exit_stack is None:
            return
        stack, self._exit_stack = self._exit_stack, None
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


#: Holds the CLI's tunnel for the process lifetime (the CLI has no teardown hook and hard-exits
#: via force_exit instead of calling aclose). Embedders hold their own UserspaceRsdTunnel.
_cli_tunnel: Optional[UserspaceRsdTunnel] = None


async def establish_userspace_rsd(
    serial: Optional[str] = None, autopair: bool = True, remotepairing_fallback: bool = True
) -> RemoteServiceDiscoveryService:
    """CLI convenience: establish a userspace tunnel, keep it alive, and return its connected RSD.

    Embedders should use :class:`UserspaceRsdTunnel` directly — it is a closeable handle / async
    context manager. This wrapper exists for the CLI, which has no teardown hook: it stashes the
    tunnel for the process lifetime and registers :func:`force_exit` at exit so the CLI exits
    promptly without awaiting teardown.

    ``remotepairing_fallback=False`` makes a pre-17.4 device (no CoreDeviceProxy) raise
    :class:`UserspaceTunnelUnavailableError` instead of attempting RemotePairing, so the caller can
    route such devices elsewhere (the CLI uses this to fall back to ``tunneld``).
    """
    global _cli_tunnel
    tunnel = UserspaceRsdTunnel(serial=serial, autopair=autopair, remotepairing_fallback=remotepairing_fallback)
    rsd = await tunnel.aopen()
    _cli_tunnel = tunnel
    # The pure-asyncio stack has no threads to park, so process exit cannot hang anymore. The
    # CLI still never closes its tunnel (it lives for the process lifetime), so hard-exit at
    # atexit to skip the "Task was destroyed but it is pending!" GC noise from the stack's
    # still-scheduled loop tasks. Embedders who call aclose() never reach this with
    # USERSPACE_ACTIVE set.
    atexit.register(force_exit)
    return rsd


def force_exit(code: int = 0) -> None:
    """Flush output and hard-exit, skipping userspace tunnel teardown. No-op unless a userspace
    tunnel is active. Used by the CLI, which keeps its tunnel for the process lifetime instead of
    closing it; embedders should prefer :meth:`UserspaceRsdTunnel.aclose`, which tears down
    cleanly and lets the process exit on its own."""
    if not USERSPACE_ACTIVE:
        return
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(code)
