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
imports it at module level and ``cli_common`` establishes the userspace tunnel directly. The
fork is cross-platform on its own (it guards its Unix-only ``fcntl`` import, starts its worker
threads as daemons, logs through the ``pmd_pytcp`` logger, and ships the MLD attribute), so no
host-side compatibility shim is needed — only the throughput sysctls below, which ride the
fork's public knobs.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import socket
import struct
import sys
import threading
from contextlib import AsyncExitStack, suppress
from typing import Optional

from pmd_net_addr import Ip6Address, Ip6IfAddr, MacAddress
from pmd_pytcp import stack
from pmd_pytcp.lib.interface_layer import InterfaceLayer
from pmd_pytcp.lib.io_backend import register_interface_fd, unregister_interface_fd
from pmd_pytcp.socket import AF_INET6, SOCK_DGRAM, SOCK_STREAM
from pmd_pytcp.socket import socket as pytcp_socket
from pmd_pytcp.stack import sysctl

import pymobiledevice3.remote.tunnel_service as tunnel_service
from pymobiledevice3.exceptions import InvalidServiceError, PyMobileDevice3Exception
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
#: bounded separately by the tcp.snd_mss_max sysctl (:data:`MAX_SEND_MSS`), so a large
#: value is safe here.
INTERFACE_MTU = 16000

#: Receive-window ceiling (PyTCP 'tcp.rcv_wnd_max'; default 65535). A download is bounded by
#: window / RTT, so 64 KB throttles it; 4 MiB keeps a full bandwidth-delay-product in flight and
#: stays within PyTCP's negotiated window-scale-7 reach (~8 MiB). Measured on an iOS 17+ DSC
#: fetch: 64 KB window -> 8 MB/s, 4 MiB window -> 40 MB/s (kernel-tunnel parity).
MAX_RECV_WINDOW = 4 * 1024 * 1024

#: Cap on the host->device send MSS (PyTCP 'tcp.snd_mss_max'; 0 = uncapped). 1340 (= a 1400-byte
#: IPv6 packet minus 40+20 headers) is the proven-safe send size; a larger interface MTU keeps
#: downloads fast (big device->host segments) while uploads avoid RTO stalls on the forwarding
#: path. The advertised receive MSS is untouched, so downloads stay fast.
MAX_SEND_MSS = 1340


def throughput_sysctls() -> dict[str, int]:
    """The ``stack.init(sysctls=...)`` entries that tune the tunnel for bulk transfer.

    These ride pmd-pytcp's public sysctls: ``tcp.rcv_wnd_max`` raises the advertised receive
    window for fast downloads; ``tcp.snd_mss_max`` caps host->device segments so a large
    interface MTU does not stall uploads. Any knob the installed pmd-pytcp does not register is
    omitted (with a warning) so the tunnel runs untuned rather than failing.
    """
    wanted = {"tcp.rcv_wnd_max": MAX_RECV_WINDOW, "tcp.default.snd_mss_max": MAX_SEND_MSS}
    # The registry lists base keys, so an interface-scope knob is checked by its base name.
    base_key = {"tcp.rcv_wnd_max": "tcp.rcv_wnd_max", "tcp.default.snd_mss_max": "tcp.snd_mss_max"}
    registered = sysctl.list_keys()
    out: dict[str, int] = {}
    for key, value in wanted.items():
        if base_key[key] in registered:
            out[key] = value
        else:
            logger.warning("userspace tunnel: installed pmd-pytcp lacks the %r sysctl; running untuned", base_key[key])
    return out


#: Datagram socketpair buffer, sized to hold a burst of a full receive window of packets.
SOCKET_BUFFER_SIZE = 8 * 1024 * 1024

#: Read/relay chunk size for the dial-plane bridge.
_CHUNK = 65536

#: pmd3's per-OS tun loopback header (macOS: b"\x00\x00\x00\x1e" = AF_INET6).
LOOPBACK_HEADER = get_os_utils().loopback_header


def _mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _eth_header(dst_mac: str, src_mac: str) -> bytes:
    return _mac_to_bytes(dst_mac) + _mac_to_bytes(src_mac) + struct.pack("!H", _ETH_IPV6)


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
    """Drop-in for ``pytun_pmd3.TunTapDevice`` backed by a PyTCP L2 stack.

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

    def up(self) -> None:
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
        stack.start()
        logger.debug("userspace tunnel up: pytcp L2 iface=%s addr=%s/64 mtu=%s", self._ifidx, self._addr, self._mtu)

    def set_peer(self, device_addr: str) -> None:
        """Install a static neighbor for the device (point-to-point; skips ND)."""
        stack.neighbor.interface(self._ifidx).add(ip=Ip6Address(device_addr), mac=MacAddress(_PEER_MAC))

    def write(self, data: bytes) -> None:
        # inbound (device -> stack): strip pmd3 loopback header, add Ethernet, enqueue
        ipv6 = data[len(LOOPBACK_HEADER) :] if data[: len(LOOPBACK_HEADER)] == LOOPBACK_HEADER else data
        with suppress(OSError):
            self._peer.send(_eth_header(_STACK_MAC, _PEER_MAC) + ipv6)

    def _recv_ipv6(self) -> bytes:
        # outbound (stack -> device): block for an Ethernet frame, return its IPv6 payload
        while not self._closed:
            try:
                frame = self._peer.recv(65535)
            except OSError:
                return b""
            if len(frame) < 14 or struct.unpack("!H", frame[12:14])[0] != _ETH_IPV6:
                continue
            return frame[14:]
        return b""

    def read(self, size: int) -> bytes:
        # Unix tun_read_task path: returns loopback-prefixed IPv6 (caller strips the header).
        ipv6 = self._recv_ipv6()
        return LOOPBACK_HEADER + ipv6 if ipv6 else b""

    async def async_read(self) -> bytes:
        # Windows tun_read_task path: wants a RAW IPv6 packet (it checks the version nibble,
        # no loopback header), delivered asynchronously.
        return await asyncio.to_thread(self._recv_ipv6)

    def connect_tcp(self, addr: str, port: int):
        """Open a blocking PyTCP TCP socket to (addr, port) over this stack."""
        s = pytcp_socket(AF_INET6, SOCK_STREAM)
        s.connect((addr, port))
        return s

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Wake a thread parked in _recv_ipv6: tun_read_task runs the blocking UserspaceTun.read in
        # the default ThreadPoolExecutor, whose workers are NON-daemon and are joined at interpreter
        # shutdown. Closing the socket from another thread does NOT reliably interrupt a blocked
        # recv(), so the read would stay parked and that join would hang forever — which is why a
        # hard exit (force_exit) was previously required. Push a 1-byte sentinel into the receiving
        # end instead: _recv_ipv6's frame filter ignores it (len < 14) and the loop re-checks
        # _closed and returns b"", so the worker finishes and the join completes promptly.
        with suppress(OSError):
            self._pend.send(b"\x00")
        unregister_interface_fd(self._pend)
        # Close the socketpair so PyTCP's RX/TX ring threads (parked in read/select on the fd)
        # unblock, then stop the stack — otherwise stop() deadlocks on those threads.
        for s in (self._peer, self._pend):
            with suppress(Exception):
                s.close()
        try:
            stack.stop()
            stack._pmd3_inited = False  # type: ignore[attr-defined]
        except Exception:
            logger.debug("error stopping pytcp stack", exc_info=True)


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

    async def __aenter__(self) -> UserspaceDialPlane:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        for srv in self._servers:
            srv.close()
        for srv in self._servers:
            with suppress(Exception):
                await srv.wait_closed()
        self._servers.clear()
        self._relays.clear()

    async def _relay_handler(self, port: int, creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter) -> None:
        loop = asyncio.get_running_loop()
        try:
            psock = await asyncio.to_thread(self._tun.connect_tcp, self._device_addr, port)
        except Exception:
            logger.debug("relay connect_tcp(%s:%s) failed", self._device_addr, port, exc_info=True)
            cwriter.close()
            return

        # device -> client: PyTCP recv() blocks and does NOT unblock on close(), so pump it
        # in a DAEMON thread bridged to asyncio via a queue. Daemon threads are killed at
        # process exit without being joined, so shutdown never hangs.
        rx_queue: asyncio.Queue = asyncio.Queue(maxsize=256)

        def rx_pump() -> None:
            try:
                while True:
                    data = psock.recv(_CHUNK)
                    loop.call_soon_threadsafe(rx_queue.put_nowait, data)
                    if not data:
                        break
            except Exception:
                loop.call_soon_threadsafe(rx_queue.put_nowait, b"")

        threading.Thread(target=rx_pump, daemon=True).start()

        async def client_to_device() -> None:
            try:
                while True:
                    data = await creader.read(_CHUNK)
                    if not data:
                        break
                    await asyncio.to_thread(psock.send, data)
            except Exception:
                pass

        async def device_to_client() -> None:
            try:
                while True:
                    data = await rx_queue.get()
                    if not data:
                        break
                    cwriter.write(data)
                    await cwriter.drain()
            except Exception:
                pass

        try:
            await asyncio.gather(client_to_device(), device_to_client())
        finally:
            for closer in (psock.close, cwriter.close):
                with suppress(Exception):
                    closer()

    async def _ensure_relay(self, port: int) -> int:
        key = (self._device_addr, port)
        if key in self._relays:
            return self._relays[key]

        async def handle(creader: asyncio.StreamReader, cwriter: asyncio.StreamWriter) -> None:
            await self._relay_handler(port, creader, cwriter)

        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        self._servers.append(srv)
        lport = srv.sockets[0].getsockname()[1]
        self._relays[key] = lport
        logger.debug("userspace relay %s:%s -> 127.0.0.1:%s", self._device_addr, port, lport)
        return lport

    async def dial(self, host=None, port=None, **kwargs):
        """``asyncio.open_connection``-compatible dialer passed to the RSD via ``open_connection=``.

        Connections to the device's tunnel address are relayed through the userspace stack;
        everything else falls through to the stdlib ``asyncio.open_connection`` unchanged."""
        if host is not None and str(host) == self._device_addr:
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
    the recv/sendto surface ``screen_stream`` needs. A dedicated reader thread drains the socket
    into an asyncio queue so the hot receive path is not a per-packet ``asyncio.to_thread`` hop.
    """

    def __init__(self, recv_queue_max: int = 8192) -> None:
        addr = userspace_stack_addr()
        if addr is None:
            raise PyMobileDevice3Exception("userspace tunnel is not active")
        self._sock = pytcp_socket(AF_INET6, SOCK_DGRAM)
        self._sock.bind((addr, 0))
        bound = self._sock.getsockname()
        self._local_ip, self._port = bound[0], bound[1]
        self._loop = asyncio.get_event_loop()
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=recv_queue_max)
        self._closed = False
        self._reader = threading.Thread(target=self._read_loop, name="userspace-udp-recv", daemon=True)
        self._reader.start()

    @property
    def local_ip(self) -> str:
        return self._local_ip

    @property
    def port(self) -> int:
        return self._port

    def _read_loop(self) -> None:
        # Blocking recv off the pytcp stack in its own thread, handing each datagram to the
        # event loop. The 0.5 s timeout paces the idle loop and lets it observe close(); a
        # TimeoutError is the idle case (loop again), any other error means the socket is gone
        # so the thread exits — the consumer task is cancelled on teardown, and a genuinely
        # dead stream is restarted by screen_stream's stall watchdog.
        while not self._closed:
            try:
                data = self._sock.recv(65535, timeout=0.5)
            except TimeoutError:
                continue
            except Exception:
                return
            if not data:
                continue
            try:
                self._loop.call_soon_threadsafe(self._enqueue, data)
            except RuntimeError:
                return  # event loop closed

    def _enqueue(self, data: bytes) -> None:
        with suppress(asyncio.QueueFull):
            self._queue.put_nowait(data)

    async def recv(self, bufsize: int = 65535) -> bytes:
        # bufsize is accepted for socket-API parity; UDP datagrams are queued whole.
        return await self._queue.get()

    async def sendto(self, data: bytes, ip: str, port: int) -> None:
        await asyncio.to_thread(self._sock.sendto, data, (ip, port))

    def close(self) -> None:
        self._closed = True
        with suppress(Exception):
            self._sock.close()


async def _create_no_root_tunnel_provider(serial: Optional[str], autopair: bool):
    """Pick a tunnel provider that needs no root, mirroring ``remote start-tunnel``'s family:

    * iOS 17.4+ over USB: :class:`~pymobiledevice3.remote.tunnel_service.CoreDeviceTunnelProxy`
      (the ``com.apple.internal.devicecompute.CoreDeviceProxy`` lockdown service — no remoted).
    * iOS 17.0-17.3 / Wi-Fi: RemotePairing over bonjour
      (:func:`~pymobiledevice3.remote.tunnel_service.get_remote_pairing_tunnel_services`).

    The RSD/USB path (``get_core_device_tunnel_services``) is intentionally NOT attempted: it
    suspends remoted via :func:`stop_remoted`, which needs root on macOS — defeating the no-root
    purpose. Returns ``(provider, lockdown_or_None)``; the lockdown is kept alive for the
    CoreDeviceProxy provider and is ``None`` for the RemotePairing one.
    """
    lockdown = await create_using_usbmux(serial=serial, autopair=autopair)
    try:
        return await tunnel_service.CoreDeviceTunnelProxy.create(lockdown), lockdown
    except InvalidServiceError:
        # iOS < 17.4 has no CoreDeviceProxy lockdown service; fall back to the no-root WiFi path.
        logger.info("CoreDeviceProxy unavailable (iOS < 17.4); falling back to RemotePairing over bonjour")
        await lockdown.close()
    except BaseException:
        await lockdown.close()
        raise

    services = await tunnel_service.get_remote_pairing_tunnel_services(udid=serial)
    if not services:
        raise PyMobileDevice3Exception(
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

    def __init__(self, serial: Optional[str] = None, autopair: bool = True) -> None:
        self.serial = serial
        self.autopair = autopair
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
            provider, lockdown = await _create_no_root_tunnel_provider(self.serial, self.autopair)
            stack.push_async_callback(provider.close)
            if lockdown is not None:
                stack.push_async_callback(lockdown.close)
            tunnel_result = await stack.enter_async_context(provider.start_tcp_tunnel())
            self.tun = tunnel_result.client.tun
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

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.aclose()


#: Holds the CLI's tunnel for the process lifetime (the CLI has no teardown hook and hard-exits
#: via force_exit instead of calling aclose). Embedders hold their own UserspaceRsdTunnel.
_cli_tunnel: Optional[UserspaceRsdTunnel] = None


async def establish_userspace_rsd(serial: Optional[str] = None, autopair: bool = True) -> RemoteServiceDiscoveryService:
    """CLI convenience: establish a userspace tunnel, keep it alive, and return its connected RSD.

    Embedders should use :class:`UserspaceRsdTunnel` directly — it is a closeable handle / async
    context manager. This wrapper exists for the CLI, which has no teardown hook: it stashes the
    tunnel for the process lifetime and registers :func:`force_exit` so the CLI exits promptly at
    the end without awaiting teardown (see :func:`_register_clean_exit`).
    """
    global _cli_tunnel
    tunnel = UserspaceRsdTunnel(serial=serial, autopair=autopair)
    rsd = await tunnel.aopen()
    _cli_tunnel = tunnel
    await _register_clean_exit()
    return rsd


async def _register_clean_exit() -> None:
    # pmd3's tun_read_task parks a blocking UserspaceTun.read in the default ThreadPoolExecutor.
    # At interpreter shutdown, threading._shutdown joins those executor threads BEFORE regular
    # atexit handlers run, and that join blocks forever on the parked read. Register force_exit
    # via threading's own shutdown hook so it runs before that join. Handlers run
    # last-registered-first, so we first touch the default executor (await a no-op in it) to
    # force concurrent.futures' own join-hook to register before ours — then ours wins.
    atexit.register(force_exit)  # fallback
    try:
        await asyncio.to_thread(lambda: None)  # ensure the executor's shutdown hook registers first
        threading._register_atexit(force_exit)  # type: ignore[attr-defined]
    except Exception:
        logger.debug("could not register threading shutdown hook", exc_info=True)


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
