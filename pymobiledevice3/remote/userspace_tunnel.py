"""Userspace (root-free) tunnel backend for iOS 17+ RSD/RemotePairing tunnels.

The standard tunnel writes raw IPv6 packets to a kernel ``utun``, which needs admin/root.
This backend replaces the kernel interface with a pure-Python TCP/IP stack (PyTCP) so the
tunnel and all host-initiated RSD developer services run as a normal user.

Two pieces:

* :class:`UserspaceTun` — a drop-in for ``pytun_pmd3.TunTapDevice`` (same
  ``mtu``/``addr``/``up``/``write``/``read``/``close`` surface) that bridges packets to a
  PyTCP L2 stack over a datagram socketpair plus a 14-byte Ethernet shim. (PyTCP's mature
  path is L2; its L3/TUN egress is buggy.)
* :class:`UserspaceDialPlane` — wraps :func:`asyncio.open_connection` so connections to the
  device's tunnel address are relayed through a localhost socket into a PyTCP socket. This
  covers the RSD HTTP/2 handshake and every ``ServiceConnection.create_using_tcp``.

PyTCP ships only on Python >= 3.14, so it is an OPTIONAL dependency. This module imports
:mod:`pymobiledevice3.remote.pytcp_compat` (which imports PyTCP) at module level, so importing
it REQUIRES PyTCP; ``cli_common`` imports this module inside a try/except and falls back to the
kernel tunnel when PyTCP is absent. All PyTCP/OS-internal workarounds — and the single PyTCP
import point that the symbols below are re-exported from — live in ``pytcp_compat``, not here.
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

import pymobiledevice3.remote.pytcp_compat as pytcp_compat
import pymobiledevice3.remote.tunnel_service as tunnel_service
from pymobiledevice3.exceptions import InvalidServiceError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.pytcp_compat import (  # PyTCP symbols, re-exported post-fcntl-stub
    AF_INET6,
    SOCK_STREAM,
    InterfaceLayer,
    Ip6Address,
    Ip6IfAddr,
    MacAddress,
    pytcp_socket,
    stack,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

logger = logging.getLogger(__name__)

_ETH_IPV6 = 0x86DD
_STACK_MAC = "02:00:00:00:00:01"
_PEER_MAC = "02:00:00:00:00:02"

#: Ceiling on the PyTCP interface MTU. The tunnel negotiates 16000; a large interface MTU
#: makes downloads fast (the device sends big segments to us). Host->device segments are
#: bounded separately by the tcp.snd_mss_max sysctl (pytcp_compat.MAX_SEND_MSS), so a large
#: value is safe here.
INTERFACE_MTU = 16000

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
        pytcp_compat.apply()
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

        with pytcp_compat.daemonize_new_threads():
            if not getattr(stack, "_pmd3_inited", False):
                # accept_dad off (point-to-point link, no DAD peer) + the throughput sysctls
                # (public PyTCP knobs; omitted automatically on a PyTCP too old to have them).
                sysctls = {"icmp6.default.accept_dad": 0, **pytcp_compat.throughput_sysctls()}
                stack.init(sysctls=sysctls)
                stack._pmd3_inited = True  # type: ignore[attr-defined]
            pytcp_compat.register_interface_fd(self._pend)
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
        logger.info("userspace tunnel up: pytcp L2 iface=%s addr=%s/64 mtu=%s", self._ifidx, self._addr, self._mtu)

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
        pytcp_compat.unregister_interface_fd(self._pend)
        # Close the socketpair FIRST so PyTCP's RX/TX ring threads (parked in read/select on
        # the fd) unblock, then stop the stack — otherwise stop() deadlocks on those threads.
        for s in (self._peer, self._pend):
            with suppress(Exception):
                s.close()
        try:
            stack.stop()
            stack._pmd3_inited = False  # type: ignore[attr-defined]
        except Exception:
            logger.debug("error stopping pytcp stack", exc_info=True)


class UserspaceDialPlane:
    """Redirects device-bound ``asyncio.open_connection`` to localhost relays that bridge to
    PyTCP sockets. Use as an async context manager: ``__aenter__`` installs the redirect and
    ``__aexit__`` restores ``asyncio.open_connection`` and tears the relay servers down."""

    def __init__(self, tun: UserspaceTun, device_addr: str) -> None:
        self._tun = tun
        self._device_addr = str(device_addr)
        self._relays: dict[tuple[str, int], int] = {}
        self._servers: list[asyncio.AbstractServer] = []  # kept referenced so relays stay alive
        self._real_open_connection = asyncio.open_connection
        self._installed = False

    async def __aenter__(self) -> UserspaceDialPlane:
        if not self._installed:
            asyncio.open_connection = self._open_connection  # type: ignore[assignment]
            self._installed = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self._installed:
            return
        asyncio.open_connection = self._real_open_connection  # type: ignore[assignment]
        self._installed = False
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

    async def _open_connection(self, host=None, port=None, **kwargs):
        if host is not None and str(host) == self._device_addr:
            lport = await self._ensure_relay(port)
            return await self._real_open_connection("127.0.0.1", lport, **kwargs)
        return await self._real_open_connection(host, port, **kwargs)


# --- high-level in-process establishment (the default no-root RSD path) -----------------

#: Owns the established tunnel's resources (transport, tunnel, dial plane, RSD) for the
#: process duration; keeping them referenced also keeps their background tasks running.
#: :func:`aclose_userspace` unwinds it.
_EXIT_STACK: Optional[AsyncExitStack] = None

#: True once a userspace tunnel has been established in this process. The CLI uses this to
#: force a hard exit at teardown (PyTCP/asyncio teardown otherwise hangs).
USERSPACE_ACTIVE = False


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


async def establish_userspace_rsd(serial: Optional[str] = None, autopair: bool = True):
    """Establish an iOS 17+ RSD tunnel IN-PROCESS over a userspace stack — no root.

    Returns a connected :class:`RemoteServiceDiscoveryService`. The tunnel and dial plane
    are kept alive for the process lifetime; since graceful teardown is not yet clean,
    callers (the CLI) should hard-exit via :func:`force_exit` when done.

    The tunnel provider is selected like ``remote start-tunnel``, but restricted to the
    root-free paths (see :func:`_create_no_root_tunnel_provider`): CoreDeviceTunnelProxy over
    lockdown on iOS 17.4+, falling back to RemotePairing over bonjour on iOS 17.0-17.3 / Wi-Fi.

    NOTE: device-initiated inbound flows (serve-vnc/serve-web/screen_stream AV) are NOT
    handled — they bind a UDP receiver and advertise its address to the device, which a
    userspace stack would need per-site changes to serve. Host-initiated developer services
    (the common case) all work.
    """
    global USERSPACE_ACTIVE, _EXIT_STACK
    # PyTCP presence was already proven at import time (this module imports pytcp_compat, which
    # imports PyTCP); cli_common imports us inside a try/except that falls back to the kernel
    # tunnel when that import fails. Select the userspace tun in tunnel_service's factory — no
    # class is monkeypatched; RemotePairingTunnel.start_tunnel() consults create_tun_device().
    tunnel_service.USE_USERSPACE_TUNNEL = True

    # `serial` selects the target device (None => first USB device). Device selection — incl.
    # the --udid / PYMOBILEDEVICE3_UDID resolution — is the caller's job (cli_common._cli_udid);
    # this low-level entry point does not read CLI env vars itself. The usbmux socket location
    # (incl. a remote usbmuxd) is resolved centrally in MuxConnection._resolve_usbmux_address.

    # Every resource is registered on a single AsyncExitStack that owns process-lifetime
    # teardown (see aclose_userspace). On any failure during setup, the stack unwinds what was
    # already acquired, in LIFO order; on success it is stashed in _EXIT_STACK.
    stack = AsyncExitStack()
    try:
        provider, lockdown = await _create_no_root_tunnel_provider(serial, autopair)
        stack.push_async_callback(provider.close)
        if lockdown is not None:
            stack.push_async_callback(lockdown.close)
        tunnel_result = await stack.enter_async_context(provider.start_tcp_tunnel())
        tun = tunnel_result.client.tun
        tun.set_peer(tunnel_result.address)
        await stack.enter_async_context(UserspaceDialPlane(tun, tunnel_result.address))
        rsd = RemoteServiceDiscoveryService((tunnel_result.address, tunnel_result.port))
        stack.push_async_callback(rsd.close)
        await rsd.connect()
    except BaseException:
        await stack.aclose()
        raise

    _EXIT_STACK = stack
    USERSPACE_ACTIVE = True

    await _register_clean_exit()
    logger.info("userspace RSD established (no root): %s rsd_port=%s", tunnel_result.address, tunnel_result.port)
    return rsd


async def aclose_userspace() -> None:
    """Graceful teardown of the userspace tunnel's resources (the inverse of
    :func:`establish_userspace_rsd`). Closes everything the establish stack acquired in LIFO
    order. The CLI currently hard-exits via :func:`force_exit` instead — see its docstring —
    but this provides the clean path for embedders and tests."""
    global _EXIT_STACK, USERSPACE_ACTIVE
    if _EXIT_STACK is None:
        return
    stack, _EXIT_STACK = _EXIT_STACK, None
    USERSPACE_ACTIVE = False
    await stack.aclose()


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
    """Flush output and hard-exit, bypassing the (currently non-graceful) userspace stack
    teardown. No-op unless a userspace tunnel was established."""
    if not USERSPACE_ACTIVE:
        return
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(code)
