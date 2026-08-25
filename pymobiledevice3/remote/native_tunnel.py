"""macOS-only: reach an iOS 17+ device's RSD by piggybacking Apple's own ``remoted`` tunnel.

Instead of building our own tunnel (kernel ``utun`` -> root, or the in-process userspace stack) or
suspending ``remoted`` for the bonjour/RSD path, this asks the base-OS pairing daemon
``com.apple.CoreDevice.remotepairingd`` (provided by ``RemotePairing.framework`` -- present on stock
macOS, no Xcode) to hand us the device's existing tunnel, then rides it:

1. Browse ``remotepairingd`` for the device and open its per-device XPC endpoint.
2. ``RemotePairing.CreateAssertionCommand`` -> the device's in-tunnel ``tunnelIPAddress`` plus an
   assertion identifier that keeps Apple's tunnel alive for as long as we hold it.
3. Discover the in-tunnel RSD port by reading ``net.inet.tcp.pcblist_n`` (no root) and finding
   ``remoted``'s own connection to that tunnel address.
4. Connect a normal TCP socket to ``[tunnelIPAddress]:rsd_port`` (the tunnel address is
   kernel-routable, so no root) and run the standard RSD handshake via
   :class:`~pymobiledevice3.remote.remote_service_discovery.RemoteServiceDiscoveryService`.

No root, no entitlement, no Xcode, and ``remoted`` is left running -- so unlike the kernel/bonjour
path this coexists with Xcode/``devicectl``. The whole XPC conversation goes through ``ctypes`` +
libxpc (no pyobjc). See ``docs/guides/network-stacks.md``.
"""

import asyncio
import atexit
import contextlib
import ctypes
import platform
import socket
import struct
import threading
from typing import Any, Callable, Optional

from pymobiledevice3.exceptions import UserspaceTunnelUnavailableError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

_IS_DARWIN = platform.system() == "Darwin"

REMOTEPAIRING_MACH_SERVICE = "com.apple.CoreDevice.remotepairingd"
REMOTED_PATH = "/usr/libexec/remoted"

# com.apple.dt.RemotePairingError code returned by InitiatePairingCommand when the host is already
# paired -- a benign no-op, not a failure.
_REMOTEPAIRING_ALREADY_PAIRED = 1002

# net.inet.tcp.pcblist_n item kinds (xgen_n.xgn_kind) and inp_vflag bit.
_XSO_SOCKET = 0x001
_XSO_INPCB = 0x010
_INP_IPV6 = 0x02

# Objective-C block flags.
_BLOCK_IS_GLOBAL = 1 << 28


class _BlockDescriptor(ctypes.Structure):
    _fields_ = [("reserved", ctypes.c_ulong), ("size", ctypes.c_ulong)]


class _ObjcBlock(ctypes.Structure):
    _fields_ = [
        ("isa", ctypes.c_void_p),
        ("flags", ctypes.c_int),
        ("reserved", ctypes.c_int),
        ("invoke", ctypes.c_void_p),
        ("descriptor", ctypes.c_void_p),
    ]


class _LibXpc:
    """Lazily-bound libxpc / libdispatch / libproc surface, plus an Objective-C global-block factory.

    Instantiated only on macOS (see :func:`_libxpc`). Every bound function is annotated with a
    concrete return type so call sites stay pyright-clean despite ctypes being dynamic.
    """

    def __init__(self) -> None:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        self._lib = lib
        vp = ctypes.c_void_p
        cp = ctypes.c_char_p

        self.dispatch_queue_create: Callable[..., int] = self._cfg("dispatch_queue_create", vp, [cp, vp])

        self.connection_create_mach_service: Callable[..., int] = self._cfg(
            "xpc_connection_create_mach_service", vp, [cp, vp, ctypes.c_uint64]
        )
        self.connection_create_from_endpoint: Callable[..., int] = self._cfg(
            "xpc_connection_create_from_endpoint", vp, [vp]
        )
        self.connection_set_event_handler: Callable[..., None] = self._cfg(
            "xpc_connection_set_event_handler", None, [vp, vp]
        )
        self.connection_activate: Callable[..., None] = self._cfg("xpc_connection_activate", None, [vp])
        self.connection_cancel: Callable[..., None] = self._cfg("xpc_connection_cancel", None, [vp])
        self.connection_send_message: Callable[..., None] = self._cfg("xpc_connection_send_message", None, [vp, vp])
        self.connection_send_message_with_reply: Callable[..., None] = self._cfg(
            "xpc_connection_send_message_with_reply", None, [vp, vp, vp, vp]
        )

        self.dictionary_create: Callable[..., int] = self._cfg("xpc_dictionary_create", vp, [vp, vp, ctypes.c_size_t])
        self.dictionary_set_string: Callable[..., None] = self._cfg("xpc_dictionary_set_string", None, [vp, cp, cp])
        self.dictionary_set_bool: Callable[..., None] = self._cfg(
            "xpc_dictionary_set_bool", None, [vp, cp, ctypes.c_bool]
        )
        self.dictionary_set_int64: Callable[..., None] = self._cfg(
            "xpc_dictionary_set_int64", None, [vp, cp, ctypes.c_int64]
        )
        self.dictionary_set_value: Callable[..., None] = self._cfg("xpc_dictionary_set_value", None, [vp, cp, vp])
        self.dictionary_get_value: Callable[..., int] = self._cfg("xpc_dictionary_get_value", vp, [vp, cp])
        self.dictionary_get_string: Callable[..., bytes] = self._cfg("xpc_dictionary_get_string", cp, [vp, cp])
        self.dictionary_get_int64: Callable[..., int] = self._cfg("xpc_dictionary_get_int64", ctypes.c_int64, [vp, cp])
        self.retain: Callable[..., int] = self._cfg("xpc_retain", vp, [vp])
        self.release: Callable[..., None] = self._cfg("xpc_release", None, [vp])
        self.copy_description: Callable[..., bytes] = self._cfg("xpc_copy_description", cp, [vp])

        self.proc_pidpath: Callable[..., int] = self._cfg(
            "proc_pidpath", ctypes.c_int, [ctypes.c_int, cp, ctypes.c_uint32]
        )
        self.sysctlbyname: Callable[..., int] = self._cfg(
            "sysctlbyname", ctypes.c_int, [cp, vp, ctypes.POINTER(ctypes.c_size_t), vp, ctypes.c_size_t]
        )

        # Address of the _NSConcreteGlobalBlock class object -> the block's isa pointer.
        self._global_block_isa = ctypes.addressof(ctypes.c_void_p.in_dll(lib, "_NSConcreteGlobalBlock"))
        self._block_keepalive: list[Any] = []

    def _cfg(self, name: str, restype: Any, argtypes: list[Any]) -> Any:
        fn = getattr(self._lib, name)
        fn.restype = restype
        fn.argtypes = argtypes
        return fn

    def make_block(self, func: Callable[[int], None]) -> ctypes.c_void_p:
        """Wrap ``func(xpc_object_ptr)`` in an Objective-C global block for an xpc handler.

        The block, its descriptor and the trampoline are retained for the process lifetime -- an
        xpc handler may fire on a libdispatch thread long after this returns, so they must never be
        collected.
        """
        invoke_t = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)

        def _invoke(_block: Optional[int], obj: Optional[int]) -> None:
            func(int(obj or 0))

        trampoline = invoke_t(_invoke)

        descriptor = _BlockDescriptor(0, ctypes.sizeof(_ObjcBlock))
        block = _ObjcBlock(
            ctypes.c_void_p(self._global_block_isa),
            _BLOCK_IS_GLOBAL,
            0,
            ctypes.cast(trampoline, ctypes.c_void_p),
            ctypes.cast(ctypes.byref(descriptor), ctypes.c_void_p),
        )
        self._block_keepalive.extend([trampoline, descriptor, block])
        return ctypes.cast(ctypes.byref(block), ctypes.c_void_p)


_libxpc_singleton: Optional[_LibXpc] = None


def _libxpc() -> _LibXpc:
    global _libxpc_singleton
    if not _IS_DARWIN:
        raise UserspaceTunnelUnavailableError("the native remoted tunnel is only available on macOS")
    if _libxpc_singleton is None:
        _libxpc_singleton = _LibXpc()
    return _libxpc_singleton


class _RemotePairingError(UserspaceTunnelUnavailableError):
    pass


class _RemotePairingSession:
    """Synchronous libxpc conversation with ``remotepairingd`` that owns the tunnel assertion.

    Blocking by design (waits on reply events); the async wrapper runs it in a worker thread. The
    browse/per-device XPC connections and the assertion must stay alive for the tunnel's lifetime,
    so this object is held open until :meth:`close`.
    """

    _REPLY_TIMEOUT = 10.0

    def __init__(self, xpc: _LibXpc) -> None:
        self._xpc = xpc
        self._queue = xpc.dispatch_queue_create(b"pymobiledevice3.native-remotepairing", None)
        self._browse_conn: Optional[int] = None
        self._device_conn: Optional[int] = None
        self._assertion_id: Optional[int] = None  # retained xpc uuid object
        self.tunnel_ip: Optional[str] = None

    def _request(self, conn: int, mangled_type_name: bytes, body_setup: Callable[[int], None]) -> int:
        """Send ``{mangledTypeName, value}`` and block for the reply. Returns the (retained) reply."""
        xpc = self._xpc
        body = xpc.dictionary_create(None, None, 0)
        body_setup(body)
        message = xpc.dictionary_create(None, None, 0)
        xpc.dictionary_set_string(message, b"mangledTypeName", mangled_type_name)
        xpc.dictionary_set_value(message, b"value", body)

        holder: list[int] = []
        done = threading.Event()

        def on_reply(reply: int) -> None:
            xpc.retain(reply)
            holder.append(reply)
            done.set()

        xpc.connection_send_message_with_reply(conn, message, self._queue, xpc.make_block(on_reply))
        if not done.wait(self._REPLY_TIMEOUT):
            raise _RemotePairingError(f"timed out waiting for reply to {mangled_type_name.decode()}")
        return holder[0]

    def browse(self, serial: Optional[str]) -> None:
        """Browse for ``serial`` (or the first device) and open its per-device XPC endpoint."""
        xpc = self._xpc
        want = serial.encode() if serial is not None else None
        endpoint_holder: list[int] = []
        found = threading.Event()

        def on_event(obj: int) -> None:
            if not obj:
                return
            value = xpc.dictionary_get_value(obj, b"value")
            if not value:
                return
            device_found = xpc.dictionary_get_value(value, b"deviceFound")
            if not device_found:
                return
            zero = xpc.dictionary_get_value(device_found, b"_0")
            info = xpc.dictionary_get_value(zero, b"deviceInfo") if zero else 0
            if not info:
                return
            udid = xpc.dictionary_get_string(info, b"udid")
            if want is not None and udid != want:
                return
            endpoint = xpc.dictionary_get_value(info, b"endpoint")
            if endpoint and not found.is_set():
                xpc.retain(endpoint)
                endpoint_holder.append(endpoint)
                found.set()

        conn = xpc.connection_create_mach_service(REMOTEPAIRING_MACH_SERVICE.encode(), self._queue, 0)
        self._browse_conn = conn
        xpc.connection_set_event_handler(conn, xpc.make_block(on_event))
        xpc.connection_activate(conn)

        def browse_body(body: int) -> None:
            xpc.dictionary_set_bool(body, b"currentDevicesOnly", False)

        # Mercury needs a reply channel or it silently drops the request; the device list itself
        # arrives asynchronously via on_event, so the reply is ignored.
        message = xpc.dictionary_create(None, None, 0)
        body = xpc.dictionary_create(None, None, 0)
        browse_body(body)
        xpc.dictionary_set_string(message, b"mangledTypeName", b"RemotePairing.BrowseRequest")
        xpc.dictionary_set_value(message, b"value", body)
        xpc.connection_send_message_with_reply(conn, message, self._queue, xpc.make_block(lambda _obj: None))

        if not found.wait(self._REPLY_TIMEOUT):
            hint = f" matching udid {serial}" if serial is not None else ""
            raise _RemotePairingError(f"remotepairingd reported no device{hint}")

        device_conn = xpc.connection_create_from_endpoint(endpoint_holder[0])
        self._device_conn = device_conn
        xpc.connection_set_event_handler(device_conn, xpc.make_block(lambda _obj: None))
        xpc.connection_activate(device_conn)

    def open_tunnel(self) -> str:
        """Ensure paired, create the tunnel assertion, and return the device tunnel IP address."""
        xpc = self._xpc
        assert self._device_conn is not None

        # Ensure paired. Already-paired comes back as a RemotePairingError (code 1002) -- benign.
        initiate = self._request(
            self._device_conn,
            b"RemotePairing.InitiatePairingCommand",
            lambda body: xpc.dictionary_set_bool(body, b"requireNonInteractive", False),
        )
        error = xpc.dictionary_get_value(initiate, b"error")
        if error:
            # Compare the numeric code, not the localized message: RemotePairingError code 1002 is
            # the benign "device is already paired" case, and NSLocalizedDescription is localized
            # (matching the English string would misfire on non-English macOS).
            code = xpc.dictionary_get_int64(error, b"code")
            if code != _REMOTEPAIRING_ALREADY_PAIRED:
                description = xpc.dictionary_get_value(error, b"userInfo")
                message = xpc.dictionary_get_string(description, b"NSLocalizedDescription") if description else b""
                raise _RemotePairingError(
                    f"pairing failed (code {code}): {(message or b'unknown error').decode(errors='replace')}"
                )
        xpc.release(initiate)

        assertion = self._request(
            self._device_conn,
            b"RemotePairing.CreateAssertionCommand",
            lambda body: xpc.dictionary_set_int64(body, b"flags", 0),
        )
        response = xpc.dictionary_get_value(assertion, b"response")
        if not response:
            raise _RemotePairingError(f"CreateAssertion had no response: {self._describe(assertion)}")
        assertion_id = xpc.dictionary_get_value(response, b"assertionIdentifier")
        if assertion_id:
            self._assertion_id = xpc.retain(assertion_id)
        info = xpc.dictionary_get_value(response, b"info")
        tunnel_ip = xpc.dictionary_get_string(info, b"tunnelIPAddress") if info else None
        xpc.release(assertion)
        if not tunnel_ip:
            raise _RemotePairingError("CreateAssertion returned no tunnelIPAddress")
        self.tunnel_ip = tunnel_ip.decode()
        return self.tunnel_ip

    def _describe(self, obj: int) -> str:
        raw = self._xpc.copy_description(obj)
        return raw.decode(errors="replace") if raw else "<no description>"

    def close(self) -> None:
        xpc = self._xpc
        if self._assertion_id is not None and self._device_conn is not None:
            with contextlib.suppress(Exception):
                release = self._request(
                    self._device_conn,
                    b"RemotePairing.ReleaseAssertionRequest",
                    lambda body, aid=self._assertion_id: xpc.dictionary_set_value(body, b"assertionIdentifier", aid),
                )
                xpc.release(release)
            xpc.release(self._assertion_id)
            self._assertion_id = None
        for conn in (self._device_conn, self._browse_conn):
            if conn is not None:
                with contextlib.suppress(Exception):
                    xpc.connection_cancel(conn)
        self._device_conn = None
        self._browse_conn = None


def parse_tcp_pcbs(data: bytes) -> list[tuple[int, int, bytes, int]]:
    """Parse ``net.inet.tcp.pcblist_n`` bytes into ``(effective_pid, version_flag, foreign_addr, foreign_port)``.

    The buffer is a sequence of ``{uint32 length; uint32 kind}`` records after a leading ``xinpgen``
    header (whose first uint32 is its own length); each connection contributes an ``XSO_SOCKET``
    record (carrying the owning pid) and an ``XSO_INPCB`` record (carrying the addresses/ports),
    terminated by a trailing ``xinpgen`` (length 24). Records are paired per connection regardless of
    their order within the block.
    """
    connections: list[tuple[int, int, bytes, int]] = []
    if len(data) < 4:
        return connections
    # Skip the leading xinpgen header (its first uint32 is xig_len).
    offset = int(struct.unpack_from("<I", data, 0)[0])
    pending_pid: Optional[int] = None
    pending: Optional[tuple[int, bytes, int]] = None  # (version_flag, foreign_addr, foreign_port)
    while offset + 8 <= len(data):
        header = struct.unpack_from("<II", data, offset)
        length, kind = int(header[0]), int(header[1])
        if length == 24:  # trailing xinpgen end marker (sizeof(struct xinpgen))
            break
        if length < 8 or offset + length > len(data):  # malformed/truncated: avoid a bad or endless walk
            break
        if kind == _XSO_SOCKET and offset + 72 <= len(data):
            pending_pid = int(struct.unpack_from("<i", data, offset + 68)[0])
        elif kind == _XSO_INPCB and offset + 64 <= len(data):
            foreign_port = int(struct.unpack_from(">H", data, offset + 16)[0])
            version_flag = data[offset + 44]
            foreign_addr = data[offset + 48 : offset + 48 + 16]
            pending = (version_flag, foreign_addr, foreign_port)
        if pending_pid is not None and pending is not None:
            version_flag, foreign_addr, foreign_port = pending
            connections.append((pending_pid, version_flag, foreign_addr, foreign_port))
            pending_pid = None
            pending = None
        step = length if length % 8 == 0 else length + (8 - length % 8)
        offset += step
    return connections


def _read_tcp_pcblist(xpc: _LibXpc) -> Optional[bytes]:
    """Read the ``net.inet.tcp.pcblist_n`` sysctl, tolerating growth between the sizing and data calls.

    The socket table can grow on a busy host in the window between the size query and the fetch, which
    makes the fetch fail with ENOMEM; over-allocate and retry a few times instead of giving up.
    """
    name = b"net.inet.tcp.pcblist_n"
    for _ in range(5):
        size = ctypes.c_size_t(0)
        if xpc.sysctlbyname(name, None, ctypes.byref(size), None, 0) != 0 or size.value == 0:
            return None
        capacity = size.value + 16384  # slack for connections opened since the sizing call
        buf = (ctypes.c_uint8 * capacity)()
        got = ctypes.c_size_t(capacity)
        if xpc.sysctlbyname(name, buf, ctypes.byref(got), None, 0) == 0:
            return bytes(buf[: got.value])
    return None


def find_rsd_port(xpc: _LibXpc, tunnel_ip: str) -> list[int]:
    """Return candidate in-tunnel RSD ports: ``remoted``'s TCP connections to ``tunnel_ip``.

    Reads ``net.inet.tcp.pcblist_n`` (available without root) rather than shelling out to netstat.
    """
    target = socket.inet_pton(socket.AF_INET6, tunnel_ip)
    data = _read_tcp_pcblist(xpc)
    if data is None:
        return []

    ports: list[int] = []
    for pid, version_flag, foreign_addr, foreign_port in parse_tcp_pcbs(data):
        if (version_flag & _INP_IPV6) and foreign_addr == target and _proc_path(xpc, pid) == REMOTED_PATH:
            ports.append(foreign_port)
    return ports


def _proc_path(xpc: _LibXpc, pid: int) -> str:
    buf = ctypes.create_string_buffer(4096)
    if xpc.proc_pidpath(pid, buf, 4096) <= 0:
        return ""
    return buf.value.decode(errors="replace")


class NativeRemotedTunnel:
    """A no-root macOS RSD obtained by piggybacking ``remoted``'s tunnel via ``remotepairingd``.

    Async context manager (closes automatically)::

        async with NativeRemotedTunnel(serial=udid) as rsd:
            ...  # rsd is a connected RemoteServiceDiscoveryService

    Or open/close explicitly with :meth:`aopen` / :meth:`aclose`. ``serial`` selects the device by
    UDID (``None`` -> the single device ``remotepairingd`` reports). The RSD address is
    kernel-routable (Apple's tunnel), so unlike the userspace tunnel it is reachable by other tools;
    the tunnel lives only while this handle (its assertion) is held open.
    """

    def __init__(self, serial: Optional[str] = None) -> None:
        self.serial = serial
        self.rsd: Optional[RemoteServiceDiscoveryService] = None
        self._session: Optional[_RemotePairingSession] = None

    async def aopen(self) -> RemoteServiceDiscoveryService:
        if self.rsd is not None:
            return self.rsd
        xpc = _libxpc()
        session = _RemotePairingSession(xpc)
        try:
            tunnel_ip, ports = await asyncio.to_thread(self._establish, xpc, session)
            if not ports:
                raise _RemotePairingError(f"could not find remoted's RSD connection to the tunnel address {tunnel_ip}")
            rsd = await self._connect_rsd(tunnel_ip, ports)
        except BaseException:
            await asyncio.to_thread(session.close)
            raise
        self._session = session
        self.rsd = rsd
        return rsd

    def _establish(self, xpc: _LibXpc, session: _RemotePairingSession) -> tuple[str, list[int]]:
        session.browse(self.serial)
        tunnel_ip = session.open_tunnel()
        return tunnel_ip, find_rsd_port(xpc, tunnel_ip)

    async def _connect_rsd(self, tunnel_ip: str, ports: list[int]) -> RemoteServiceDiscoveryService:
        last_error: Optional[Exception] = None
        for port in ports:
            rsd = RemoteServiceDiscoveryService((tunnel_ip, port))
            try:
                await rsd.connect()
            except Exception as e:  # try the next candidate port
                last_error = e
                await rsd.close()
            else:
                return rsd
        raise _RemotePairingError(
            f"failed to complete RSD handshake over the native tunnel [{tunnel_ip}]: {last_error!r}"
        )

    async def aclose(self) -> None:
        if self.rsd is not None:
            await self.rsd.close()
            self.rsd = None
        if self._session is not None:
            await asyncio.to_thread(self._session.close)
            self._session = None

    async def __aenter__(self) -> RemoteServiceDiscoveryService:
        return await self.aopen()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()


_cli_native_tunnel: Optional[NativeRemotedTunnel] = None
_cli_native_atexit_registered = False


async def establish_native_rsd(serial: Optional[str] = None) -> RemoteServiceDiscoveryService:
    """CLI convenience: open a native tunnel, keep it alive for the process, and return its RSD.

    Embedders should use :class:`NativeRemotedTunnel` directly — it is a closeable handle / async
    context manager. This wrapper exists for the CLI, which has no teardown hook: it stashes the
    tunnel for the process lifetime and releases the assertion at interpreter exit.

    Raises :class:`~pymobiledevice3.exceptions.UserspaceTunnelUnavailableError` when the native path
    is not usable (non-macOS, ``remotepairingd`` unavailable, or the device cannot be reached).
    """
    global _cli_native_tunnel, _cli_native_atexit_registered
    if (
        _cli_native_tunnel is not None
        and _cli_native_tunnel.rsd is not None
        and (serial is None or serial in (_cli_native_tunnel.serial, _cli_native_tunnel.rsd.udid))
    ):
        return _cli_native_tunnel.rsd
    # A stored tunnel for a different device: release its on-device assertion before replacing it.
    if _cli_native_tunnel is not None:
        stale, _cli_native_tunnel = _cli_native_tunnel, None
        await stale.aclose()
    tunnel = NativeRemotedTunnel(serial=serial)
    rsd = await tunnel.aopen()
    _cli_native_tunnel = tunnel
    if not _cli_native_atexit_registered:
        atexit.register(_close_cli_native_tunnel_at_exit)
        _cli_native_atexit_registered = True
    return rsd


def _close_cli_native_tunnel_at_exit() -> None:
    """Release the CLI's process-lifetime native tunnel (and its assertion) at interpreter exit."""
    global _cli_native_tunnel
    tunnel = _cli_native_tunnel
    if tunnel is None:
        return
    _cli_native_tunnel = None
    with contextlib.suppress(Exception):
        asyncio.run(tunnel.aclose())
