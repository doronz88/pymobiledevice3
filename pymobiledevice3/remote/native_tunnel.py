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
import logging
import os
import platform
import socket
import struct
import threading
import uuid
from typing import Any, Callable, Optional, cast

from pymobiledevice3.exceptions import DeviceNotFoundError, UserspaceTunnelUnavailableError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService, parse_device_kvs_data

logger = logging.getLogger(__name__)

_IS_DARWIN = platform.system() == "Darwin"

REMOTEPAIRING_MACH_SERVICE = "com.apple.CoreDevice.remotepairingd"
REMOTED_PATH = "/usr/libexec/remoted"

# ``remotepairingd`` is an XPCService declaring ``ServiceType = User``, so launchd registers it
# per-uid in a logged-in user's domain and never in the system/root domain: a process running as
# root (CI runner, LaunchDaemon, ``launchctl asuser 0``) gets "Connection invalid" from the plain
# lookup, not an empty device list. ``xpc_connection_set_target_uid`` redirects the lookup into
# another uid's domain, which lets such a process stay root and reach the login user's daemon
# selectively. Set this to choose that uid explicitly -- required on a host with no console user.
NATIVE_TARGET_UID_ENV_VAR = "PYMOBILEDEVICE3_NATIVE_TARGET_UID"

# Per-process memo of how to reach remotepairingd, resolved from what the daemon actually does
# rather than guessed from our own uid: ``None`` = not established yet, ``0`` = the ordinary lookup
# works (never retarget), a positive uid = search that uid's launchd domain.
_remotepairing_target_uid: Optional[int] = None

# com.apple.dt.RemotePairingError code returned by InitiatePairingCommand when the host is already
# paired -- a benign no-op, not a failure.
_REMOTEPAIRING_ALREADY_PAIRED = 1002

# net.inet.tcp.pcblist_n item kinds (xgen_n.xgn_kind) and inp_vflag bit.
_XSO_SOCKET = 0x001
_XSO_INPCB = 0x010
_INP_IPV6 = 0x02

# Objective-C block flags.
_BLOCK_IS_GLOBAL = 1 << 28

# RSD handshake retry budget (see NativeRemotedTunnel._connect_rsd): covers the device resetting
# the initial post-tunnel RSD connection while remoted redials onto a new port.
_RSD_CONNECT_ATTEMPTS = 5
_RSD_CONNECT_RETRY_DELAY = 0.5


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
        # SPI, absent from every SDK header, and the surface drifts across releases (the sibling
        # xpc_connection_set_target_gid is already gone), so bind it defensively.
        self.connection_set_target_uid: Optional[Callable[..., None]] = self._cfg_optional(
            "xpc_connection_set_target_uid", None, [vp, ctypes.c_uint32]
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
        self.dictionary_get_data: Callable[..., Optional[int]] = self._cfg(
            "xpc_dictionary_get_data", vp, [vp, cp, ctypes.POINTER(ctypes.c_size_t)]
        )
        self.retain: Callable[..., int] = self._cfg("xpc_retain", vp, [vp])
        self.release: Callable[..., None] = self._cfg("xpc_release", None, [vp])
        self.copy_description: Callable[..., bytes] = self._cfg("xpc_copy_description", cp, [vp])

        self.get_type: Callable[..., int] = self._cfg("xpc_get_type", vp, [vp])
        self.type_get_name: Callable[..., bytes] = self._cfg("xpc_type_get_name", cp, [vp])
        self.dictionary_apply: Callable[..., bool] = self._cfg("xpc_dictionary_apply", ctypes.c_bool, [vp, vp])
        self.array_apply: Callable[..., bool] = self._cfg("xpc_array_apply", ctypes.c_bool, [vp, vp])
        self.string_get_string_ptr: Callable[..., bytes] = self._cfg("xpc_string_get_string_ptr", cp, [vp])
        self.int64_get_value: Callable[..., int] = self._cfg("xpc_int64_get_value", ctypes.c_int64, [vp])
        self.uint64_get_value: Callable[..., int] = self._cfg("xpc_uint64_get_value", ctypes.c_uint64, [vp])
        self.double_get_value: Callable[..., float] = self._cfg("xpc_double_get_value", ctypes.c_double, [vp])
        self.bool_get_value: Callable[..., bool] = self._cfg("xpc_bool_get_value", ctypes.c_bool, [vp])
        self.date_get_value: Callable[..., int] = self._cfg("xpc_date_get_value", ctypes.c_int64, [vp])
        self.data_get_length: Callable[..., int] = self._cfg("xpc_data_get_length", ctypes.c_size_t, [vp])
        self.data_get_bytes: Callable[..., int] = self._cfg(
            "xpc_data_get_bytes", ctypes.c_size_t, [vp, vp, ctypes.c_size_t, ctypes.c_size_t]
        )
        self.uuid_get_bytes: Callable[..., int] = self._cfg("xpc_uuid_get_bytes", vp, [vp])

        self.proc_pidpath: Callable[..., int] = self._cfg(
            "proc_pidpath", ctypes.c_int, [ctypes.c_int, cp, ctypes.c_uint32]
        )
        self.sysctlbyname: Callable[..., int] = self._cfg(
            "sysctlbyname", ctypes.c_int, [cp, vp, ctypes.POINTER(ctypes.c_size_t), vp, ctypes.c_size_t]
        )

        # XPC_ERROR_CONNECTION_INVALID is `&_xpc_error_connection_invalid`: the symbol *is* the
        # error object, so the sentinel to compare against is its address, not its value.
        try:
            self.error_connection_invalid: int = ctypes.addressof(
                ctypes.c_void_p.in_dll(lib, "_xpc_error_connection_invalid")
            )
        except ValueError:
            self.error_connection_invalid = 0

        # Address of the _NSConcreteGlobalBlock class object -> the block's isa pointer.
        self._global_block_isa = ctypes.addressof(ctypes.c_void_p.in_dll(lib, "_NSConcreteGlobalBlock"))
        self._block_keepalive: list[Any] = []

    def _cfg(self, name: str, restype: Any, argtypes: list[Any]) -> Any:
        fn = getattr(self._lib, name)
        fn.restype = restype
        fn.argtypes = argtypes
        return fn

    def _cfg_optional(self, name: str, restype: Any, argtypes: list[Any]) -> Optional[Any]:
        """Bind a symbol that may not exist on every macOS release; ``None`` when it is absent."""
        try:
            return self._cfg(name, restype, argtypes)
        except AttributeError:
            return None

    def make_block(self, func: Callable[[int], None]) -> ctypes.c_void_p:
        """Wrap ``func(xpc_object_ptr)`` in an Objective-C global block for an xpc handler.

        The block, its descriptor and the trampoline are retained for the process lifetime -- an
        xpc handler may fire on a libdispatch thread long after this returns, so they must never be
        collected.
        """
        invoke_t = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)

        def _invoke(_block: Optional[int], obj: Optional[int]) -> None:
            func(int(obj or 0))

        return self._wrap_block(invoke_t(_invoke))

    def make_dictionary_apply_block(self, func: Callable[[bytes, int], bool]) -> ctypes.c_void_p:
        """Applier block for ``xpc_dictionary_apply``: ``func(key, xpc_object_ptr) -> keep_going``."""
        invoke_t = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p)

        def _invoke(_block: Optional[int], key: Optional[bytes], obj: Optional[int]) -> bool:
            return func(key or b"", int(obj or 0))

        return self._wrap_block(invoke_t(_invoke))

    def make_array_apply_block(self, func: Callable[[int, int], bool]) -> ctypes.c_void_p:
        """Applier block for ``xpc_array_apply``: ``func(index, xpc_object_ptr) -> keep_going``."""
        invoke_t = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)

        def _invoke(_block: Optional[int], index: int, obj: Optional[int]) -> bool:
            return func(index, int(obj or 0))

        return self._wrap_block(invoke_t(_invoke))

    def _wrap_block(self, trampoline: Any) -> ctypes.c_void_p:
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

    def get_data_bytes(self, dictionary: int, key: bytes) -> Optional[bytes]:
        """Copy the raw bytes of an xpc ``data`` value, or ``None`` if the key is absent/empty."""
        length = ctypes.c_size_t(0)
        ptr = self.dictionary_get_data(dictionary, key, ctypes.byref(length))
        if not ptr or length.value == 0:
            return None
        return ctypes.string_at(ptr, length.value)


_libxpc_singleton: Optional[_LibXpc] = None


def _libxpc() -> _LibXpc:
    global _libxpc_singleton
    if not _IS_DARWIN:
        raise UserspaceTunnelUnavailableError("the native remoted tunnel is only available on macOS")
    if _libxpc_singleton is None:
        _libxpc_singleton = _LibXpc()
    return _libxpc_singleton


def xpc_to_python(xpc: _LibXpc, obj: int) -> Any:
    """Best-effort conversion of a libxpc object into plain Python data.

    Types with no data representation (endpoints, connections, ...) become a ``"<type-name>"``
    placeholder so callers still see the key exists.
    """
    if not obj:
        return None
    type_name = (xpc.type_get_name(xpc.get_type(obj)) or b"?").decode(errors="replace")
    if type_name == "dictionary":
        result: dict[str, Any] = {}

        def on_entry(key: bytes, value: int) -> bool:
            result[key.decode(errors="replace")] = xpc_to_python(xpc, value)
            return True

        xpc.dictionary_apply(obj, xpc.make_dictionary_apply_block(on_entry))
        return result
    if type_name == "array":
        items: list[Any] = []

        def on_item(_index: int, value: int) -> bool:
            items.append(xpc_to_python(xpc, value))
            return True

        xpc.array_apply(obj, xpc.make_array_apply_block(on_item))
        return items
    if type_name == "string":
        raw = xpc.string_get_string_ptr(obj)
        return raw.decode(errors="replace") if raw else ""
    if type_name == "int64":
        return int(xpc.int64_get_value(obj))
    if type_name == "uint64":
        return int(xpc.uint64_get_value(obj))
    if type_name == "double":
        return float(xpc.double_get_value(obj))
    if type_name == "bool":
        return bool(xpc.bool_get_value(obj))
    if type_name == "date":
        return int(xpc.date_get_value(obj))  # nanoseconds since the epoch
    if type_name == "data":
        length = int(xpc.data_get_length(obj))
        if length == 0:
            return b""
        buf = (ctypes.c_uint8 * length)()
        got = int(xpc.data_get_bytes(obj, buf, 0, length))
        return bytes(buf[:got])
    if type_name == "uuid":
        ptr = xpc.uuid_get_bytes(obj)
        return str(uuid.UUID(bytes=ctypes.string_at(ptr, 16))) if ptr else None
    if type_name == "null":
        return None
    return f"<{type_name}>"


def _console_user_uid() -> Optional[int]:
    """uid of the console (window-server) user, or ``None`` when nobody is logged in.

    ``/dev/console`` is chowned to the console user at login and back to root at logout, so its
    owner is a dependency-free stand-in for ``SCDynamicStoreCopyConsoleUser``.
    """
    try:
        uid = os.stat("/dev/console").st_uid
    except OSError:
        return None
    return uid or None


def _is_root() -> bool:
    """Whether we are running with effective uid 0.

    ``os.geteuid`` is POSIX-only and absent on Windows, where importing this module is still legal
    even though its tunnel is macOS-only -- so probe for it rather than calling it blind.
    """
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _seeded_target_uid() -> Optional[int]:
    """Memoized target uid for this process, or ``None`` to use the ordinary lookup.

    Seeded once from ``PYMOBILEDEVICE3_NATIVE_TARGET_UID`` when set, which skips the ordinary
    attempt entirely -- what a daemon on a host with no console user wants, since it already knows
    which uid holds the pairing. ``=0`` pins the ordinary lookup and disables retargeting.
    """
    global _remotepairing_target_uid
    if _remotepairing_target_uid is not None:
        return _remotepairing_target_uid or None
    value = os.getenv(NATIVE_TARGET_UID_ENV_VAR)
    if not value:
        return None
    try:
        _remotepairing_target_uid = int(value.strip())
    except ValueError:
        logger.warning("ignoring invalid %s=%r (expected a numeric uid)", NATIVE_TARGET_UID_ENV_VAR, value)
        return None
    return _remotepairing_target_uid or None


def _remember_plain_lookup_works() -> None:
    """Memoize that the ordinary lookup reached the daemon, so later browses skip the retry dance."""
    global _remotepairing_target_uid
    if _remotepairing_target_uid is None:
        _remotepairing_target_uid = 0


def _resolve_target_uid_after_invalid(xpc: _LibXpc) -> Optional[int]:
    """uid to retry in after the ordinary lookup reported the service missing, or ``None``.

    Reached only once ``remotepairingd`` has actually told us it is not registered in our domain, so
    nothing here is guessed from our own uid. ``None`` means there is no second thing to try -- most
    importantly when we are not root, where the retarget SPI is both useless and fatal.
    """
    global _remotepairing_target_uid
    if not _is_root():
        return None
    if xpc.connection_set_target_uid is None:
        logger.warning(
            "%s is not registered in this domain and xpc_connection_set_target_uid is unavailable "
            "on this macOS, so another user's domain cannot be searched",
            REMOTEPAIRING_MACH_SERVICE,
        )
        return None
    uid = _console_user_uid()
    if uid is None:
        return None
    _remotepairing_target_uid = uid
    return uid


def _create_remotepairing_connection(xpc: _LibXpc, queue: int, target_uid: Optional[int]) -> int:
    """Create the ``remotepairingd`` mach-service connection, optionally aimed at another uid's domain.

    Returned inactive: the caller installs its event handler before activating.
    """
    conn = xpc.connection_create_mach_service(REMOTEPAIRING_MACH_SERVICE.encode(), queue, 0)
    if not target_uid:
        return conn
    if not _is_root():
        # xpc_connection_set_target_uid traps (SIGTRAP) when a non-root caller invokes it, so a
        # seeded uid must never be honoured unprivileged.
        logger.warning("ignoring %s: retargeting another uid's domain requires root", NATIVE_TARGET_UID_ENV_VAR)
        return conn
    if xpc.connection_set_target_uid is None:
        logger.warning(
            "ignoring %s: xpc_connection_set_target_uid is unavailable on this macOS", NATIVE_TARGET_UID_ENV_VAR
        )
        return conn
    xpc.connection_set_target_uid(conn, target_uid)  # must precede xpc_connection_activate
    logger.debug("searching uid %d's launchd domain for %s", target_uid, REMOTEPAIRING_MACH_SERVICE)
    return conn


class _BrowseAttempt:
    """One activated browse connection, tracking whether libxpc reported the service missing.

    ``XPC_ERROR_CONNECTION_INVALID`` on a freshly activated connection means the mach service is not
    registered in the domain we searched. Since ``remotepairingd`` is per-user, that is the signal
    -- observed, not guessed -- that we are looking in the wrong domain. It arrives essentially
    immediately (~0.2 ms), which is what makes trying the ordinary lookup first free. libxpc also
    delivers the same error after our own ``cancel``, so ``invalid`` is only meaningful before that.
    """

    def __init__(
        self,
        xpc: _LibXpc,
        queue: int,
        on_device: Callable[[int], None],
        target_uid: Optional[int],
        settled: Optional[threading.Event] = None,
    ) -> None:
        self._xpc = xpc
        self.invalid = threading.Event()
        self.conn = _create_remotepairing_connection(xpc, queue, target_uid)

        def handler(obj: int) -> None:
            if obj and obj == xpc.error_connection_invalid:
                self.invalid.set()
                if settled is not None:
                    settled.set()
                return
            on_device(obj)

        xpc.connection_set_event_handler(self.conn, xpc.make_block(handler))
        xpc.connection_activate(self.conn)
        _send_browse_request(xpc, self.conn, queue)

    def cancel(self) -> None:
        with contextlib.suppress(Exception):
            self._xpc.connection_cancel(self.conn)


def _send_browse_request(xpc: _LibXpc, conn: int, queue: int) -> None:
    """Send ``RemotePairing.BrowseRequest``; devices arrive via the connection's event handler.

    Mercury needs a reply channel or it silently drops the request; the reply itself is ignored.
    """
    message = xpc.dictionary_create(None, None, 0)
    body = xpc.dictionary_create(None, None, 0)
    xpc.dictionary_set_bool(body, b"currentDevicesOnly", False)
    xpc.dictionary_set_string(message, b"mangledTypeName", b"RemotePairing.BrowseRequest")
    xpc.dictionary_set_value(message, b"value", body)
    xpc.connection_send_message_with_reply(conn, message, queue, xpc.make_block(lambda _obj: None))


class _RemotePairingError(UserspaceTunnelUnavailableError):
    pass


class _RemotePairingDeviceNotFoundError(_RemotePairingError, DeviceNotFoundError):
    """``remotepairingd`` reported no matching device.

    Inherits :class:`~pymobiledevice3.exceptions.DeviceNotFoundError` so callers get the same
    exception type the usbmux/tunneld paths raise for a missing device, and ``_RemotePairingError``
    so the CLI's native -> userspace/tunneld routing keeps treating it as a native-path failure.
    """

    def __init__(self, udid: Optional[str], message: Optional[str] = None) -> None:
        DeviceNotFoundError.__init__(self, udid, message)


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
        # Device auxiliary metadata (decoded ``deviceKVSData``) captured from the browse ``deviceInfo``.
        # remotepairingd's merged KVS reliably carries domains like ``com.apple.WebInspector`` here.
        self.auxiliary_metadata: dict[str, dict[str, Any]] = {}

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
        """Browse for ``serial`` (or the first device) and open its per-device XPC endpoint.

        Tries the ordinary lookup first and only retargets another uid's domain if the daemon
        reports it is not registered here -- see :class:`_BrowseAttempt`.
        """
        xpc = self._xpc
        want = serial.encode() if serial is not None else None
        endpoint_holder: list[int] = []

        def make_on_device(settled: threading.Event) -> Callable[[int], None]:
            def on_device(obj: int) -> None:
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
                if endpoint and not settled.is_set():
                    self.auxiliary_metadata = parse_device_kvs_data(xpc.get_data_bytes(info, b"deviceKVSData"))
                    xpc.retain(endpoint)
                    endpoint_holder.append(endpoint)
                    settled.set()

            return on_device

        def attempt(target_uid: Optional[int]) -> _BrowseAttempt:
            settled = threading.Event()
            att = _BrowseAttempt(xpc, self._queue, make_on_device(settled), target_uid, settled)
            self._browse_conn = att.conn
            settled.wait(self._REPLY_TIMEOUT)
            return att

        seeded = _seeded_target_uid()
        att = attempt(seeded)
        if not endpoint_holder and att.invalid.is_set():
            retry_uid = _resolve_target_uid_after_invalid(xpc)
            if retry_uid is not None:
                att.cancel()
                attempt(retry_uid)
        elif endpoint_holder and not seeded:
            _remember_plain_lookup_works()

        if not endpoint_holder:
            hint = f" matching udid {serial}" if serial is not None else ""
            if _is_root() and _console_user_uid() is None and _seeded_target_uid() is None:
                hint += (
                    f"; running as root with no console user -- {REMOTEPAIRING_MACH_SERVICE} is registered "
                    f"per-user, so set {NATIVE_TARGET_UID_ENV_VAR} to the uid of the logged-in user "
                    "that owns the pairing"
                )
            raise _RemotePairingDeviceNotFoundError(
                serial, f"Device not found: remotepairingd reported no device{hint}"
            )

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


def _browse_native_devices_sync(xpc: _LibXpc, timeout: float) -> list[dict[str, Any]]:
    """Collect the ``deviceInfo`` of every device ``remotepairingd`` reports within ``timeout`` seconds."""
    queue = xpc.dispatch_queue_create(b"pymobiledevice3.native-browse", None)
    lock = threading.Lock()
    devices: list[dict[str, Any]] = []
    seen: set[str] = set()

    def on_event(obj: int) -> None:
        if not obj:
            return
        value = xpc.dictionary_get_value(obj, b"value")
        device_found = xpc.dictionary_get_value(value, b"deviceFound") if value else 0
        zero = xpc.dictionary_get_value(device_found, b"_0") if device_found else 0
        info = xpc.dictionary_get_value(zero, b"deviceInfo") if zero else 0
        if not info:
            return
        converted = xpc_to_python(xpc, info)
        if not isinstance(converted, dict):
            return
        info_dict = cast(dict[str, Any], converted)
        key = str(info_dict.get("udid", info_dict))
        with lock:
            if key not in seen:
                seen.add(key)
                devices.append(info_dict)

    def attempt(target_uid: Optional[int]) -> _BrowseAttempt:
        att = _BrowseAttempt(xpc, queue, on_event, target_uid)
        # deviceFound events stream in asynchronously, so collect for the whole window -- unless the
        # domain turns out to be wrong, which libxpc reports at once and ends the wait early.
        att.invalid.wait(timeout)
        return att

    seeded = _seeded_target_uid()
    att = attempt(seeded)
    if att.invalid.is_set():
        retry_uid = _resolve_target_uid_after_invalid(xpc)
        if retry_uid is not None:
            att.cancel()
            att = attempt(retry_uid)
    elif not seeded:
        _remember_plain_lookup_works()
    att.cancel()
    with lock:
        return list(devices)


async def browse_native_devices(timeout: float = 3.0) -> list[dict[str, Any]]:
    """List the devices Apple's ``remotepairingd`` reports (macOS only, no root).

    Each entry is the daemon's ``deviceInfo`` dictionary converted to plain Python data via
    :func:`xpc_to_python` (XPC endpoints render as ``"<endpoint>"`` placeholders).

    Raises :class:`~pymobiledevice3.exceptions.UserspaceTunnelUnavailableError` off macOS.
    """
    return await asyncio.to_thread(_browse_native_devices_sync, _libxpc(), timeout)


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
            tunnel_ip = await asyncio.to_thread(self._establish, session)
            rsd = await self._connect_rsd(xpc, tunnel_ip, session.auxiliary_metadata)
        except BaseException:
            await asyncio.to_thread(session.close)
            raise
        self._session = session
        self.rsd = rsd
        return rsd

    def _establish(self, session: _RemotePairingSession) -> str:
        session.browse(self.serial)
        return session.open_tunnel()

    async def _connect_rsd(
        self, xpc: _LibXpc, tunnel_ip: str, auxiliary_metadata: Optional[dict[str, dict[str, Any]]] = None
    ) -> RemoteServiceDiscoveryService:
        # Right after the tunnel comes up the device may reset the just-established RSD connection
        # ("Device must renegotiate TLS" in remoted's log) and remoted transparently redials -- onto
        # a NEW device port. Apple's own client treats that reset as routine, so retry here too, and
        # re-scan the pcblist on every attempt: a cached candidate list goes stale the moment
        # remoted redials (the scan may also simply run before remoted has connected at all).
        last_error: Optional[Exception] = None
        for attempt in range(_RSD_CONNECT_ATTEMPTS):
            if attempt:
                await asyncio.sleep(_RSD_CONNECT_RETRY_DELAY)
            for port in await asyncio.to_thread(find_rsd_port, xpc, tunnel_ip):
                rsd = RemoteServiceDiscoveryService((tunnel_ip, port), auxiliary_metadata=auxiliary_metadata)
                try:
                    await rsd.connect()
                except Exception as e:  # try the next candidate port
                    last_error = e
                    await rsd.close()
                else:
                    return rsd
        if last_error is None:
            raise _RemotePairingError(f"could not find remoted's RSD connection to the tunnel address {tunnel_ip}")
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
