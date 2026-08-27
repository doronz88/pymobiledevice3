import ctypes
import platform
import socket
import struct
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.exceptions import DeviceNotFoundError, UserspaceTunnelUnavailableError
from pymobiledevice3.remote import native_tunnel


def _pcblist_with_one_connection(pid: int, addr: bytes, port: int) -> bytes:
    """Build a synthetic ``net.inet.tcp.pcblist_n`` buffer with a single IPv6 TCP connection."""
    buf = bytearray()
    buf += struct.pack("<I", 24) + b"\x00" * 20  # leading xinpgen: first uint32 is its own length

    sock = bytearray(72)  # XSO_SOCKET record; effective_pid is an int32 at offset 68
    struct.pack_into("<II", sock, 0, 72, native_tunnel._XSO_SOCKET)
    struct.pack_into("<i", sock, 68, pid)
    buf += sock

    inpcb = bytearray(88)  # XSO_INPCB record: foreign_port@16 (BE), inp_vflag@44, foreign_addr@48
    struct.pack_into("<II", inpcb, 0, 88, native_tunnel._XSO_INPCB)
    struct.pack_into(">H", inpcb, 16, port)
    inpcb[44] = native_tunnel._INP_IPV6
    inpcb[48:64] = addr
    buf += inpcb

    buf += struct.pack("<II", 24, 0)  # trailing xinpgen (length 24) ends the walk
    return bytes(buf)


def test_parse_tcp_pcbs_pairs_socket_and_inpcb() -> None:
    addr = socket.inet_pton(socket.AF_INET6, "fd7b:7934:1752::1")
    connections = native_tunnel.parse_tcp_pcbs(_pcblist_with_one_connection(4321, addr, 50881))
    assert connections == [(4321, native_tunnel._INP_IPV6, addr, 50881)]


def test_parse_tcp_pcbs_ignores_malformed_or_empty() -> None:
    assert native_tunnel.parse_tcp_pcbs(b"") == []
    assert native_tunnel.parse_tcp_pcbs(struct.pack("<I", 9999)) == []  # header points past the end
    assert native_tunnel.parse_tcp_pcbs(struct.pack("<III", 8, 0, 0)) == []  # header==8, then length 0 -> stop


def test_parse_tcp_pcbs_stops_on_truncated_record() -> None:
    addr = socket.inet_pton(socket.AF_INET6, "fd7b:7934:1752::1")
    full = _pcblist_with_one_connection(4321, addr, 50881)
    # Replace the trailing xinpgen with a record claiming a huge length but no body: the parser must
    # keep the already-parsed connection and stop rather than read out of bounds.
    truncated = full[:-8] + struct.pack("<II", 4096, native_tunnel._XSO_INPCB)
    assert native_tunnel.parse_tcp_pcbs(truncated) == [(4321, native_tunnel._INP_IPV6, addr, 50881)]


@pytest.mark.skipif(platform.system() != "Darwin", reason="libxpc is macOS-only")
def test_xpc_to_python_converts_nested_objects() -> None:
    xpc = native_tunnel._libxpc()
    lib = xpc._lib
    vp = ctypes.c_void_p

    def bind(name: str, argtypes: list[Any]) -> Any:
        fn = getattr(lib, name)
        fn.restype = vp
        fn.argtypes = argtypes
        return fn

    string_create = bind("xpc_string_create", [ctypes.c_char_p])
    data_create = bind("xpc_data_create", [ctypes.c_char_p, ctypes.c_size_t])
    uuid_create = bind("xpc_uuid_create", [ctypes.c_char_p])
    fd_create = bind("xpc_fd_create", [ctypes.c_int])
    array_create = bind("xpc_array_create", [vp, ctypes.c_size_t])
    array_append = lib.xpc_array_append_value
    array_append.restype = None
    array_append.argtypes = [vp, vp]

    root = xpc.dictionary_create(None, None, 0)
    xpc.dictionary_set_string(root, b"udid", b"00008120-000000000000001E")
    xpc.dictionary_set_int64(root, b"answer", -42)
    xpc.dictionary_set_bool(root, b"paired", True)
    xpc.dictionary_set_value(root, b"blob", data_create(b"\x00\x01\x02", 3))
    xpc.dictionary_set_value(root, b"identifier", uuid_create(b"\x01" * 16))
    xpc.dictionary_set_value(root, b"endpoint", fd_create(0))  # no data representation -> placeholder

    array = array_create(None, 0)
    array_append(array, string_create(b"first"))
    array_append(array, string_create(b"second"))
    xpc.dictionary_set_value(root, b"names", array)

    nested = xpc.dictionary_create(None, None, 0)
    xpc.dictionary_set_string(nested, b"inner", b"value")
    xpc.dictionary_set_value(root, b"info", nested)

    assert native_tunnel.xpc_to_python(xpc, root) == {
        "udid": "00008120-000000000000001E",
        "answer": -42,
        "paired": True,
        "blob": b"\x00\x01\x02",
        "identifier": "01010101-0101-0101-0101-010101010101",
        "endpoint": "<fd>",
        "names": ["first", "second"],
        "info": {"inner": "value"},
    }


def test_xpc_to_python_null_pointer_is_none() -> None:
    if platform.system() != "Darwin":
        pytest.skip("libxpc is macOS-only")
    assert native_tunnel.xpc_to_python(native_tunnel._libxpc(), 0) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("scans", [[[51011], [51013]], [[], [51013]]])
async def test_aopen_retries_handshake_with_fresh_port_scan(
    monkeypatch: pytest.MonkeyPatch, scans: list[list[int]]
) -> None:
    """Right after tunnel establishment the device may reset the initial RSD connection ("Device
    must renegotiate TLS") and remoted transparently redials — onto a NEW device port. aopen must
    re-scan and retry instead of failing on the first RST (or on a scan that ran before remoted
    connected at all)."""
    scan_iter = iter(scans)
    scan_count = 0

    class FakeSession:
        def __init__(self, xpc: object) -> None:
            self.auxiliary_metadata: dict[str, dict[str, object]] = {}

        def browse(self, serial: Optional[str]) -> None:
            pass

        def open_tunnel(self) -> str:
            return "fdcd:5fb2:b94b::1"

        def close(self) -> None:
            pass

    class FakeRsd:
        def __init__(self, address: tuple[str, int], auxiliary_metadata: object = None) -> None:
            self.address = address
            self.auxiliary_metadata = auxiliary_metadata

        async def connect(self) -> None:
            if self.address[1] == 51011:
                raise ConnectionError("RST_STREAM error_code=5")

        async def close(self) -> None:
            pass

    def fake_find_rsd_port(xpc: object, tunnel_ip: str) -> list[int]:
        nonlocal scan_count
        scan_count += 1
        return next(scan_iter)

    monkeypatch.setattr(native_tunnel, "_libxpc", lambda: object())
    monkeypatch.setattr(native_tunnel, "_RemotePairingSession", FakeSession)
    monkeypatch.setattr(native_tunnel, "find_rsd_port", fake_find_rsd_port)
    monkeypatch.setattr(native_tunnel, "RemoteServiceDiscoveryService", FakeRsd)
    monkeypatch.setattr(native_tunnel, "_RSD_CONNECT_RETRY_DELAY", 0, raising=False)

    tunnel = native_tunnel.NativeRemotedTunnel()
    rsd = cast(Any, await tunnel.aopen())
    assert rsd.address == ("fdcd:5fb2:b94b::1", 51013)
    assert scan_count == 2
    await tunnel.aclose()


def test_browse_missing_device_raises_device_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """A device remotepairingd does not report must surface as DeviceNotFoundError -- the same type
    the usbmux/tunneld paths raise -- while staying a native-path (UserspaceTunnelUnavailable)
    failure so the CLI's transport routing keeps falling back."""
    import threading

    class FakeAttempt:
        def __init__(self, xpc: object, queue: object, on_device: object, target_uid: object, settled: Any) -> None:
            self.conn = 0
            self.invalid = threading.Event()
            settled.set()  # nothing matched; settle instead of blocking on the reply timeout

        def cancel(self) -> None:
            pass

    monkeypatch.setattr(native_tunnel, "_BrowseAttempt", FakeAttempt)
    monkeypatch.setattr(native_tunnel, "_seeded_target_uid", lambda: None)
    monkeypatch.setattr(native_tunnel, "_is_root", lambda: False)

    session = cast(Any, native_tunnel._RemotePairingSession.__new__(native_tunnel._RemotePairingSession))
    session._xpc = object()
    session._queue = 0

    with pytest.raises(DeviceNotFoundError) as exc_info:
        session.browse("BOGUS-UDID")
    assert exc_info.value.udid == "BOGUS-UDID"
    assert isinstance(exc_info.value, UserspaceTunnelUnavailableError)
    assert "BOGUS-UDID" in str(exc_info.value) and "remotepairingd" in str(exc_info.value)


def test_libxpc_requires_darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_tunnel, "_IS_DARWIN", False)
    monkeypatch.setattr(native_tunnel, "_libxpc_singleton", None)
    with pytest.raises(UserspaceTunnelUnavailableError):
        native_tunnel._libxpc()


# --- required-RSD transport selection / fallback routing (pymobiledevice3.cli.cli_common) ---


class _Ctx:
    def fail(self, message: str) -> None:
        raise _CtxFail(message)


class _CtxFail(Exception):
    pass


def _route(
    monkeypatch: pytest.MonkeyPatch,
    *,
    system: str,
    default_fallback: Optional[str] = None,
    userspace_exc: Optional[BaseException] = None,
    native_exc: Optional[BaseException] = None,
    native_flag: bool = False,
    allow_none: bool = False,
    force_tunnel: bool = False,
) -> tuple[object, list[str]]:
    """Drive the RSD dependency with the three establishers stubbed; return (result, calls)."""
    from pymobiledevice3.cli import cli_common
    from pymobiledevice3.remote import native_tunnel as nt
    from pymobiledevice3.remote import userspace_tunnel as ut

    calls: list[str] = []
    monkeypatch.setattr(cli_common.platform, "system", lambda: system)
    monkeypatch.setattr(cli_common, "is_invoked_for_completion", lambda: False)
    monkeypatch.setattr(cli_common, "_cli_udid", lambda: None)
    monkeypatch.setattr(cli_common, "_resolve_target_serial", lambda serial: "UDID")
    if default_fallback is not None:
        monkeypatch.setenv("PYMOBILEDEVICE3_DEFAULT_FALLBACK", default_fallback)
    else:
        monkeypatch.delenv("PYMOBILEDEVICE3_DEFAULT_FALLBACK", raising=False)
    if force_tunnel:
        monkeypatch.setenv("PYMOBILEDEVICE3_FORCE_TUNNEL", "1")
    else:
        monkeypatch.delenv("PYMOBILEDEVICE3_FORCE_TUNNEL", raising=False)

    async def fake_tunneld(udid: object = None) -> str:
        calls.append("tunneld")
        return "TUNNELD"

    async def fake_userspace(*args: object, **kwargs: object) -> str:
        calls.append("userspace")
        if userspace_exc is not None:
            raise userspace_exc
        return "USERSPACE"

    async def fake_native(*args: object, **kwargs: object) -> str:
        calls.append("native")
        if native_exc is not None:
            raise native_exc
        return "NATIVE"

    monkeypatch.setattr(cli_common, "_tunneld", fake_tunneld)
    monkeypatch.setattr(ut, "establish_userspace_rsd", fake_userspace)
    monkeypatch.setattr(nt, "establish_native_rsd", fake_native)

    dependency = cli_common.make_rsd_dependency(allow_none=allow_none)
    result = dependency(_Ctx(), rsd=None, tunnel=None, userspace=False, native=native_flag)
    return result, calls


def test_macos_default_uses_native_first(monkeypatch: pytest.MonkeyPatch) -> None:
    # On macOS the built-in default prefers the native tunnel (no DEFAULT_FALLBACK set).
    result, calls = _route(monkeypatch, system="Darwin")
    assert result == "NATIVE"
    assert calls == ["native"]  # userspace/tunneld never attempted


def test_macos_default_falls_through_native_userspace_tunneld(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = _route(
        monkeypatch,
        system="Darwin",
        native_exc=UserspaceTunnelUnavailableError("no remotepairingd"),
        userspace_exc=UserspaceTunnelUnavailableError("no 17.4"),
    )
    assert result == "TUNNELD"
    assert calls == ["native", "userspace", "tunneld"]


def test_non_macos_default_uses_userspace(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = _route(monkeypatch, system="Linux")
    assert result == "USERSPACE"
    assert calls == ["userspace"]  # native only exists on macOS


def test_non_macos_falls_back_to_tunneld(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = _route(monkeypatch, system="Linux", userspace_exc=UserspaceTunnelUnavailableError("no 17.4"))
    assert result == "TUNNELD"
    assert "native" not in calls  # remoted only exists on macOS


def test_explicit_native_flag_forces_native(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = _route(monkeypatch, system="Linux", native_flag=True)
    assert result == "NATIVE"
    assert calls == ["native"]  # explicit --native bypasses userspace/tunneld selection


def test_transport_flags_are_mutually_exclusive() -> None:
    from pymobiledevice3.cli import cli_common

    dependency = cli_common.make_rsd_dependency(allow_none=False)
    with pytest.raises(_CtxFail):
        dependency(_Ctx(), rsd=None, tunnel=None, userspace=True, native=True)


def test_default_fallback_native_is_tried_first(monkeypatch: pytest.MonkeyPatch) -> None:
    # PYMOBILEDEVICE3_DEFAULT_FALLBACK=native: native is preferred over userspace on macOS.
    result, calls = _route(monkeypatch, system="Darwin", default_fallback="native")
    assert result == "NATIVE"
    assert calls == ["native"]  # userspace never attempted


def test_default_fallback_native_falls_through_when_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = _route(
        monkeypatch,
        system="Darwin",
        default_fallback="native",
        native_exc=UserspaceTunnelUnavailableError("no remotepairingd"),
    )
    assert result == "USERSPACE"
    assert calls == ["native", "userspace"]  # native tried first, then userspace; native not retried


def test_default_fallback_native_on_non_macos_uses_userspace(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = _route(monkeypatch, system="Linux", default_fallback="native")
    assert result == "USERSPACE"
    assert "native" not in calls  # native preference is a no-op off macOS


def test_default_fallback_tunneld_skips_no_root_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = _route(monkeypatch, system="Darwin", default_fallback="tunneld")
    assert result == "TUNNELD"
    assert calls == ["tunneld"]


def test_default_fallback_userspace_forces_userspace_on_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    # Opt back out of the macOS native default without going all the way to tunneld.
    result, calls = _route(monkeypatch, system="Darwin", default_fallback="userspace")
    assert result == "USERSPACE"
    assert calls == ["userspace"]


def test_force_tunnel_marker_establishes_chain_for_lockdown_command(monkeypatch: pytest.MonkeyPatch) -> None:
    # allow_none=True commands normally return None (use lockdown); the __main__ retry sets
    # FORCE_TUNNEL to make them establish the default chain instead.
    none_result, none_calls = _route(monkeypatch, system="Darwin", allow_none=True)
    assert none_result is None
    assert none_calls == []  # no tunnel attempted without the marker

    result, calls = _route(monkeypatch, system="Darwin", allow_none=True, force_tunnel=True)
    assert result == "NATIVE"
    assert calls == ["native"]  # marker -> full chain, macOS default is native


def test_default_transport_preference_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from pymobiledevice3.cli import cli_common

    monkeypatch.delenv("PYMOBILEDEVICE3_DEFAULT_FALLBACK", raising=False)
    monkeypatch.setattr(cli_common.platform, "system", lambda: "Darwin")
    assert cli_common.default_transport_preference() == "native"  # built-in default on macOS
    monkeypatch.setattr(cli_common.platform, "system", lambda: "Linux")
    assert cli_common.default_transport_preference() == "userspace"  # built-in default elsewhere

    monkeypatch.setenv("PYMOBILEDEVICE3_DEFAULT_FALLBACK", "NATIVE")  # case-insensitive
    assert cli_common.default_transport_preference() == "native"

    monkeypatch.setenv("PYMOBILEDEVICE3_DEFAULT_FALLBACK", "tunneld")
    assert cli_common.default_transport_preference() == "tunneld"

    monkeypatch.setenv("PYMOBILEDEVICE3_DEFAULT_FALLBACK", "bogus")  # invalid -> built-in default (Linux here)
    assert cli_common.default_transport_preference() == "userspace"


class _FakeXpcForTargeting:
    """Minimal ``_LibXpc`` stand-in recording the retargeting calls made before activation."""

    def __init__(self, has_spi: bool = True) -> None:
        self.calls: list[tuple[int, int]] = []
        self.connection_set_target_uid: Optional[Any] = self._record if has_spi else None

    def _record(self, conn: int, uid: int) -> None:
        self.calls.append((conn, uid))

    def connection_create_mach_service(self, name: bytes, queue: Optional[int], flags: int) -> int:
        return 0xC0FFEE


@pytest.fixture(autouse=True)
def _reset_target_uid_memo(monkeypatch: pytest.MonkeyPatch) -> None:
    """The resolved domain is memoized per process; keep it from leaking between tests."""
    monkeypatch.setattr(native_tunnel, "_remotepairing_target_uid", None, raising=False)
    monkeypatch.delenv(native_tunnel.NATIVE_TARGET_UID_ENV_VAR, raising=False)


def test_seeded_target_uid_is_none_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # No env and nothing established yet: the ordinary lookup is tried first, unaimed.
    assert native_tunnel._seeded_target_uid() is None


def test_seeded_target_uid_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(native_tunnel.NATIVE_TARGET_UID_ENV_VAR, " 502 ")
    assert native_tunnel._seeded_target_uid() == 502


def test_seeded_target_uid_zero_pins_the_ordinary_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(native_tunnel.NATIVE_TARGET_UID_ENV_VAR, "0")
    assert native_tunnel._seeded_target_uid() is None
    assert native_tunnel._remotepairing_target_uid == 0  # memoized, so retargeting stays disabled


def test_seeded_target_uid_ignores_invalid_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(native_tunnel.NATIVE_TARGET_UID_ENV_VAR, "not-a-uid")
    assert native_tunnel._seeded_target_uid() is None


def test_remember_plain_lookup_works_memoizes(monkeypatch: pytest.MonkeyPatch) -> None:
    native_tunnel._remember_plain_lookup_works()
    assert native_tunnel._remotepairing_target_uid == 0
    assert native_tunnel._seeded_target_uid() is None


def test_resolve_after_invalid_is_none_when_unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    # Not root: there is no second thing to try, and the SPI would trap.
    monkeypatch.setattr(native_tunnel.os, "geteuid", lambda: 501, raising=False)
    monkeypatch.setattr(native_tunnel, "_console_user_uid", lambda: 501)
    assert native_tunnel._resolve_target_uid_after_invalid(cast(Any, _FakeXpcForTargeting())) is None


def test_resolve_after_invalid_returns_console_user_and_memoizes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_tunnel.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(native_tunnel, "_console_user_uid", lambda: 501)
    assert native_tunnel._resolve_target_uid_after_invalid(cast(Any, _FakeXpcForTargeting())) == 501
    assert native_tunnel._remotepairing_target_uid == 501
    assert native_tunnel._seeded_target_uid() == 501  # later browses go straight to that domain


def test_resolve_after_invalid_none_without_console_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_tunnel.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(native_tunnel, "_console_user_uid", lambda: None)
    assert native_tunnel._resolve_target_uid_after_invalid(cast(Any, _FakeXpcForTargeting())) is None


def test_resolve_after_invalid_none_when_spi_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    # A future macOS could drop the SPI the way xpc_connection_set_target_gid was dropped.
    monkeypatch.setattr(native_tunnel.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(native_tunnel, "_console_user_uid", lambda: 501)
    xpc = _FakeXpcForTargeting(has_spi=False)
    assert native_tunnel._resolve_target_uid_after_invalid(cast(Any, xpc)) is None


def test_console_user_uid_reads_dev_console_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    real_stat = native_tunnel.os.stat

    def fake_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if path == "/dev/console":
            return real_stat("/dev/console" if platform.system() == "Darwin" else ".")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(native_tunnel.os, "stat", fake_stat)
    uid = native_tunnel._console_user_uid()
    assert uid is None or uid > 0  # root-owned (logged out) reports None rather than uid 0


def test_create_connection_retargets_when_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_tunnel.os, "geteuid", lambda: 0, raising=False)
    xpc = _FakeXpcForTargeting()
    assert native_tunnel._create_remotepairing_connection(cast(Any, xpc), 0, 501) == 0xC0FFEE
    assert xpc.calls == [(0xC0FFEE, 501)]


def test_create_connection_without_target_is_a_plain_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_tunnel.os, "geteuid", lambda: 0, raising=False)
    xpc = _FakeXpcForTargeting()
    native_tunnel._create_remotepairing_connection(cast(Any, xpc), 0, None)
    assert xpc.calls == []


def test_create_connection_never_retargets_unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    # Honouring a seeded uid without root would trap the process (SIGTRAP), so it must be refused.
    monkeypatch.setattr(native_tunnel.os, "geteuid", lambda: 501, raising=False)
    xpc = _FakeXpcForTargeting()
    native_tunnel._create_remotepairing_connection(cast(Any, xpc), 0, 501)
    assert xpc.calls == []


def test_create_connection_survives_missing_spi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_tunnel.os, "geteuid", lambda: 0, raising=False)
    xpc = _FakeXpcForTargeting(has_spi=False)
    assert native_tunnel._create_remotepairing_connection(cast(Any, xpc), 0, 501) == 0xC0FFEE
