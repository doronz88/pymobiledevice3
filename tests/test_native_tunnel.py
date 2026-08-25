import socket
import struct
from typing import Optional

import pytest

from pymobiledevice3.exceptions import UserspaceTunnelUnavailableError
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
