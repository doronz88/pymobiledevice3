import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import typer

from pymobiledevice3.cli import remote
from pymobiledevice3.exceptions import NoDeviceConnectedError, NotPairedError, RemotePairingCompletedError
from pymobiledevice3.remote import native_tunnel
from pymobiledevice3.remote.common import ConnectionType, TunnelProtocol


@pytest.mark.asyncio
async def test_start_tunnel_task_retries_empty_discovery(monkeypatch):
    service = object()
    discoveries = iter(([], [service]))
    tunnel_services_calls = 0
    tunnel_task_service = None

    async def get_tunnel_services(udid=None):
        nonlocal tunnel_services_calls
        tunnel_services_calls += 1
        return next(discoveries)

    async def tunnel_task(selected_service, **kwargs):
        nonlocal tunnel_task_service
        tunnel_task_service = selected_service

    monkeypatch.setattr(remote, "get_core_device_tunnel_services", get_tunnel_services)
    monkeypatch.setattr(remote, "tunnel_task", tunnel_task)

    await remote.start_tunnel_task(ConnectionType.USB, secrets=None)

    assert tunnel_services_calls == 2
    assert tunnel_task_service is service


@pytest.mark.asyncio
async def test_start_tunnel_task_raises_after_discovery_retries(monkeypatch):
    tunnel_services_calls = 0

    async def get_tunnel_services(udid=None):
        nonlocal tunnel_services_calls
        tunnel_services_calls += 1
        return []

    monkeypatch.setattr(remote, "get_core_device_tunnel_services", get_tunnel_services)

    with pytest.raises(NoDeviceConnectedError):
        await remote.start_tunnel_task(ConnectionType.USB, secrets=None)

    assert tunnel_services_calls == remote.TUNNEL_SERVICE_DISCOVERY_ATTEMPTS


@pytest.mark.parametrize(
    "kwargs",
    [
        {"connection_type": ConnectionType.WIFI},
        {"secrets": Path("secrets.txt")},
        {"protocol": TunnelProtocol.QUIC},
        {"max_idle_timeout": 99.0},
    ],
)
def test_cli_start_tunnel_native_rejects_incompatible_options(kwargs):
    with pytest.raises(typer.BadParameter):
        remote.cli_start_tunnel(native=True, **kwargs)


def test_cli_start_tunnel_native_skips_sudo_check(monkeypatch):
    # --native must not require root: the native task is reached without the admin gate.
    called_with = None

    async def fake_native_tunnel_task(udid=None, script_mode=False):
        nonlocal called_with
        called_with = (udid, script_mode)

    monkeypatch.setattr(remote, "native_tunnel_task", fake_native_tunnel_task)
    monkeypatch.setattr(type(remote.OSUTILS), "is_admin", property(lambda self: False))

    remote.cli_start_tunnel(native=True, udid="UDID", script_mode=True)

    assert called_with == ("UDID", True)


def test_cli_start_tunnel_defaults_to_native_on_macos(monkeypatch):
    # No --native/--no-native given: the macOS transport preference routes to the native task,
    # with no root required.
    called = False

    async def fake_native_tunnel_task(udid=None, script_mode=False):
        nonlocal called
        called = True

    monkeypatch.setattr(remote, "native_tunnel_task", fake_native_tunnel_task)
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "native")
    monkeypatch.setattr(type(remote.OSUTILS), "is_admin", property(lambda self: False))

    remote.cli_start_tunnel()

    assert called


@pytest.mark.parametrize(
    "kwargs",
    [
        {"native": False},  # explicit opt-out
        {"connection_type": ConnectionType.WIFI},  # classic-tunnel option implies the classic path
        {"secrets": Path("secrets.txt")},
        {"protocol": TunnelProtocol.QUIC},
        {"max_idle_timeout": 99.0},
    ],
)
def test_cli_start_tunnel_auto_native_yields_to_classic_path(monkeypatch, kwargs):
    # Under the auto default, --no-native or any classic-tunnel option must route to the classic
    # (root) tunnel instead of erroring: hitting the sudo gate proves the classic path was taken.
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "native")
    monkeypatch.setattr(type(remote.OSUTILS), "is_admin", property(lambda self: False))

    from pymobiledevice3.exceptions import AccessDeniedError

    with pytest.raises(AccessDeniedError):
        remote.cli_start_tunnel(**kwargs)


def test_cli_start_tunnel_non_native_preference_uses_classic_path(monkeypatch):
    # Off macOS (or with PYMOBILEDEVICE3_DEFAULT_FALLBACK opting out) the default stays classic.
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "userspace")
    monkeypatch.setattr(type(remote.OSUTILS), "is_admin", property(lambda self: False))

    from pymobiledevice3.exceptions import AccessDeniedError

    with pytest.raises(AccessDeniedError):
        remote.cli_start_tunnel()


def test_cli_start_tunnel_auto_reroute_to_classic_is_logged(monkeypatch, caplog):
    # When a classic-tunnel option diverts the macOS native default to the root path, say so (and
    # name the option) instead of dying with a bare "requires root" error.
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "native")
    monkeypatch.setattr(type(remote.OSUTILS), "is_admin", property(lambda self: False))

    from pymobiledevice3.exceptions import AccessDeniedError

    with caplog.at_level("INFO", logger=remote.logger.name), pytest.raises(AccessDeniedError):
        remote.cli_start_tunnel(secrets=Path("secrets.txt"))

    assert any("--secrets" in r.message and "classic tunnel" in r.message for r in caplog.records)


def test_cli_start_tunnel_native_default_does_not_log_reroute(monkeypatch, caplog):
    # No classic option: the native default is taken silently, with no spurious reroute notice.
    async def fake_native_tunnel_task(udid=None, script_mode=False):
        pass

    monkeypatch.setattr(remote, "native_tunnel_task", fake_native_tunnel_task)
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "native")

    with caplog.at_level("INFO", logger=remote.logger.name):
        remote.cli_start_tunnel()

    assert not any("classic tunnel" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_native_tunnel_task_prints_rsd_and_holds(monkeypatch, capsys):
    class FakeService:
        address = ("fdf4:cb47:dd51::1", 61234)

    class FakeRsd:
        udid = "UDID"
        service = FakeService()

    async def fake_establish_native_rsd(serial=None):
        return FakeRsd()

    monkeypatch.setattr(native_tunnel, "establish_native_rsd", fake_establish_native_rsd)
    monkeypatch.setattr(remote, "user_requested_colored_output", lambda: False)

    # The task prints the RSD endpoint and then holds the assertion forever (until Ctrl-C).
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(remote.native_tunnel_task("UDID", script_mode=True), timeout=0.1)
    assert capsys.readouterr().out == "fdf4:cb47:dd51::1 61234\n"

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(remote.native_tunnel_task("UDID"), timeout=0.1)
    out = capsys.readouterr().out
    assert "RSD Address: fdf4:cb47:dd51::1" in out
    assert "RSD Port: 61234" in out
    assert "--rsd fdf4:cb47:dd51::1 61234" in out


def test_cli_browse_native_uses_remotepairingd(monkeypatch):
    browsed_timeout = None

    async def fake_browse_native_devices(timeout):
        nonlocal browsed_timeout
        browsed_timeout = timeout
        return [{"udid": "UDID"}]

    printed = []
    monkeypatch.setattr(native_tunnel, "browse_native_devices", fake_browse_native_devices)
    monkeypatch.setattr(remote, "print_json", printed.append)

    remote.browse(timeout=1.5, native=True)

    assert browsed_timeout == 1.5
    assert printed == [[{"udid": "UDID"}]]


def test_cli_browse_defaults_to_remotepairingd_on_macos(monkeypatch):
    # No --native/--no-native: macOS browses remotepairingd whichever tunnel transport is preferred
    # (browsing opens no RSD connection on remoted's tunnel), unless tunneld opts out of remoted
    # entirely; elsewhere bonjour. --no-native forces bonjour.
    calls = []

    async def fake_browse_native_devices(timeout):
        calls.append("native")
        return []

    async def fake_cli_browse(timeout):
        calls.append("bonjour")

    monkeypatch.setattr(native_tunnel, "browse_native_devices", fake_browse_native_devices)
    monkeypatch.setattr(remote, "cli_browse", fake_cli_browse)
    monkeypatch.setattr(remote, "print_json", lambda obj: None)

    monkeypatch.setattr(remote.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "userspace")
    remote.browse()
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "tunneld")
    remote.browse()
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "userspace")
    remote.browse(native=False)
    monkeypatch.setattr(remote.platform, "system", lambda: "Linux")
    remote.browse()

    assert calls == ["native", "bonjour", "bonjour", "bonjour"]


@pytest.mark.asyncio
async def test_pair_reports_completion_instead_of_raising(monkeypatch, caplog):
    class _PairedService:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return None

        async def open_stream(self):
            return None

        async def connect(self, autopair=True):
            # what RemotePairingProtocol.connect() raises once the pair record is saved
            raise RemotePairingCompletedError()

    async def browse():
        return [
            SimpleNamespace(
                properties={"name": "Vision Pro", "identifier": "IDENTIFIER"},
                addresses=[SimpleNamespace(full_ip="fe80::1%en0")],
                port=49152,
            )
        ]

    monkeypatch.setattr(remote, "start_tunnel", object())
    monkeypatch.setattr(remote, "browse_remotepairing_manual_pairing", browse)
    monkeypatch.setattr(remote, "prompt_device_list", lambda devices: devices[0])
    monkeypatch.setattr(remote, "RemotePairingManualPairingService", lambda *args: _PairedService())

    # `cli_pair` is the sync wrapper Typer registers; `__wrapped__` is the coroutine underneath.
    with caplog.at_level(logging.INFO, logger=remote.logger.name):
        await cast(Any, remote.cli_pair).__wrapped__(name=None, udid=None)

    assert "Pairing completed" in caplog.text


_TV_ID = "0E5E5D3E-F712-48A3-97FB-C8C962299C8E"


def _manual_pairing_answer(name: str, identifier: str, *ips: str) -> SimpleNamespace:
    return SimpleNamespace(
        properties={"name": name, "identifier": identifier},
        addresses=[SimpleNamespace(full_ip=ip) for ip in ips],
        port=58884,
    )


def _install_pair_fakes(monkeypatch, answers, unreachable=()):
    """Fake browse and pairing service; returns the (identifier, address) of every open attempt."""
    attempts: list[tuple[str, str]] = []

    class _Service:
        def __init__(self, identifier, hostname, port):
            self.identifier, self.hostname = identifier, hostname

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return None

        async def open_stream(self):
            attempts.append((self.identifier, self.hostname))
            if self.hostname in unreachable:
                raise OSError("unreachable")

        async def connect(self, autopair=True):
            raise RemotePairingCompletedError()

    async def browse():
        return answers

    def no_prompt(devices):
        raise AssertionError(f"prompted for {devices}")

    monkeypatch.setattr(remote, "start_tunnel", object())
    monkeypatch.setattr(remote, "browse_remotepairing_manual_pairing", browse)
    monkeypatch.setattr(remote, "prompt_device_list", no_prompt)
    monkeypatch.setattr(remote, "RemotePairingManualPairingService", _Service)
    return attempts


@pytest.mark.asyncio
async def test_pair_groups_addresses_of_one_device_without_prompt(monkeypatch):
    # An Apple TV answers once per address (IPv6 link-local and IPv4) under one identifier.
    answers = [_manual_pairing_answer("Main Bedroom", _TV_ID, "fe80::f6:d18e:bab1:6093%en0", "192.168.0.138")]
    attempts = _install_pair_fakes(monkeypatch, answers)

    await cast(Any, remote.cli_pair).__wrapped__(name=None, udid=None)

    # one candidate, so no prompt; the routable IPv4 address is tried first
    assert attempts == [(_TV_ID, "192.168.0.138")]


@pytest.mark.asyncio
async def test_pair_falls_back_to_next_address_when_unreachable(monkeypatch):
    answers = [_manual_pairing_answer("Main Bedroom", _TV_ID, "fe80::1%en0", "192.168.0.138")]
    attempts = _install_pair_fakes(monkeypatch, answers, unreachable={"192.168.0.138"})

    await cast(Any, remote.cli_pair).__wrapped__(name=None, udid=None)

    assert attempts == [(_TV_ID, "192.168.0.138"), (_TV_ID, "fe80::1%en0")]


@pytest.mark.asyncio
async def test_pair_fails_when_no_address_is_reachable(monkeypatch):
    answers = [_manual_pairing_answer("Main Bedroom", _TV_ID, "192.168.0.138")]
    _install_pair_fakes(monkeypatch, answers, unreachable={"192.168.0.138"})

    with pytest.raises(typer.Exit):
        await cast(Any, remote.cli_pair).__wrapped__(name=None, udid=None)


@pytest.mark.asyncio
async def test_pair_udid_selects_by_identifier(monkeypatch):
    answers = [
        _manual_pairing_answer("Living Room", "OTHER-ID", "192.168.0.20"),
        _manual_pairing_answer("Main Bedroom", _TV_ID, "fe80::1%en0"),
        _manual_pairing_answer("Main Bedroom", _TV_ID, "192.168.0.138"),
    ]
    attempts = _install_pair_fakes(monkeypatch, answers)

    await cast(Any, remote.cli_pair).__wrapped__(name=None, udid=_TV_ID)

    assert attempts == [(_TV_ID, "192.168.0.138")]


@pytest.mark.asyncio
async def test_pair_udid_without_match_exits(monkeypatch):
    answers = [_manual_pairing_answer("Living Room", "OTHER-ID", "192.168.0.20")]
    attempts = _install_pair_fakes(monkeypatch, answers)

    with pytest.raises(typer.Exit):
        await cast(Any, remote.cli_pair).__wrapped__(name=None, udid=_TV_ID)
    assert attempts == []


def test_delete_pair_without_record_raises_not_paired(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(remote, "get_home_folder", lambda: tmp_path)

    with pytest.raises(NotPairedError, match="No remote pairing record for 00008000-0000"):
        remote.cli_delete_pair("00008000-0000")


def test_delete_pair_removes_record(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(remote, "get_home_folder", lambda: tmp_path)
    record = tmp_path / f"{remote.get_remote_pairing_record_filename('00008000-0000')}.{remote.PAIRING_RECORD_EXT}"
    record.write_bytes(b"")

    remote.cli_delete_pair("00008000-0000")

    assert not record.exists()
