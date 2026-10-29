import asyncio
import contextlib
import ipaddress
import json
import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import typer

from pymobiledevice3.cli import remote
from pymobiledevice3.cli.cli_common import OutputFormat
from pymobiledevice3.exceptions import NoDeviceConnectedError, RemotePairingCompletedError
from pymobiledevice3.remote import native_tunnel
from pymobiledevice3.remote.common import ConnectionType, TunnelProtocol
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


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

    async def fake_native_tunnel_task(udid=None, script_mode=False, output_format=OutputFormat.TEXT):
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

    async def fake_native_tunnel_task(udid=None, script_mode=False, output_format=OutputFormat.TEXT):
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
    async def fake_native_tunnel_task(udid=None, script_mode=False, output_format=OutputFormat.TEXT):
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


@pytest.mark.asyncio
async def test_native_tunnel_task_format_json_prints_held_peer_info_once(monkeypatch, capsys):
    class FakeService:
        address = ("fdf4:cb47:dd51::1", 61234)

    class FakeRsd:
        udid = "UDID"
        service = FakeService()

        def __init__(self):
            self.peer_info = {
                "Properties": {"UniqueDeviceID": "UDID", "OSVersion": "27.2"},
                "Services": {},
                "Blob": b"\x01\xff",
            }

    establish_calls = []

    async def fake_establish_native_rsd(serial=None):
        establish_calls.append(serial)
        return FakeRsd()

    async def forbidden_connect(self, *args, **kwargs):
        raise AssertionError("a second RSD handshake would make iOS 27.2+ drop the tunnel's listeners")

    monkeypatch.setattr(native_tunnel, "establish_native_rsd", fake_establish_native_rsd)
    monkeypatch.setattr(RemoteServiceDiscoveryService, "connect", forbidden_connect)

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(remote.native_tunnel_task("UDID", output_format=OutputFormat.JSON), timeout=0.1)

    out = capsys.readouterr().out
    assert out.count("\n") == 1
    assert json.loads(out) == {
        "udid": "UDID",
        "address": "fdf4:cb47:dd51::1",
        "port": 61234,
        "peer_info": {
            "Properties": {"UniqueDeviceID": "UDID", "OSVersion": "27.2"},
            "Services": {},
            "Blob": {"$hex": "01ff"},
        },
    }
    assert establish_calls == ["UDID"]


@pytest.mark.parametrize("native", [True, None, False])
def test_cli_start_tunnel_rejects_script_mode_with_format_json(native):
    with pytest.raises(typer.BadParameter, match="--script-mode"):
        remote.cli_start_tunnel(native=native, script_mode=True, output_format=OutputFormat.JSON)


def test_cli_start_tunnel_format_json_does_not_force_classic_tunnel(monkeypatch):
    # --format is not a classic-tunnel option: under the native default it stays on the native task.
    received = None

    async def fake_native_tunnel_task(udid=None, script_mode=False, output_format=OutputFormat.TEXT):
        nonlocal received
        received = output_format

    monkeypatch.setattr(remote, "native_tunnel_task", fake_native_tunnel_task)
    monkeypatch.setattr(remote, "default_transport_preference", lambda: "native")
    monkeypatch.setattr(type(remote.OSUTILS), "is_admin", property(lambda self: False))

    remote.cli_start_tunnel(output_format=OutputFormat.JSON)

    assert received is OutputFormat.JSON


def test_cli_start_tunnel_classic_path_passes_output_format(monkeypatch):
    received = None

    async def fake_start_tunnel_task(*args, output_format=OutputFormat.TEXT, **kwargs):
        nonlocal received
        received = output_format

    monkeypatch.setattr(remote, "default_transport_preference", lambda: "userspace")
    monkeypatch.setattr(type(remote.OSUTILS), "is_admin", property(lambda self: True))
    monkeypatch.setattr(remote, "verify_tunnel_imports", lambda: True)
    monkeypatch.setattr(remote, "start_tunnel_task", fake_start_tunnel_task)

    remote.cli_start_tunnel(output_format=OutputFormat.JSON)

    assert received is OutputFormat.JSON


@pytest.mark.asyncio
async def test_tunnel_task_format_json_prints_one_line(monkeypatch, capsys):
    class FakeClient:
        async def wait_closed(self):
            pass

    class FakeTunnelContext:
        async def __aenter__(self):
            return SimpleNamespace(
                interface="utun6",
                protocol=TunnelProtocol.TCP,
                address="fd7b:e5b:6f53::1",
                port=64337,
                client=FakeClient(),
            )

        async def __aexit__(self, *exc_info):
            return None

    monkeypatch.setattr(remote, "start_tunnel", lambda *args, **kwargs: FakeTunnelContext())
    service = cast(Any, SimpleNamespace(remote_identifier="IDENTIFIER"))

    await remote.tunnel_task(service, output_format=OutputFormat.JSON)

    out = capsys.readouterr().out
    assert out.count("\n") == 1
    assert json.loads(out) == {
        "identifier": "IDENTIFIER",
        "interface": "utun6",
        "protocol": "tcp",
        "address": "fd7b:e5b:6f53::1",
        "port": 64337,
    }


# Needs the real macOS tunnel to the device behind --udid (it is deliberately not "the first device
# found": the native tunnel competes with remoted/Xcode for the device).
@pytest.mark.device
@pytest.mark.asyncio
async def test_native_tunnel_task_format_json_on_device(udid_option, monkeypatch, capsys):
    if sys.platform != "darwin":
        pytest.skip("The native tunnel is macOS only")
    if udid_option is None:
        pytest.skip("Pass --udid UDID: the native tunnel is only opened for an explicitly chosen device")

    connect_calls = 0
    real_connect = RemoteServiceDiscoveryService.connect

    async def counting_connect(self, *args, **kwargs):
        nonlocal connect_calls
        connect_calls += 1
        return await real_connect(self, *args, **kwargs)

    monkeypatch.setattr(RemoteServiceDiscoveryService, "connect", counting_connect)

    task = asyncio.create_task(remote.native_tunnel_task(udid_option, output_format=OutputFormat.JSON))
    try:
        out = ""
        deadline = time.monotonic() + 90
        while not out.endswith("\n"):
            if task.done():
                task.result()  # surface why the tunnel never came up
            if time.monotonic() > deadline:
                pytest.fail("the native tunnel printed nothing within 90 seconds")
            await asyncio.sleep(0.1)
            out += capsys.readouterr().out
        connects_at_output = connect_calls

        assert out.count("\n") == 1
        record = json.loads(out)
        assert set(record) == {"udid", "address", "port", "peer_info"}
        assert record["udid"] == udid_option
        assert record["udid"] == record["peer_info"]["Properties"]["UniqueDeviceID"]
        assert ipaddress.ip_address(record["address"])
        assert 0 < record["port"] < 65536
        services = record["peer_info"]["Services"]
        assert services

        # A plain TCP connect (no RSD handshake) to an advertised service port: on iOS 27.2+ a second
        # RSD connection with another handshake UUID makes the device close these listeners.
        service_port = int(next(service["Port"] for service in services.values() if "Port" in service))
        _, writer = await asyncio.wait_for(asyncio.open_connection(record["address"], service_port), timeout=10)
        writer.close()
        await writer.wait_closed()

        assert connect_calls == connects_at_output, "start-tunnel --format json opened another RSD connection"
        assert not task.done()
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        # establish_native_rsd keeps the tunnel for the process lifetime (the CLI releases it at exit);
        # release it here so the assertion and the RSD socket do not outlive the test.
        tunnel, native_tunnel._cli_native_tunnel = native_tunnel._cli_native_tunnel, None
        if tunnel is not None:
            await tunnel.aclose()


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
        await cast(Any, remote.cli_pair).__wrapped__(name=None)

    assert "Pairing completed" in caplog.text
