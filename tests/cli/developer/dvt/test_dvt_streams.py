import ipaddress
import json
from typing import cast

import pytest

from pymobiledevice3.cli.cli_common import OutputFormat
from pymobiledevice3.cli.developer import dvt as dvt_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.instruments.network_monitor import (
    AddressV4,
    ConnectionDetectionEvent,
    SocketAddress,
)

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())


class _FakeDvtProvider:
    def __init__(self, service_provider):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _fake_stream(items):
    class _Stream:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def __aiter__(self):
            return self._generate()

        async def _generate(self):
            for item in items:
                yield item

    return _Stream


@pytest.fixture(autouse=True)
def _fake_dvt(monkeypatch):
    monkeypatch.setattr(dvt_module, "DvtProvider", _FakeDvtProvider)


def test_energy_emits_ndjson_records(monkeypatch, capsys):
    samples = [{"energy.cost": 1.5}, {"energy.cost": 2.5}]
    monkeypatch.setattr(dvt_module, "EnergyMonitor", _fake_stream(samples))

    dvt_module.dvt_energy(_FAKE_SERVICE_PROVIDER, ["123"])

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == samples


def test_notifications_emits_ndjson_records(monkeypatch, capsys):
    events = [{"execName": "app", "state": 4}]
    monkeypatch.setattr(dvt_module, "Notifications", _fake_stream(events))

    dvt_module.dvt_notifications(_FAKE_SERVICE_PROVIDER)

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == events


def test_graphics_emits_ndjson_records(monkeypatch, capsys):
    samples = [{"CoreAnimationFramesPerSecond": 60}]
    monkeypatch.setattr(dvt_module, "Graphics", _fake_stream(samples))

    dvt_module.dvt_graphics(_FAKE_SERVICE_PROVIDER)

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == samples


def _connection_event() -> ConnectionDetectionEvent:
    def address(ip: str, port: int) -> SocketAddress:
        return SocketAddress(
            length=0x10,
            family=2,
            port=port,
            data=AddressV4(address=ipaddress.IPv4Address(ip), _zero=b"\x00" * 8),
        )

    return ConnectionDetectionEvent(
        local_address=address("10.0.0.1", 5000),
        remote_address=address("17.0.0.1", 443),
        interface_index=1,
        pid=42,
        recv_buffer_size=0,
        recv_buffer_used=0,
        serial_number=7,
        kind=1,
    )


def test_netstat_json_emits_connection_records(monkeypatch, capsys):
    monkeypatch.setattr(dvt_module, "NetworkMonitor", _fake_stream([_connection_event()]))

    dvt_module.netstat(_FAKE_SERVICE_PROVIDER, output_format=OutputFormat.JSON)

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == [
        {
            "event": "connection_detected",
            "local": {"address": "10.0.0.1", "port": 5000},
            "remote": {"address": "17.0.0.1", "port": 443},
            "pid": 42,
            "interface_index": 1,
        }
    ]


def test_netstat_text_prints_connection_line_to_stdout(monkeypatch, capsys):
    monkeypatch.setattr(dvt_module, "NetworkMonitor", _fake_stream([_connection_event()]))

    dvt_module.netstat(_FAKE_SERVICE_PROVIDER, output_format=OutputFormat.TEXT)

    captured = capsys.readouterr()
    assert "10.0.0.1:5000 -> 17.0.0.1:443" in captured.out


class _FakeOslogMessage:
    process = 42
    message_type = "Default"
    sender_image_path = "/usr/lib/libfoo.dylib"
    subsystem = "com.apple.test"
    category = "general"
    message = None
    name = "hello world"


def test_oslog_json_emits_ndjson_records(monkeypatch, capsys):
    monkeypatch.setattr(dvt_module, "ActivityTraceTap", _fake_stream([_FakeOslogMessage()]))

    dvt_module.dvt_oslog(_FAKE_SERVICE_PROVIDER, output_format=OutputFormat.JSON)

    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["pid"] == 42
    assert record["message_type"] == "Default"
    assert record["subsystem"] == "com.apple.test"
    assert record["category"] == "general"
    assert record["image_name"] == "libfoo.dylib"
    assert record["message"] == "hello world"
    assert "timestamp" in record
