import json
from typing import cast

import pytest

from pymobiledevice3.cli.diagnostics import battery as battery_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())

_RAW_INFO = {
    "InstantAmperage": -211,
    "Temperature": 3010,
    "Voltage": 4123,
    "IsCharging": False,
    "CurrentCapacity": 78,
    "SomethingElse": "ignored",
}


class _StopMonitor(Exception):
    """Raised by the fake service to break the endless monitor loop after one sample."""


class _FakeDiagnosticsService:
    def __init__(self, lockdown):
        self.samples = 0

    async def get_battery(self):
        if self.samples:
            raise _StopMonitor
        self.samples += 1
        return _RAW_INFO


@pytest.fixture(autouse=True)
def _fake_service(monkeypatch):
    monkeypatch.setattr(battery_module, "DiagnosticsService", _FakeDiagnosticsService)
    monkeypatch.setattr(battery_module.asyncio, "sleep", _no_sleep)


async def _no_sleep(_duration):
    return None


def test_battery_monitor_emits_ndjson_record(capsys):
    with pytest.raises(_StopMonitor):
        battery_module.diagnostics_battery_monitor(_FAKE_SERVICE_PROVIDER)

    lines = capsys.readouterr().out.strip().splitlines()
    assert json.loads(lines[0]) == {
        "InstantAmperage": -211,
        "Temperature": 3010,
        "Voltage": 4123,
        "IsCharging": False,
        "CurrentCapacity": 78,
    }
