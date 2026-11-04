from dataclasses import dataclass
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.cli.developer.dvt import sysmon as sysmon_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


@dataclass
class _SystemAttributes:
    CPU: int


class _FakeSysmontap:
    system_attributes_cls = _SystemAttributes

    @classmethod
    async def create(cls, _dvt: object) -> "_FakeSysmontap":
        return cls()

    async def __aenter__(self) -> "_FakeSysmontap":
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        return None

    async def __aiter__(self):
        row = {"System": [7], "SystemCPUUsage": {"CPU_TotalLoad": 12.5}, "CPUCount": 6, "EnabledCPUs": 6}
        # the first SystemCPUUsage sample is discarded as unreliable
        yield row
        yield row


class _FakeDvtProvider:
    def __init__(self, _service_provider: object) -> None:
        pass

    async def __aenter__(self) -> "_FakeDvtProvider":
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        return None


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ("CPUCount", ["CPUCount: 6"]),
        ("CPU", ["CPU: 7"]),
        ("CPU, EnabledCPUs", ["CPU: 7", "EnabledCPUs: 6"]),
        (None, ["CPU: 7", "CPU_TotalLoad: 12.5", "CPUCount: 6", "EnabledCPUs: 6"]),
    ],
)
def test_system_fields_match_exact_names(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fields: Optional[str],
    expected: list[str],
) -> None:
    monkeypatch.setattr(sysmon_module, "DvtProvider", _FakeDvtProvider)
    monkeypatch.setattr(sysmon_module, "Sysmontap", _FakeSysmontap)

    sysmon_module.sysmon_system(cast(LockdownServiceProvider, object()), fields=fields)

    assert capsys.readouterr().out.splitlines() == expected
