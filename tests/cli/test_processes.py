import json
from typing import cast

import pytest

from pymobiledevice3.cli import cli_common
from pymobiledevice3.cli import processes as processes_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())


@pytest.fixture(autouse=True)
def _no_color(monkeypatch):
    # capsys' stdout has no fileno(); disable print_json's TTY color autodetection
    monkeypatch.setattr(cli_common, "user_requested_colored_output", lambda: False)


class _FakeOsTraceService:
    def __init__(self, lockdown):
        pass

    async def get_pid_list(self):
        return {
            "Payload": {
                1: {"ProcessName": "kernel_task"},
                42: {"ProcessName": "backboardd"},
                77: {"ProcessName": "kernelmanagerd"},
            }
        }


def test_pgrep_prints_matches_as_json_on_stdout(monkeypatch, capsys):
    monkeypatch.setattr(processes_module, "OsTraceService", _FakeOsTraceService)

    processes_module.processes_pgrep(_FAKE_SERVICE_PROVIDER, "kernel")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == [
        {"pid": 1, "name": "kernel_task"},
        {"pid": 77, "name": "kernelmanagerd"},
    ]


def test_pgrep_no_matches_prints_empty_json_list(monkeypatch, capsys):
    monkeypatch.setattr(processes_module, "OsTraceService", _FakeOsTraceService)

    processes_module.processes_pgrep(_FAKE_SERVICE_PROVIDER, "no-such-process")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
