import datetime
import json
from typing import cast

import pytest

from pymobiledevice3.cli import crash as crash_module
from pymobiledevice3.cli.cli_common import OutputFormat
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())


class _FakeReport:
    name = "MobileSafari"
    bug_type = 309
    bug_type_str = "crash"
    incident_id = "AAAA-BBBB"
    timestamp = datetime.datetime(2026, 8, 8, 12, 0, 0)

    def __str__(self):
        return "MobileSafari crash report"


def _fake_manager(items):
    class _Manager:
        def __init__(self, service_provider):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def watch(self, name=None, raw=False):
            for item in items:
                yield item

    return _Manager


def test_crash_watch_json_emits_parsed_record(monkeypatch, capsys):
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([_FakeReport()]))

    crash_module.crash_watch(_FAKE_SERVICE_PROVIDER, output_format=OutputFormat.JSON)

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == [
        {
            "name": "MobileSafari",
            "bug_type": 309,
            "bug_type_str": "crash",
            "incident_id": "AAAA-BBBB",
            "timestamp": "2026-08-08T12:00:00",
        }
    ]


def test_crash_watch_json_emits_raw_record_as_content(monkeypatch, capsys):
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager(["raw report text"]))

    crash_module.crash_watch(_FAKE_SERVICE_PROVIDER, raw=True, output_format=OutputFormat.JSON)

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == [{"content": "raw report text"}]


def test_crash_watch_text_prints_report(monkeypatch, capsys):
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([_FakeReport()]))

    crash_module.crash_watch(_FAKE_SERVICE_PROVIDER, output_format=OutputFormat.TEXT)

    captured = capsys.readouterr()
    assert "MobileSafari crash report" in captured.out
