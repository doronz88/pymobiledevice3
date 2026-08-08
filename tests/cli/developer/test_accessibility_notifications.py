import json
from typing import ClassVar, cast

import pytest

from pymobiledevice3.cli.cli_common import OutputFormat
from pymobiledevice3.cli.developer import accessibility as accessibility_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())


class _FakeFocusItem:
    def to_dict(self):
        return {"caption": "Settings", "element": {"$hexish": "irrelevant"}}

    def __str__(self):
        return "<FocusItem caption=Settings>"


class _FakeEvent:
    name = "hostInspectorCurrentElementChanged:"
    data: ClassVar[list["_FakeFocusItem"]] = [_FakeFocusItem()]


class _FakeAccessibilityAudit:
    def __init__(self, service_provider):
        pass

    async def iter_events(self):
        yield _FakeEvent()


@pytest.fixture(autouse=True)
def _fake_service(monkeypatch):
    monkeypatch.setattr(accessibility_module, "AccessibilityAudit", _FakeAccessibilityAudit)


def test_accessibility_notifications_json_emits_ndjson_records(capsys):
    accessibility_module.accessibility_notifications(_FAKE_SERVICE_PROVIDER, output_format=OutputFormat.JSON)

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == [{"caption": "Settings", "element": {"$hexish": "irrelevant"}}]


def test_accessibility_notifications_text_prints_records_to_stdout(capsys):
    accessibility_module.accessibility_notifications(_FAKE_SERVICE_PROVIDER, output_format=OutputFormat.TEXT)

    captured = capsys.readouterr()
    assert "caption=Settings" in captured.out
