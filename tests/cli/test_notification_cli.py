import json
from typing import cast

import pytest

from pymobiledevice3.cli import notification as notification_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())

_EVENTS = [
    {"Command": "RelayNotification", "Name": "com.apple.mobile.data_sync.domain_changed"},
    {"Command": "RelayNotification", "Name": "com.apple.springboard.lockstate"},
]


class _FakeNotificationProxyService:
    def __init__(self, lockdown, insecure=False):
        pass

    async def notify_register_dispatch(self, name):
        pass

    async def receive_notification(self):
        for event in _EVENTS:
            yield event


@pytest.fixture(autouse=True)
def _fake_service(monkeypatch):
    monkeypatch.setattr(notification_module, "NotificationProxyService", _FakeNotificationProxyService)


def test_observe_emits_ndjson_records(capsys):
    notification_module.observe(_FAKE_SERVICE_PROVIDER, ["some-name"])

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == _EVENTS


def test_observe_all_emits_ndjson_records(monkeypatch, capsys):
    monkeypatch.setattr(notification_module, "get_notifications", lambda: ["a", "b"])

    notification_module.observe_all(_FAKE_SERVICE_PROVIDER)

    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in lines] == _EVENTS
