import json
import logging
from collections.abc import AsyncGenerator
from typing import Any, ClassVar, cast

import pytest
import typer

from pymobiledevice3.cli.developer import accessibility as accessibility_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.accessibilityaudit import AXAuditElement_v1, AXAuditInspectorFocus_v1

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())
_ELEMENT = bytes.fromhex("27000000007041A27C00000A0700000000000000")


class _FakeAccessibilityAudit:
    captions: ClassVar[list[str]] = []
    timeout = False

    def __init__(self, service_provider: Any) -> None:
        pass

    async def __aenter__(self) -> "_FakeAccessibilityAudit":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    async def iter_elements(self) -> AsyncGenerator[AXAuditInspectorFocus_v1, None]:
        for caption in self.captions:
            yield AXAuditInspectorFocus_v1({
                "CaptionTextValue_v1": caption,
                "ElementValue_v1": AXAuditElement_v1({"PlatformElementValue_v1": _ELEMENT}),
            })
        if self.timeout:
            raise TimeoutError("timed out waiting for accessibility focus events")


@pytest.fixture(autouse=True)
def _fake_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(accessibility_module, "AccessibilityAudit", _FakeAccessibilityAudit)
    _FakeAccessibilityAudit.captions = []
    _FakeAccessibilityAudit.timeout = False


def test_list_items_prints_the_elements(capsys: pytest.CaptureFixture[str]) -> None:
    _FakeAccessibilityAudit.captions = ["Camera, Button", "Photos"]

    accessibility_module.accessibility_list_items(_FAKE_SERVICE_PROVIDER)

    assert [item["caption"] for item in json.loads(capsys.readouterr().out)] == ["Camera, Button", "Photos"]


def test_list_items_reports_a_device_that_moves_no_focus(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    # A locked device accepts the focus moves but reports no element, which surfaced as a raw
    # TimeoutError traceback
    _FakeAccessibilityAudit.timeout = True

    with caplog.at_level(logging.ERROR), pytest.raises(typer.Exit) as exc_info:
        accessibility_module.accessibility_list_items(_FAKE_SERVICE_PROVIDER)

    assert exc_info.value.exit_code == 1
    assert "unlocked" in caplog.text
    assert capsys.readouterr().out == ""
