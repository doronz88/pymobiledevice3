import json
from typing import Any, ClassVar, cast

import pytest
import typer

from pymobiledevice3.cli.developer import accessibility as accessibility_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.accessibilityaudit import AXAuditElement_v1, AXAuditInspectorFocus_v1, Direction

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())
_ELEMENT = bytes.fromhex("27000000007041A27C00000A0700000000000000")


class _FakeAccessibilityAudit:
    directions: ClassVar[list[Direction]] = []
    requested: ClassVar[list[list[str]]] = []
    timeout = False

    def __init__(self, service_provider: Any) -> None:
        pass

    async def __aenter__(self) -> "_FakeAccessibilityAudit":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    async def move_focus_and_wait(self, direction: Direction) -> AXAuditInspectorFocus_v1:
        if self.timeout:
            raise TimeoutError
        self.directions.append(direction)
        return AXAuditInspectorFocus_v1({
            "CaptionTextValue_v1": "Camera, Button",
            "ElementValue_v1": AXAuditElement_v1({"PlatformElementValue_v1": _ELEMENT}),
        })

    async def element_attributes(self, element: bytes, attributes: list[str]) -> dict[str, Any]:
        assert element == _ELEMENT
        self.requested.append(attributes)
        return {name: {"Label": "Camera", "Identifier": "camera-orb-button"}.get(name) for name in attributes}


@pytest.fixture(autouse=True)
def _fake_service(monkeypatch):
    monkeypatch.setattr(accessibility_module, "AccessibilityAudit", _FakeAccessibilityAudit)
    _FakeAccessibilityAudit.directions = []
    _FakeAccessibilityAudit.requested = []
    _FakeAccessibilityAudit.timeout = False


def test_element_attributes_defaults(capsys):
    accessibility_module.accessibility_element_attributes(_FAKE_SERVICE_PROVIDER)

    output = json.loads(capsys.readouterr().out)
    assert _FakeAccessibilityAudit.directions == [Direction.Next]
    assert _FakeAccessibilityAudit.requested == [["Label", "Identifier", "Value"]]
    assert output["platform_identifier"] == _ELEMENT.hex().upper()
    assert output["caption"] == "Camera, Button"
    assert output["attributes"] == {"Label": "Camera", "Identifier": "camera-orb-button", "Value": None}


def test_element_attributes_custom_direction_and_attributes(capsys):
    accessibility_module.accessibility_element_attributes(
        _FAKE_SERVICE_PROVIDER, attributes=["Label"], direction=accessibility_module.FocusDirection.LAST
    )

    assert _FakeAccessibilityAudit.directions == [Direction.Last]
    assert json.loads(capsys.readouterr().out)["attributes"] == {"Label": "Camera"}


def test_element_attributes_focus_timeout_exits():
    _FakeAccessibilityAudit.timeout = True
    with pytest.raises(typer.Exit):
        accessibility_module.accessibility_element_attributes(_FAKE_SERVICE_PROVIDER)
