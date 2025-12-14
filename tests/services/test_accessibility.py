import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit


@pytest.fixture(scope="function")
def accessibility_audit(lockdown: LockdownClient):
    with AccessibilityAudit(lockdown=lockdown) as accessibility_audit:
        yield accessibility_audit


def test_capabilities(accessibility_audit: AccessibilityAudit) -> None:
    assert "deviceApiVersion" in accessibility_audit.capabilities


def test_invert_colors_in_settings(accessibility_audit: AccessibilityAudit) -> None:
    found = False
    for setting in accessibility_audit.settings:
        if setting.key == "INVERT_COLORS":
            found = True
            break
    assert found
