import pytest
import pytest_asyncio

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit


@pytest_asyncio.fixture(scope="function")
async def accessibility_audit(lockdown: LockdownClient):
    async with AccessibilityAudit(lockdown=lockdown) as accessibility_audit:
        yield accessibility_audit


@pytest.mark.asyncio
async def test_capabilities(accessibility_audit: AccessibilityAudit) -> None:
    assert "deviceApiVersion" in await accessibility_audit.capabilities()


@pytest.mark.asyncio
async def test_invert_colors_in_settings(accessibility_audit: AccessibilityAudit) -> None:
    found = False
    for setting in await accessibility_audit.settings():
        if setting.key == "INVERT_COLORS":
            found = True
            break
    assert found
