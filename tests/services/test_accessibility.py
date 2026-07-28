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


@pytest.mark.asyncio
async def test_run_audit_returns_issue_list(accessibility_audit: AccessibilityAudit) -> None:
    # A screen that passes the audit yields an empty issue list (used to raise IndexError).
    types = await accessibility_audit.supported_audits_types()
    issues = await accessibility_audit.run_audit(types[:1])
    assert isinstance(issues, list)
