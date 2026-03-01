import pytest
import pytest_asyncio

from pymobiledevice3.exceptions import AppNotInstalledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService


@pytest_asyncio.fixture(scope="function")
async def user_bundle_id(lockdown: LockdownClient) -> str:
    async with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        user_apps = await installation_proxy.get_apps(application_type="User")
    if not user_apps:
        pytest.skip("No user apps installed to exercise house arrest")
    return next(iter(user_apps))


@pytest.mark.asyncio
async def test_missing_bundle_id(lockdown: LockdownClient) -> None:
    with pytest.raises(AppNotInstalledError):
        async with await HouseArrestService.create(lockdown=lockdown, bundle_id="com.pymobiledevice3.missing.app"):
            pass


@pytest.mark.asyncio
async def test_vend_container_lists_app_root(lockdown: LockdownClient, user_bundle_id: str) -> None:
    async with await HouseArrestService.create(
        lockdown=lockdown, bundle_id=user_bundle_id, documents_only=False
    ) as service:
        entries = set(await service.listdir("/"))
    assert "Documents" in entries
