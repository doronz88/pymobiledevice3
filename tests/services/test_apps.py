import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.installation_proxy import InstallationProxyService


@pytest.mark.asyncio
async def test_get_apps(lockdown: LockdownClient) -> None:
    async with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        apps = await installation_proxy.get_apps()
        assert len(apps) > 1


@pytest.mark.asyncio
async def test_get_system_apps(lockdown: LockdownClient) -> None:
    async with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        system_apps = await installation_proxy.get_apps(application_type="System")
        app_types = {app["ApplicationType"] for app in system_apps.values()}
        assert len(app_types) == 1
        assert app_types.pop() == "System"
