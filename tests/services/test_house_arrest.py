from typing import cast
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from bytestruct import TruncatedDataError

from pymobiledevice3.exceptions import AppNotInstalledError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService


@pytest_asyncio.fixture(scope="function")
async def user_bundle_id(lockdown: LockdownClient) -> str:
    async with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        user_apps = await installation_proxy.get_apps(application_type="User")
    file_sharing_apps = [bundle_id for bundle_id, app_info in user_apps.items() if app_info.get("UIFileSharingEnabled")]
    if not file_sharing_apps:
        pytest.skip("No user apps with UIFileSharingEnabled installed to exercise house arrest")
    return file_sharing_apps[0]


@pytest.mark.asyncio
async def test_missing_bundle_id(lockdown: LockdownClient) -> None:
    with pytest.raises(AppNotInstalledError):
        async with await HouseArrestService.create(lockdown=lockdown, bundle_id="com.pymobiledevice3.missing.app"):
            pass


@pytest.mark.asyncio
async def test_vend_container_lists_app_root(lockdown: LockdownClient, user_bundle_id: str) -> None:
    async with await HouseArrestService.create(
        lockdown=lockdown, bundle_id=user_bundle_id, documents_only=True
    ) as service:
        await service.listdir("/Documents")


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [PyMobileDevice3Exception("InstallationLookupFailed"), TruncatedDataError("short")])
async def test_create_closes_the_service_when_vending_fails(monkeypatch, error: Exception) -> None:
    # A malformed reply (a binary parse error) must not leak the connection either.
    closed: list[bool] = []

    async def send_command(self: HouseArrestService, bundle_id: str, cmd: str = "VendContainer") -> None:
        raise error

    async def close(self: HouseArrestService) -> None:
        closed.append(True)

    monkeypatch.setattr(HouseArrestService, "send_command", send_command)
    monkeypatch.setattr(HouseArrestService, "close", close)
    lockdown = cast(LockdownClient, MagicMock(spec=LockdownClient))
    with pytest.raises(type(error)):
        await HouseArrestService.create(lockdown=lockdown, bundle_id="com.example.app")
    assert closed == [True]
