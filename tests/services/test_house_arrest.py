import pytest

from pymobiledevice3.exceptions import AppNotInstalledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService


@pytest.fixture(scope="function")
def user_bundle_id(lockdown: LockdownClient) -> str:
    with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        user_apps = installation_proxy.get_apps(application_type="User")
    if not user_apps:
        pytest.skip("No user apps installed to exercise house arrest")
    return next(iter(user_apps))


def test_missing_bundle_id(lockdown: LockdownClient) -> None:
    with pytest.raises(AppNotInstalledError):
        HouseArrestService(lockdown=lockdown, bundle_id="com.pymobiledevice3.missing.app")


def test_vend_container_lists_app_root(lockdown: LockdownClient, user_bundle_id: str) -> None:
    with HouseArrestService(lockdown=lockdown, bundle_id=user_bundle_id, documents_only=False) as service:
        entries = set(service.listdir("/"))
    assert "Documents" in entries
