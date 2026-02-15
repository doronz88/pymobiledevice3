import asyncio
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.installation_proxy import InstallationProxyService


def _make_minimal_ipa_bytes() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as zip_file:
        zip_file.writestr("Payload/Test.app/Info.plist", b"")
    return buffer.getvalue()


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


@pytest.mark.asyncio
async def test_parallel_installations_cleanup(lockdown: LockdownClient, monkeypatch: pytest.MonkeyPatch) -> None:
    ipa_bytes = _make_minimal_ipa_bytes()
    captured_plists: list[dict] = []

    def wrap_send_plist(service, captured: list[dict]):
        original_send_plist = service.send_plist

        async def wrapped_send_plist(payload: dict) -> None:
            if payload.get("Command") == "Install":
                captured.append(payload.copy())
            await original_send_plist(payload)

        return wrapped_send_plist

    async with (
        await create_using_usbmux(serial=lockdown.identifier) as first_lockdown,
        await create_using_usbmux(serial=lockdown.identifier) as second_lockdown,
        InstallationProxyService(lockdown=first_lockdown) as first,
        InstallationProxyService(lockdown=second_lockdown) as second,
    ):
        monkeypatch.setattr(first.service, "send_plist", wrap_send_plist(first.service, captured_plists))
        monkeypatch.setattr(second.service, "send_plist", wrap_send_plist(second.service, captured_plists))

        results = await asyncio.gather(
            first.install_from_bytes(ipa_bytes),
            second.install_from_bytes(ipa_bytes),
            return_exceptions=True,
        )

    assert all(isinstance(result, AppInstallError) for result in results)
    assert len(captured_plists) == 2, f"Expected 2 captured plists, got {len(captured_plists)}"

    package_paths = [payload["PackagePath"] for payload in captured_plists]
    assert len(set(package_paths)) == 2, f"Expected different package paths for each installation, got {package_paths}"

    async with AfcService(lockdown=lockdown) as afc:
        for package_path in package_paths:
            assert not await afc.exists(package_path), f"Expected package path {package_path} to be cleaned up"
