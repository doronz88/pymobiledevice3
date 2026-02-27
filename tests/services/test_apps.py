from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.installation_proxy import InstallationProxyService


def _make_minimal_ipa_bytes() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as zip_file:
        zip_file.writestr("Payload/Test.app/Info.plist", b"")
    return buffer.getvalue()


def test_get_apps(lockdown: LockdownClient) -> None:
    with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        apps = installation_proxy.get_apps()
        assert len(apps) > 1


def test_get_system_apps(lockdown: LockdownClient) -> None:
    with InstallationProxyService(lockdown=lockdown) as installation_proxy:
        app_types = {app["ApplicationType"] for app in installation_proxy.get_apps(application_type="System").values()}
        assert len(app_types) == 1
        assert app_types.pop() == "System"


@pytest.mark.asyncio
async def test_parallel_installations_cleanup(lockdown: LockdownClient, monkeypatch: pytest.MonkeyPatch) -> None:
    ipa_bytes = _make_minimal_ipa_bytes()
    captured_plists: list[dict] = []

    def wrap_send_plist(service, captured: list[dict]):
        original_send_plist = service.send_plist

        def wrapped_send_plist(payload: dict) -> None:
            if payload.get("Command") == "Install":
                captured.append(payload.copy())
            original_send_plist(payload)

        return wrapped_send_plist

    with InstallationProxyService(lockdown=lockdown) as first, InstallationProxyService(lockdown=lockdown) as second:
        monkeypatch.setattr(first.service, "send_plist", wrap_send_plist(first.service, captured_plists))
        monkeypatch.setattr(second.service, "send_plist", wrap_send_plist(second.service, captured_plists))

        # TODO: perform those in parallel once ServiceConnection is thread safe (they read concurrently the "StartService" response)
        # results = await asyncio.gather(
        #     asyncio.to_thread(first.install_from_bytes, ipa_bytes),
        #     asyncio.to_thread(second.install_from_bytes, ipa_bytes),
        #     return_exceptions=True,
        # )
        try:
            result1 = first.install_from_bytes(ipa_bytes)
        except Exception as e:
            result1 = e
        try:
            result2 = second.install_from_bytes(ipa_bytes)
        except Exception as e:
            result2 = e
        results = [result1, result2]

    assert all(isinstance(result, AppInstallError) for result in results)
    assert len(captured_plists) == 2, f"Expected 2 captured plists, got {len(captured_plists)}"

    package_paths = [payload["PackagePath"] for payload in captured_plists]
    assert len(set(package_paths)) == 2, f"Expected different package paths for each installation, got {package_paths}"

    with AfcService(lockdown=lockdown) as afc:
        for package_path in package_paths:
            assert not afc.exists(package_path), f"Expected package path {package_path} to be cleaned up"
