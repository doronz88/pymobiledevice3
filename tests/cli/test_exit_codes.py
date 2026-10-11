import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import typer

from pymobiledevice3.cli import backup, remote, webinspector
from pymobiledevice3.cli import lockdown as lockdown_cli
from pymobiledevice3.cli.developer import arbitration, debugserver
from pymobiledevice3.cli.developer import dvt as dvt_cli
from pymobiledevice3.cli.developer.dvt import core_profile_session
from pymobiledevice3.exceptions import (
    DeviceAlreadyInUseError,
    DvtDirListError,
    DvtException,
    ExtractingStackshotError,
    LaunchingApplicationError,
    RemoteAutomationNotEnabledError,
    WebInspectorNotEnabledError,
)
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

pytestmark = [pytest.mark.cli]

# Every command below logged its failure and returned, so the process exited 0 and scripts carried on
LOCKDOWN = cast(LockdownServiceProvider, object())
WEBINSPECTOR_ERRORS = [LaunchingApplicationError, WebInspectorNotEnabledError, RemoteAutomationNotEnabledError]


class _AsyncContext:
    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None


@pytest.mark.parametrize("error_type", WEBINSPECTOR_ERRORS)
def test_webinspector_command_exits_nonzero_on_a_handled_error(error_type: type[Exception]) -> None:
    def command() -> None:
        raise error_type()

    with pytest.raises(typer.Exit) as exc_info:
        webinspector.catch_errors(command)()

    assert exc_info.value.exit_code == 1


@pytest.mark.parametrize("error_type", WEBINSPECTOR_ERRORS)
async def test_webinspector_async_command_exits_nonzero_on_a_handled_error(error_type: type[Exception]) -> None:
    async def command() -> None:
        raise error_type()

    with pytest.raises(typer.Exit) as exc_info:
        await webinspector.catch_errors(command)()

    assert exc_info.value.exit_code == 1


def test_webinspector_js_shell_exits_nonzero_when_no_page_is_open(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeWebinspectorService(_AsyncContext):
        def __init__(self, lockdown: object) -> None:
            pass

        async def connect(self) -> None:
            pass

        async def close(self) -> None:
            pass

        async def get_open_application_pages(self, timeout: float) -> list[Any]:
            return []

    monkeypatch.setattr(webinspector, "WebinspectorService", FakeWebinspectorService)

    with pytest.raises(typer.Exit) as exc_info:
        webinspector.js_shell(service_provider=LOCKDOWN)

    assert exc_info.value.exit_code == 1


def test_arbitration_check_in_exits_nonzero_when_the_device_is_in_use(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeDtDeviceArbitration(_AsyncContext):
        def __init__(self, service_provider: object) -> None:
            pass

        async def check_in(self, hostname: str, force: bool = False) -> None:
            raise DeviceAlreadyInUseError({"message": "Device is already checked-in"})

    monkeypatch.setattr(arbitration, "DtDeviceArbitration", FakeDtDeviceArbitration)

    with pytest.raises(typer.Exit) as exc_info:
        arbitration.check_in(service_provider=LOCKDOWN, hostname="build-host")

    assert exc_info.value.exit_code == 1


@pytest.mark.parametrize(
    "error",
    [ExtractingStackshotError(), DvtException("could not start the core profile session")],
    ids=["no-stackshot", "dvt-error"],
)
def test_stackshot_exits_nonzero_when_none_was_captured(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    class FakeCoreProfileSessionTap(_AsyncContext):
        def __init__(self, dvt: object, config: object) -> None:
            pass

        async def get_stackshot(self) -> Any:
            raise error

    monkeypatch.setattr(core_profile_session, "DvtProvider", lambda _service_provider: _AsyncContext())
    monkeypatch.setattr(core_profile_session, "CoreProfileSessionTap", FakeCoreProfileSessionTap)

    with pytest.raises(typer.Exit) as exc_info:
        core_profile_session.stackshot(service_provider=LOCKDOWN)

    assert exc_info.value.exit_code == 1


def _fake_device_info(monkeypatch: pytest.MonkeyPatch, listings: dict[str, list[str]]) -> None:
    class FakeDeviceInfo(_AsyncContext):
        def __init__(self, dvt: object) -> None:
            pass

        async def ls(self, path: str) -> list[str]:
            if path not in listings:
                raise DvtDirListError()
            return listings[path]

    monkeypatch.setattr(dvt_cli, "DvtProvider", lambda _service_provider: _AsyncContext())
    monkeypatch.setattr(dvt_cli, "DeviceInfo", FakeDeviceInfo)


def test_dvt_ls_exits_nonzero_when_the_path_cannot_be_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_device_info(monkeypatch, {})

    with pytest.raises(typer.Exit) as exc_info:
        dvt_cli.ls(service_provider=LOCKDOWN, path="/no/such/dir")

    assert exc_info.value.exit_code == 1


def test_dvt_ls_recursive_still_succeeds_past_entries_it_cannot_list(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Only the path that was asked for decides the exit status; entries below it are logged and skipped
    _fake_device_info(monkeypatch, {"/var": ["db", "hosts"], "/var/db": []})

    dvt_cli.ls(service_provider=LOCKDOWN, path="/var", recursive=True)

    assert capsys.readouterr().out.splitlines() == ["/var/db", "/var/hosts"]


def test_save_pair_record_exits_nonzero_without_a_pair_record(tmp_path: Path) -> None:
    output = tmp_path / "pair_record.plist"

    with pytest.raises(typer.Exit) as exc_info:
        lockdown_cli.lockdown_save_pair_record(
            service_provider=cast(LockdownClient, SimpleNamespace(pair_record=None)), output=output
        )

    assert exc_info.value.exit_code == 1
    assert not output.exists()


def test_backup_change_password_exits_nonzero_when_encryption_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeMobilebackup2Service(_AsyncContext):
        def __init__(self, lockdown: object) -> None:
            pass

        async def get_will_encrypt(self) -> bool:
            return False

    monkeypatch.setattr(backup, "Mobilebackup2Service", FakeMobilebackup2Service)

    with pytest.raises(typer.Exit) as exc_info:
        backup.change_password(service_provider=LOCKDOWN, old_password="old", new_password="new")

    assert exc_info.value.exit_code == 1


def test_remote_pair_exits_nonzero_when_no_device_is_found(monkeypatch: pytest.MonkeyPatch) -> None:
    async def browse() -> list[Any]:
        return []

    monkeypatch.setattr(remote, "start_tunnel", object())
    monkeypatch.setattr(remote, "browse_remotepairing_manual_pairing", browse)

    with pytest.raises(typer.Exit) as exc_info:
        remote.cli_pair(name=None)

    assert exc_info.value.exit_code == 1


def test_debugserver_start_server_exits_nonzero_without_a_local_port_below_ios_17() -> None:
    service_provider = cast(LockdownServiceProvider, SimpleNamespace(product_version="16.7"))

    with pytest.raises(typer.Exit) as exc_info:
        debugserver.debugserver_start_server(service_provider=service_provider)

    assert exc_info.value.exit_code == 1


def _debugserver_lldb(target: str, product_version: str = "17.4") -> None:
    service_provider = cast(
        RemoteServiceDiscoveryService,
        SimpleNamespace(product_version=product_version, is_in_process_tunnel=False),
    )
    debugserver.debugserver_lldb(service_provider=service_provider, project_or_ipa_or_bundle_id=target)


def test_debugserver_lldb_exits_nonzero_below_ios_17() -> None:
    with pytest.raises(typer.Exit) as exc_info:
        _debugserver_lldb("com.example.app", product_version="16.7")

    assert exc_info.value.exit_code == 1


@pytest.mark.parametrize("name", ["App.xcodeproj", "App.ipa"])
def test_debugserver_lldb_exits_nonzero_when_the_target_is_missing(tmp_path: Path, name: str) -> None:
    with pytest.raises(typer.Exit) as exc_info:
        _debugserver_lldb(str(tmp_path / name))

    assert exc_info.value.exit_code == 1


def test_debugserver_lldb_exits_nonzero_when_the_build_has_no_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = tmp_path / "App.xcodeproj"
    project.mkdir()
    monkeypatch.setattr(
        debugserver.subprocess, "run", lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, stdout="")
    )

    with pytest.raises(typer.Exit) as exc_info:
        _debugserver_lldb(str(project))

    assert exc_info.value.exit_code == 1


@pytest.mark.parametrize("apps", [[], ["A.app", "B.app"]], ids=["no-app", "two-apps"])
def test_debugserver_lldb_exits_nonzero_unless_the_ipa_has_one_app(tmp_path: Path, apps: list[str]) -> None:
    ipa = tmp_path / "App.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/", "")
        for app in apps:
            archive.writestr(f"Payload/{app}/Info.plist", "")

    with pytest.raises(typer.Exit) as exc_info:
        _debugserver_lldb(str(ipa))

    assert exc_info.value.exit_code == 1


def test_debugserver_lldb_exits_nonzero_when_the_app_is_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeInstallationProxyService(_AsyncContext):
        def __init__(self, lockdown: object) -> None:
            pass

        async def get_apps(self, bundle_identifiers: list[str]) -> dict[str, Any]:
            return {}

    async def create_using_usbmux() -> object:
        return object()

    monkeypatch.setattr(debugserver, "create_using_usbmux", create_using_usbmux)
    monkeypatch.setattr(debugserver, "InstallationProxyService", FakeInstallationProxyService)

    with pytest.raises(typer.Exit) as exc_info:
        _debugserver_lldb("com.example.app")

    assert exc_info.value.exit_code == 1
