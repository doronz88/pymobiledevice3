import logging
import re
from typing import Any, cast
from urllib.error import URLError

import pytest
import typer

from pymobiledevice3.cli import mounter
from pymobiledevice3.exceptions import (
    AlreadyMountedError,
    DeveloperDiskImageNotFoundError,
    StartServiceError,
    UnsupportedCommandError,
)
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.mobile_image_mounter import PersonalizedDdi

LOCKDOWN = cast(LockdownServiceProvider, object())


def _auto_mount_raising(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    async def auto_mount(*_args: Any, **_kwargs: Any) -> None:
        raise error

    monkeypatch.setattr(mounter, "auto_mount", auto_mount)
    monkeypatch.setattr(mounter, "uses_personalized_image", lambda _lockdown: True)


@pytest.mark.parametrize(
    "error",
    [
        PermissionError(13, "Permission denied", "/Applications/Xcode.app/.../DeviceSupport/15.8"),
        DeveloperDiskImageNotFoundError(),
        URLError("no route"),
    ],
    ids=["unwritable-xcode-path", "no-image-for-version", "download-failed"],
)
def test_auto_mount_exits_nonzero_when_it_could_not_mount(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    # Regression (#1985): these were only logged, so scripts saw exit status 0 for a failed mount
    _auto_mount_raising(monkeypatch, error)

    with pytest.raises(typer.Exit) as exc_info:
        mounter.mounter_auto_mount(service_provider=LOCKDOWN)

    assert exc_info.value.exit_code == 1


def test_auto_mount_succeeds_when_the_image_is_already_mounted(monkeypatch: pytest.MonkeyPatch) -> None:
    # The image the caller asked for is there: scripts that auto-mount on every run must not fail
    _auto_mount_raising(monkeypatch, AlreadyMountedError())

    mounter.mounter_auto_mount(service_provider=LOCKDOWN)


@pytest.mark.parametrize("error", [AlreadyMountedError(), UnsupportedCommandError()])
def test_explicit_mount_commands_exit_nonzero_on_a_handled_error(error: Exception) -> None:
    def command() -> None:
        raise error

    with pytest.raises(typer.Exit) as exc_info:
        mounter.catch_errors(command)()

    assert exc_info.value.exit_code == 1


def test_auto_mount_forwards_a_forced_image(monkeypatch: pytest.MonkeyPatch) -> None:
    forwarded: list[Any] = []

    async def auto_mount(*_args: Any, image: Any = None, **_kwargs: Any) -> None:
        forwarded.append(image)

    monkeypatch.setattr(mounter, "auto_mount", auto_mount)
    monkeypatch.setattr(mounter, "uses_personalized_image", lambda _lockdown: True)

    mounter.mounter_auto_mount(service_provider=LOCKDOWN, image=PersonalizedDdi.PERSONALIZED_DMG)

    assert forwarded == [PersonalizedDdi.PERSONALIZED_DMG]


def test_auto_mount_refuses_a_forced_image_below_ios_17(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mounter, "uses_personalized_image", lambda _lockdown: False)

    with pytest.raises(typer.Exit) as exc_info:
        mounter.mounter_auto_mount(service_provider=LOCKDOWN, image=PersonalizedDdi.CRYPTEX)

    assert exc_info.value.exit_code == 1


class _RefusingProvider:
    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> None:
        raise StartServiceError(name, "InvalidService")

    async def start_lockdown_service_without_checkin(self, name: str) -> None:
        raise StartServiceError(name, "InvalidService")


@pytest.mark.parametrize("provider_class", [LockdownServiceProvider, RemoteServiceDiscoveryService])
@pytest.mark.asyncio
async def test_developer_service_failure_hints_an_existing_mounter_command(
    provider_class: Any, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR), pytest.raises(StartServiceError):
        await provider_class.start_lockdown_developer_service(_RefusingProvider(), "com.apple.instruments.dtservicehub")

    hinted = re.findall(r"pymobiledevice3 mounter ([\w-]+)", caplog.text)
    assert hinted
    registered = {command.name for command in mounter.cli.registered_commands}
    assert set(hinted) <= registered
