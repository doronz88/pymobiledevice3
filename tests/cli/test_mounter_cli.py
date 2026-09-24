from typing import Any, cast
from urllib.error import URLError

import pytest
import typer

from pymobiledevice3.cli import mounter
from pymobiledevice3.exceptions import AlreadyMountedError, DeveloperDiskImageNotFoundError, UnsupportedCommandError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

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
