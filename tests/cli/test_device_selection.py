from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
import typer

from pymobiledevice3.cli import cli_common
from pymobiledevice3.cli.cli_common import prompt_device_list

pytestmark = [pytest.mark.cli]


def test_prompt_without_tty_fails_fast_with_candidates(capsys: pytest.CaptureFixture[str]) -> None:
    # pytest runs without a TTY on stdin/stdout, which is exactly the guarded scenario
    devices = [SimpleNamespace(udid="udid-a"), SimpleNamespace(udid="udid-b")]
    with pytest.raises(typer.Exit) as exc_info:
        prompt_device_list(devices)
    assert exc_info.value.exit_code == 1
    err = capsys.readouterr().err
    assert "interactive selection requires a terminal" in err
    assert "udid-a" in err
    assert "udid-b" in err
    assert "PYMOBILEDEVICE3_UDID" in err


def test_prompt_device_closes_the_devices_not_chosen(monkeypatch: pytest.MonkeyPatch) -> None:
    lockdowns = [Mock(close=AsyncMock()) for _ in range(3)]
    monkeypatch.setattr(cli_common, "prompt_device_list", lambda devices: devices[1])
    assert cli_common._prompt_device(lockdowns) is lockdowns[1]
    assert [lockdown.close.await_count for lockdown in lockdowns] == [1, 0, 1]


def test_prompt_device_closes_every_device_when_the_prompt_is_aborted(monkeypatch: pytest.MonkeyPatch) -> None:
    lockdowns = [Mock(close=AsyncMock()) for _ in range(2)]

    def abort(devices: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_common, "prompt_device_list", abort)
    with pytest.raises(KeyboardInterrupt):
        cli_common._prompt_device(lockdowns)
    assert [lockdown.close.await_count for lockdown in lockdowns] == [1, 1]


@pytest.mark.parametrize(
    "dependency,autopair",
    [
        (lambda: cli_common.any_service_provider_dependency(rsd_service_provider=None, mobdev2=False), True),
        (lambda: cli_common.no_autopair_service_provider_dependency(rsd_service_provider=None), False),
    ],
)
def test_multiple_usb_devices_prompt(monkeypatch: pytest.MonkeyPatch, dependency: Any, autopair: bool) -> None:
    devices = [SimpleNamespace(serial="udid-a"), SimpleNamespace(serial="udid-b")]
    created: list[dict[str, Any]] = []

    async def select_devices_by_connection_type(**kwargs: Any) -> list[SimpleNamespace]:
        return devices

    async def create_using_usbmux(**kwargs: Any) -> Mock:
        created.append(kwargs)
        return Mock(udid=kwargs["serial"], close=AsyncMock())

    monkeypatch.setattr(cli_common.usbmuxd, "select_devices_by_connection_type", select_devices_by_connection_type)
    monkeypatch.setattr(cli_common, "create_using_usbmux", create_using_usbmux)
    monkeypatch.setattr(cli_common, "prompt_device_list", lambda lockdowns: lockdowns[1])

    assert dependency().udid == "udid-b"
    assert [kwargs["autopair"] for kwargs in created] == [autopair, autopair]
