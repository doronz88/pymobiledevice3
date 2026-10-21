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
