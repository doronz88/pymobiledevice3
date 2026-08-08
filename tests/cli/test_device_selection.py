from types import SimpleNamespace

import pytest
import typer

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
