from typing import Any, cast

import pytest

from pymobiledevice3.cli import restore as restore_cli
from pymobiledevice3.exceptions import ConnectionTerminatedError

pytestmark = [pytest.mark.cli]


async def test_update_failure_is_left_to_the_cli_error_handler(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FailingRestore:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def update(self) -> None:
            raise ConnectionTerminatedError()

    monkeypatch.setattr(restore_cli, "Restore", FailingRestore)
    with pytest.raises(ConnectionTerminatedError):
        await restore_cli.restore_update_task(cast(Any, None), cast(Any, None), None, erase=False, ignore_fdr=False)
    # __main__ turns it into a one-line message; a traceback here would come first
    assert "Traceback" not in capsys.readouterr().err
