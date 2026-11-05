"""The webinspector commands must honor their own options."""

import inspect
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.cli import webinspector as webinspector_cli


class _Stop(Exception):
    pass


class _RecordingInspector:
    """A WebinspectorService stand-in that records how long launch is willing to wait for Safari."""

    open_app_timeout: Optional[float] = None

    def __init__(self, lockdown: Any) -> None:
        pass

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def __aenter__(self) -> "_RecordingInspector":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def open_app(self, bundle: str, timeout: float = 3) -> Any:
        type(self).open_app_timeout = timeout
        raise _Stop


async def test_launch_waits_for_safari_as_long_as_it_is_told(monkeypatch: pytest.MonkeyPatch) -> None:
    """`--timeout` was accepted and then ignored: Safari always got the 3 s default."""
    monkeypatch.setattr(webinspector_cli, "WebinspectorService", _RecordingInspector)

    launch = inspect.unwrap(cast(Any, webinspector_cli.launch))
    with pytest.raises(_Stop):
        await launch(cast(Any, None), url="https://example.org/", timeout=12.5)

    assert _RecordingInspector.open_app_timeout == 12.5


@pytest.mark.parametrize("shell_class", [webinspector_cli.AutomationJsShell, webinspector_cli.InspectorJsShell])
async def test_js_shell_waits_for_safari_as_long_as_it_is_told(
    monkeypatch: pytest.MonkeyPatch, shell_class: type[webinspector_cli.JsShell]
) -> None:
    monkeypatch.setattr(webinspector_cli, "WebinspectorService", _RecordingInspector)
    _RecordingInspector.open_app_timeout = None

    with pytest.raises(_Stop):
        async with shell_class.create(cast(Any, None), 12.5, True, webinspector_cli.SAFARI):
            pass

    assert _RecordingInspector.open_app_timeout == 12.5
