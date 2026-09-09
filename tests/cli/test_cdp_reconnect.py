"""The CDP bridge must fail with the device error it hit, so `--reconnect` can act on it."""

from typing import Any, Optional, cast

import pytest

from pymobiledevice3.cli import webinspector as webinspector_cli
from pymobiledevice3.exceptions import ConnectionTerminatedError


class _RefusingInspector:
    """A WebinspectorService stand-in that fails to connect the way a rebooting device makes it."""

    def __init__(self, lockdown: Any) -> None:
        self.on_connection_lost: Optional[Any] = None
        self.trace: Optional[Any] = None

    async def connect(self) -> None:
        raise ConnectionTerminatedError


async def test_a_device_error_starting_the_bridge_reaches_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """uvicorn runs the ASGI lifespan itself and turns a failure there into `sys.exit(3)`, which
    asyncio re-raises out of the event loop - so a device that is still rebooting when the bridge
    starts used to kill the process (exit code 3) instead of reaching the top-level handler that
    `--reconnect` retries from. Connecting to the device happens before uvicorn owns the failure."""
    monkeypatch.setattr(webinspector_cli, "WebinspectorService", _RefusingInspector)
    monkeypatch.setattr(webinspector_cli, "find_chrome", lambda chrome: None)

    # `cdp` is the sync wrapper Typer registers; `__wrapped__` is the coroutine underneath.
    cdp = cast(Any, webinspector_cli.cdp).__wrapped__
    with pytest.raises(ConnectionTerminatedError):
        await cdp(cast(Any, None), host="127.0.0.1", port=0)
