import asyncio

import pytest

from pymobiledevice3.exceptions import MuxException
from pymobiledevice3.tunneld import server as tunneld_server


class _FakeMux:
    """Minimal stand-in for a usbmux connection used by monitor_usbmux_task."""

    def __init__(self, on_receive) -> None:
        self._on_receive = on_receive
        self.devices = []
        self.closed = False

    async def listen(self) -> None:
        return None

    async def receive_device_state_update(self) -> None:
        await self._on_receive()

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_monitor_usbmux_task_reconnects_after_socket_broken(monkeypatch):
    """Regression for issue #1742: a dropped usbmuxd listen socket raises
    MuxException("socket connection broken"). The monitor task must catch it and
    reconnect instead of dying, otherwise the tunnel never auto-recovers after a
    device replug/reboot (notably on Linux)."""
    # make the reconnect backoff instant
    monkeypatch.setattr(tunneld_server, "USBMUX_INTERVAL", 0)

    create_calls = 0

    async def fake_receive() -> None:
        # first connection: usbmuxd drops the socket
        raise MuxException("socket connection broken")

    async def fake_create_mux(usbmux_address=None):
        nonlocal create_calls
        create_calls += 1
        if create_calls >= 2:
            # the task successfully reconnected; stop the loop cleanly.
            # CancelledError is caught by the task's own handler, which breaks the loop.
            raise asyncio.CancelledError()
        return _FakeMux(fake_receive)

    monkeypatch.setattr(tunneld_server.usbmux, "create_mux", fake_create_mux)

    core = tunneld_server.TunneldCore(wifi_monitor=False, usb_monitor=False, usbmux_monitor=True, mobdev2_monitor=False)

    # The task should swallow the MuxException, sleep, attempt create_mux again, and
    # then return cleanly once cancelled (rather than dying on the MuxException).
    await core.monitor_usbmux_task()

    assert create_calls >= 2, "monitor task did not reconnect after socket connection broken"
