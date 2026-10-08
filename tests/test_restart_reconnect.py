from typing import Any

import pytest

from pymobiledevice3 import usbmux
from pymobiledevice3.cli import diagnostics
from pymobiledevice3.usbmux import MuxDevice, wait_for_device_detach

UDID = "00008150-001074523440401C"


def _listing(monkeypatch: pytest.MonkeyPatch, listings: list[list[str]]) -> list[int]:
    """Make usbmuxd report ``listings`` on successive polls (the last one repeats)."""
    polls: list[int] = []

    async def list_devices(usbmux_address: Any = None) -> list[MuxDevice]:
        serials = listings[min(len(polls), len(listings) - 1)]
        polls.append(len(polls))
        return [MuxDevice(index, serial, "USB") for index, serial in enumerate(serials)]

    async def no_sleep(delay: float) -> None:
        pass

    monkeypatch.setattr(usbmux, "list_devices", list_devices)
    monkeypatch.setattr(usbmux.asyncio, "sleep", no_sleep)
    return polls


@pytest.mark.asyncio
async def test_wait_for_device_detach_polls_until_the_device_is_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    polls = _listing(monkeypatch, [[UDID, "OTHER"], [UDID, "OTHER"], ["OTHER"]])

    assert await wait_for_device_detach(UDID) is True

    assert len(polls) == 3


@pytest.mark.asyncio
async def test_wait_for_device_detach_gives_up_after_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _listing(monkeypatch, [[UDID]])

    assert await wait_for_device_detach(UDID, timeout=0) is False


@pytest.mark.asyncio
async def test_restart_waits_for_the_device_to_leave_before_reconnecting(monkeypatch: pytest.MonkeyPatch) -> None:
    # The device is still connected right after it accepts the restart; reconnecting then would
    # report it back before it has gone down.
    events: list[str] = []

    async def fake_wait_for_device_detach(serial: str, timeout: Any = None) -> bool:
        events.append(f"detached {serial}")
        return True

    class FakeLockdown:
        async def close(self) -> None:
            events.append("closed")

    async def fake_retry_create_using_usbmux(retry_timeout: Any = None, **kwargs: Any) -> FakeLockdown:
        events.append(f"reconnected {kwargs['serial']}")
        return FakeLockdown()

    monkeypatch.setattr(diagnostics, "wait_for_device_detach", fake_wait_for_device_detach)
    monkeypatch.setattr(diagnostics, "retry_create_using_usbmux", fake_retry_create_using_usbmux)

    await diagnostics.wait_for_restart(UDID)

    assert events == [f"detached {UDID}", f"reconnected {UDID}", "closed"]
