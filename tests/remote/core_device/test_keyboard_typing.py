from contextlib import asynccontextmanager
from inspect import unwrap

import pytest

from pymobiledevice3.cli.developer import core_device
from pymobiledevice3.remote.core_device import hid_service
from pymobiledevice3.remote.core_device.hid_service import ASCII_TO_HID, KEY_BACKSPACE, KEY_LEFT, KEY_LEFT_SHIFT
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["abc", "ABC", "aBc", "a!A", "AA"])
async def test_shift_is_held_before_shifted_key_down(monkeypatch, text):
    class Keyboard:
        def __init__(self):
            self.held = set()
            self.key_downs = []

        async def create_keyboard_service(self):
            return 1

        async def send_keyboard(self, service_id, usages):
            assert service_id == 1
            for usage in set(usages) - self.held - {KEY_LEFT_SHIFT}:
                self.key_downs.append((usage, KEY_LEFT_SHIFT in self.held))
            self.held = set(usages)

    keyboard = Keyboard()

    @asynccontextmanager
    async def session(provider):
        yield keyboard

    monkeypatch.setattr(core_device, "touch_session", session)
    await unwrap(core_device.core_device_universal_hid_service_type)(None, text, char_delay=0, inter_delay=0)
    assert keyboard.key_downs == [ASCII_TO_HID[ch] for ch in text]
    assert not keyboard.held


@pytest.mark.asyncio
async def test_create_keyboard_service_lets_the_keyboard_attach_before_returning(monkeypatch):
    """Every caller sends its first report as soon as this returns, so the pause belongs here."""
    events = []

    class Transport:
        async def send_receive_request(self, request):
            assert "createService" in request["payload"]
            events.append("createService")
            return {"serviceID": 7}

    async def sleep(delay):
        events.append(("sleep", delay))

    monkeypatch.setattr(hid_service.asyncio, "sleep", sleep)
    service = hid_service.UniversalHIDServiceService(RemoteServiceDiscoveryService(("127.0.0.1", 0)))
    monkeypatch.setattr(service, "_service", Transport())

    assert await service.create_keyboard_service() == 7
    assert events == ["createService", ("sleep", hid_service.KEYBOARD_ATTACH_SETTLE_SECONDS)]


@pytest.mark.asyncio
async def test_type_does_not_pause_on_its_own(monkeypatch):
    """`type` relies on create_keyboard_service for the attach pause instead of adding one."""
    sleeps = []

    class Keyboard:
        async def create_keyboard_service(self):
            return 1

        async def send_keyboard(self, service_id, usages):
            pass

    @asynccontextmanager
    async def session(provider):
        yield Keyboard()

    async def sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(core_device, "touch_session", session)
    monkeypatch.setattr(core_device.asyncio, "sleep", sleep)
    await unwrap(core_device.core_device_universal_hid_service_type)(None, "a", char_delay=0.5, inter_delay=0.25)
    assert sleeps == [0.5, 0.25]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "usage", "count"), [("backspace", KEY_BACKSPACE, 3), ("left", KEY_LEFT, 1)])
async def test_key_presses_the_named_key_count_times(monkeypatch, name, usage, count):
    reports = []

    class Keyboard:
        async def create_keyboard_service(self):
            return 1

        async def send_keyboard(self, service_id, usages):
            assert service_id == 1
            reports.append(tuple(usages))

    @asynccontextmanager
    async def session(provider):
        yield Keyboard()

    monkeypatch.setattr(core_device, "touch_session", session)
    await unwrap(core_device.core_device_universal_hid_service_key)(
        None, core_device.KeyName(name), count=count, char_delay=0, inter_delay=0
    )
    assert reports == [(usage,), ()] * count
