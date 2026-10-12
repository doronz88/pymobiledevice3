from contextlib import asynccontextmanager
from inspect import unwrap

import pytest

from pymobiledevice3.cli.developer import core_device
from pymobiledevice3.remote.core_device.hid_service import ASCII_TO_HID, KEY_LEFT_SHIFT


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
