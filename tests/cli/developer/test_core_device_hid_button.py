from pymobiledevice3.cli.developer.core_device import _NAMED_BUTTONS as CLI_BUTTONS
from pymobiledevice3.cli.developer.core_device import ButtonName
from pymobiledevice3.remote.core_device.screen_stream import _NAMED_BUTTONS as SERVE_WEB_BUTTONS

# SpringBoard's LockButton long-press recognizer fires ~0.4 s after the button goes down and opens Siri
LOCK_LONG_PRESS_SECONDS = 0.4


def test_lock_press_is_a_tap() -> None:
    assert ButtonName.LOCK.usage()[2] < LOCK_LONG_PRESS_SECONDS
    assert SERVE_WEB_BUTTONS["lock"][2] < LOCK_LONG_PRESS_SECONDS


def test_serve_web_buttons_mirror_the_cli() -> None:
    assert {name.value: usage for name, usage in CLI_BUTTONS.items()} == SERVE_WEB_BUTTONS
