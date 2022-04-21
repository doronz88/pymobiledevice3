from pymobiledevice3.services.screenshot import ScreenshotService

PNG_HEADER = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'
TIFF_HEADER = b'\x4D\x4D\x00\x2A'


def test_screenshot(lockdown):
    """
    Test that taking a screenshot returns a PNG.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    with ScreenshotService(lockdown) as screenshot_taker:
        screenshot = screenshot_taker.take_screenshot()
        assert screenshot.startswith(PNG_HEADER) or screenshot.startswith(TIFF_HEADER)
