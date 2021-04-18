# -*- coding:utf-8 -*-
"""
screenshotr test case
"""

from pymobiledevice3.services.screenshot import ScreenshotService

PNG_HEADER = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'


def test_screenshot(lockdown):
    """
    Test that taking a screenshot returns a PNG.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    screenshot_taker = ScreenshotService(lockdown)
    screenshot = screenshot_taker.take_screenshot()
    assert screenshot.startswith(PNG_HEADER)
