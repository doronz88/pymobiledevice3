# -*- coding:utf-8 -*-
'''screenshotr test case
'''

import unittest
import tempfile

from pymobiledevice3.usbmux.usbmux import USBMux
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.screenshot_service import ScreenshotService


class ScreenshotrTest(unittest.TestCase):

    def test_screenshot(self):
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        if len(mux.devices) == 0:
            print("no real device found")
            return
        udid = mux.devices[0].serial
        lockdownclient = LockdownClient(udid)
        tiff_file = tempfile.NamedTemporaryFile(suffix='.tiff')
        tiff_file_path = tiff_file.name
        screenshot = ScreenshotService(lockdownclient)
        data = screenshot.take_screenshot()
        with open(tiff_file_path, "wb") as fd:
            fd.write(data)
        screenshot.stop_session()
        tiff_file.close()
