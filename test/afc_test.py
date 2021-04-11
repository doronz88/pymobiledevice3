# -*- coding:utf-8 -*-
'''afc test case
'''

import unittest

from pymobiledevice3.usbmux.usbmux import USBMux
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.afc import AFCShell



class AfcTest(unittest.TestCase):

    def _get_device(self):
        retry_times = 5
        udid = None
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        while retry_times > 0:
            if len(mux.devices) > 0:
                udid = mux.devices[0].serial
                break
            mux.process(0.5)
            retry_times -= 1
        return udid

    def test_get_device_info(self):
        udid = self._get_device()
        print('udid:%s' % udid)
        if udid is None:
            print("no real device found")
            return
        lockdown = LockdownClient(udid)
        lockdown.start_service("com.apple.afc")
        info = lockdown.allValues
        print(info)
        self.assertIsInstance(info, dict, 'Query device information error')

    def test_exec_cmd(self):
        udid = self._get_device()
        print('udid:%s' % udid)
        if udid is None:
            print("no real device found")
            return
        AFCShell().onecmd("Hello iPhone!")
