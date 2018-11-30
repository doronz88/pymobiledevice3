# -*- coding:utf-8 -*-
'''afc的测试用例
'''

import unittest

from pymobiledevice.usbmux.usbmux import USBMux
from pymobiledevice.lockdown import LockdownClient
from pymobiledevice.afc import AFCShell



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
        lockdown.startService("com.apple.afc")
        info = lockdown.allValues
        print(info)
        self.assertIsInstance(info, dict, '查询设备信息错误')

    def test_exec_cmd(self):
        udid = self._get_device()
        print('udid:%s' % udid)
        if udid is None:
            print("no real device found")
            return
        AFCShell().onecmd("Hello iPhone!")
