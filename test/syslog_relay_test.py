# -*- coding:utf-8 -*-
'''syslog_relay的测试用例
'''

import unittest

from pymobiledevice.usbmux.usbmux import USBMux
from pymobiledevice.syslog import Syslog


class ListDeviceTest(unittest.TestCase):

    def test_list_devices(self):
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        if len(mux.devices) == 0:
            print("no real device found")
            return
        syslog = Syslog()
        syslog.watch(10, '/tmp/sys.log', 'QQ')