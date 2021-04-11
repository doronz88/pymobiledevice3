# -*- coding:utf-8 -*-
'''syslog_relay test case
'''

import unittest

from pymobiledevice3.usbmux.usbmux import USBMux
from pymobiledevice3.syslog_service import SyslogService


class ListDeviceTest(unittest.TestCase):

    def test_list_devices(self):
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        if len(mux.devices) == 0:
            print("no real device found")
            return
        syslog = SyslogService()
        syslog.watch(10, '/tmp/sys.log', 'QQ')
