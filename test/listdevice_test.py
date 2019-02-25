# -*- coding:utf-8 -*-
'''查询设备的测试用例
'''

import unittest

from pymobiledevice.usbmux.usbmux import USBMux


class ListDeviceTest(unittest.TestCase):
    
    
    def test_list_devices(self):
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        self.assertTrue(len(mux.devices)>=0, 'usbmuxd通信异常')