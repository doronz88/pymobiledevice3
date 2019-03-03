# -*- coding:utf-8 -*-
'''house_arrest的测试用例
'''

import unittest
import os
import pprint

from pymobiledevice.usbmux.usbmux import USBMux
from pymobiledevice.lockdown import LockdownClient
from pymobiledevice.afc import AFCShell
from pymobiledevice.afc import AFCClient


class HouseArrestTest(unittest.TestCase):

    def setUp(self):
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        if len(mux.devices) == 0:
            print("no real device found")
            self.no_device = True
            return
        udid = mux.devices[0].serial
        lockdown_client = LockdownClient(udid)
        self.service = lockdown_client.startService("com.apple.mobile.house_arrest")
        self.service.sendPlist({"Command": "VendContainer", "Identifier": "com.tencent.mqq"})
        status = self.service.recvPlist()
        if 'Error' in status and status['Error'] == "ApplicationLookupFailed":
            raise RuntimeWarning('ApplicationLookupFailed')
        if 'Status' in status and status['Status'] != 'Complete':
            raise RuntimeWarning('House arrest service launch failed')
        self.afc = AFCClient(lockdown_client, service=self.service)
        self.afc_shell = AFCShell(client=self.afc)

    def test_list_files_in_sandbox(self):
        if self.no_device:
            return
        sandbox_tree =[]
        file_path = '/Documents'
        for l in self.afc.read_directory(file_path):
            if l not in ('.', '..'):
                tmp_dict = {}
                tmp_dict['path'] = os.path.join(file_path, l)
                info = self.afc.get_file_info(tmp_dict['path'])
                tmp_dict['is_dir'] = (info is not None and info['st_ifmt'] == 'S_IFDIR')
                sandbox_tree.append(tmp_dict)
        pprint.pprint(sandbox_tree)

    def test_push_file_to_sandbox(self):
        if self.no_device:
            return
        data = b"hello sandbox!"
        self.afc.set_file_contents('/Documents/test.log', data)

    def test_pull_file_from_sandbox(self):
        if self.no_device:
            return
        data = b"hello sandbox!"
        content = self.afc.get_file_contents('/Documents/test.log')
        print(content)

    def test_remove_file_in_sandbox(self):
        if self.no_device:
            return
        self.afc_shell.do_rm('/Documents/test.log')

    def tearDown(self):
        if not self.no_device and self.service:
            self.service.close()