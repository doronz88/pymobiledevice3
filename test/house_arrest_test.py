# -*- coding:utf-8 -*-
'''house_arrest test case
'''

import unittest
import os
import pprint

from pymobiledevice.usbmux.usbmux import USBMux
from pymobiledevice.lockdown import LockdownClient
from pymobiledevice.afc import AFCShell
from pymobiledevice.afc import AFCClient
from pymobiledevice.house_arrest import HouseArrestClient

class HouseArrestTest(unittest.TestCase):

    def setUp(self):
        self.no_device = False
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        if len(mux.devices) == 0:
            print("no real device found")
            self.no_device = True
            return
        udid = mux.devices[0].serial
        self.house_arrest_client = HouseArrestClient(udid)
        app_bundle_id = "com.gotohack.testapp"
        result = self.house_arrest_client.send_command(app_bundle_id)
        if not result:
            raise RuntimeError("Launching HouseArrest failed for app:%s" % app_bundle_id)

    def test_list_files_in_sandbox(self):
        if self.no_device:
            return
        sandbox_tree =[]
        file_path = '/Documents'
        for l in self.house_arrest_client.read_directory(file_path):
            if l not in ('.', '..'):
                tmp_dict = {}
                tmp_dict['path'] = os.path.join(file_path, l)
                info = self.house_arrest_client.get_file_info(tmp_dict['path'])
                tmp_dict['is_dir'] = (info is not None and info['st_ifmt'] == 'S_IFDIR')
                sandbox_tree.append(tmp_dict)
        pprint.pprint(sandbox_tree)

    def test_push_file_to_sandbox(self):
        if self.no_device:
            return
        data = b"hello sandbox!"
        self.house_arrest_client.set_file_contents('/Documents/test.log', data)

    def test_pull_file_from_sandbox(self):
        if self.no_device:
            return
        content = self.house_arrest_client.get_file_contents('/Documents/test.log')
        print(content)

    def test_remove_file_in_sandbox(self):
        if self.no_device:
            return
        shell = AFCShell(client=self.house_arrest_client)
        shell.do_rm('/Documents/test.log')

    def tearDown(self):
        if not self.no_device and self.house_arrest_client:
            self.house_arrest_client.service.close()
