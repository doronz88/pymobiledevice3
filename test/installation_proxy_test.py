# -*- coding:utf-8 -*-
'''installation_proxy的测试用例
'''

import unittest
import time
import os

from pymobiledevice.usbmux.usbmux import USBMux
from pymobiledevice.lockdown import LockdownClient
from pymobiledevice.afc import AFCClient

class InstallationProxyTest(unittest.TestCase):

    def setUp(self):
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        if len(mux.devices) == 0:
            print("no real device found")
            self.no_device = True
            return
        self.udid = mux.devices[0].serial
        self.lockdownclient = LockdownClient(self.udid)
        self.service = self.lockdownclient.startService("com.apple.mobile.installation_proxy")

    def wait_completion(self, handler=None, *args):
        while True:
            z = self.service.recvPlist()
            print(type(z), z)
            if not z:
                break
            completion = z.get("PercentComplete")
            if completion:
                if handler:
                    handler(completion, *args)
                print("%s: %s%% Complete" % (z.get("Status"), completion))
            else:
                if z.get("Status") == "Complete" or ("Status" not in z and "CFBundleIdentifier" in z):
                    return (True, "")
                else:
                    return (False, z.get("ErrorDescription"))

    def test_install_app(self):
        if self.no_device:
            return
        ipa_path = os.path.join(os.path.expanduser("~"), "Downloads/app/DemoApp.ipa")
        tmp_ipa = "/t%d.ipa" % time.time()
        with open(ipa_path, "rb") as f:
            ipa_content = f.read()
            afc = AFCClient(self.lockdownclient)
            afc.set_file_contents(tmp_ipa, ipa_content)
            print("上传完毕")
        print("开始安装")
        cmd = {"Command":"Install", "PackagePath": tmp_ipa}
        self.lockdownclient = LockdownClient(self.udid)
        self.service = self.lockdownclient.startService("com.apple.mobile.installation_proxy")
        self.service.sendPlist(cmd)
        result, err = self.wait_completion()
        self.assertTrue(result, 'install_app failed: %s' % err)

    def test_uninstall_app(self):
        if self.no_device:
            return
        bundle_id = "com.tencent.qt4i.demo"
        cmd = {"Command": "Uninstall", "ApplicationIdentifier": bundle_id}
        self.service.sendPlist(cmd)
        result, err = self.wait_completion()
        self.assertTrue(result, 'uninstall_app failed: %s' % err)

    def test_apps_info(self):
        if self.no_device:
            return
        self.service.sendPlist({"Command": "Lookup"})
        print(self.service.recvPlist())

    def test_list_apps(self, app_type='user'):
        if self.no_device:
            return
        options = {}
        if app_type == 'system':
            options["ApplicationType"] = "System"
        elif app_type == 'user':
            options["ApplicationType"] = "User"
        options["ReturnAttributes"] = ["CFBundleIdentifier",
                                       "CFBundleName", ]
        self.service.sendPlist({"Command": "Browse", "ClientOptions": options})
        apps = []
        while True:
            z = self.service.recvPlist()
            if z.get("Status") == "BrowsingApplications":
                apps.extend(z["CurrentList"])
            elif z.get("Status") == "Complete":
                break
            else:
                raise Exception(z.get("ErrorDescription"))
        print(apps)

    def tearDown(self):
        if not self.no_device and self.service:
            self.service.close()