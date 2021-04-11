#!/usr/bin/env python3
import logging

from pymobiledevice3.lockdown import LockdownClient


class ScreenshotService(object):
    def __init__(self, lockdown=None, service_name='com.apple.mobile.screenshotr', udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown if lockdown else LockdownClient(udid=udid)
        self.service = self.lockdown.start_service(service_name)
        DLMessageVersionExchange = self.service.recv_plist()
        version_major = DLMessageVersionExchange[1]
        self.service.send_plist(["DLMessageVersionExchange", "DLVersionsOk", version_major])
        DLMessageDeviceReady = self.service.recv_plist()
        if DLMessageDeviceReady[0] != 'DLMessageDeviceReady':
            raise Exception('Screenshotr didnt return ready state')

    def stop_session(self):
        self.service.close()

    def take_screenshot(self):
        self.service.send_plist(['DLMessageProcessMessage', {'MessageType': 'ScreenShotRequest'}])
        res = self.service.recv_plist()

        assert len(res) == 2
        assert res[0] == "DLMessageProcessMessage"

        if res[1].get('MessageType') == 'ScreenShotReply':
            return res[1]['ScreenShotData']
        return None

