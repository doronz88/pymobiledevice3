import logging

from pymobiledevice3.lockdown import LockdownClient

from pprint import *

SB_PORTRAIT = 1
SB_PORTRAIT_UPSIDE_DOWN = 2
SB_LANDSCAPE = 3
SB_LANDSCAPE_HOME_TO_LEFT = 4


class SBServicesService(object):
    service = None

    def __init__(self, lockdown=None, udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown if lockdown else LockdownClient(udid=udid)
        if not self.lockdown:
            raise Exception("Unable to start lockdown")
        self.start()

    def start(self):
        self.service = self.lockdown.start_service("com.apple.springboardservices")
        if not self.service:
            raise Exception("SBService init error : Could not start com.apple.springboardservices")

    def get_icon_state(self, format_version="2"):
        cmd = {"command": "getIconState"}
        if format_version:
            cmd["formatVersion"] = format_version

        self.service.send_plist(cmd)
        res = self.service.recv_plist()
        return res

    def set_icon_state(self, newstate=None):
        if newstate is None:
            newstate = {}
        cmd = {"command": "setIconState",
               "iconState": newstate}

        self.service.send_plist(cmd)

    def get_icon_pngdata(self, bid):
        cmd = {"command": "getIconPNGData",
               "bundleId": bid}

        self.service.send_plist(cmd)
        res = self.service.recv_plist()
        pngdata = res.get("pngData")
        if res:
            return pngdata
        return None

    def get_interface_orientation(self):
        cmd = {"command": "getInterfaceOrientation"}
        self.service.send_plist(cmd)
        res = self.service.recv_plist()
        return res.get('interfaceOrientation')

    def get_wallpaper_pngdata(self):
        cmd = {"command": "getHomeScreenWallpaperPNGData"}
        self.service.send_plist(cmd)
        res = self.service.recv_plist()
        if res:
            return res.get("pngData")
        return None


if __name__ == "__main__":
    s = SBServicesService()
    print(s.get_icon_pngdata("com.apple.weather"))
