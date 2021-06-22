import logging
from enum import IntEnum

from pymobiledevice3.lockdown import LockdownClient


class InterfaceOrientation(IntEnum):
    PORTRAIT = 1
    PORTRAIT_UPSIDE_DOWN = 2
    LANDSCAPE = 3
    LANDSCAPE_HOME_TO_LEFT = 4


class SpringBoardServicesService(object):
    SERVICE_NAME = 'com.apple.springboardservices'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)

    def get_icon_state(self, format_version='2'):
        cmd = {'command': 'getIconState'}
        if format_version:
            cmd['formatVersion'] = format_version

        return self.service.send_recv_plist(cmd)

    def set_icon_state(self, newstate=None):
        if newstate is None:
            newstate = {}
        cmd = {'command': 'setIconState',
               'iconState': newstate}

        self.service.send_recv_plist(cmd)

    def get_icon_pngdata(self, bid):
        cmd = {'command': 'getIconPNGData',
               'bundleId': bid}

        return self.service.send_recv_plist(cmd).get('pngData')

    def get_interface_orientation(self):
        cmd = {'command': 'getInterfaceOrientation'}
        self.service.send_plist(cmd)
        res = self.service.recv_plist()
        return InterfaceOrientation(res.get('interfaceOrientation'))

    def get_wallpaper_pngdata(self):
        cmd = {'command': 'getHomeScreenWallpaperPNGData'}
        return self.service.send_recv_plist(cmd).get('pngData')
