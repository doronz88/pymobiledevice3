import typing
from enum import IntEnum

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class InterfaceOrientation(IntEnum):
    PORTRAIT = 1
    PORTRAIT_UPSIDE_DOWN = 2
    LANDSCAPE = 3
    LANDSCAPE_HOME_TO_LEFT = 4


class SpringBoardServicesService(BaseService):
    SERVICE_NAME = 'com.apple.springboardservices'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME)

    def get_icon_state(self, format_version: str = '2'):
        cmd = {'command': 'getIconState'}
        if format_version:
            cmd['formatVersion'] = format_version

        return self.service.send_recv_plist(cmd)

    def set_icon_state(self, newstate: typing.Mapping = None):
        if newstate is None:
            newstate = {}
        cmd = {'command': 'setIconState',
               'iconState': newstate}

        self.service.send_recv_plist(cmd)

    def get_icon_pngdata(self, bundle_id: str):
        cmd = {'command': 'getIconPNGData',
               'bundleId': bundle_id}

        return self.service.send_recv_plist(cmd).get('pngData')

    def get_interface_orientation(self):
        cmd = {'command': 'getInterfaceOrientation'}
        self.service.send_plist(cmd)
        res = self.service.recv_plist()
        return InterfaceOrientation(res.get('interfaceOrientation'))

    def get_wallpaper_pngdata(self):
        cmd = {'command': 'getHomeScreenWallpaperPNGData'}
        return self.service.send_recv_plist(cmd).get('pngData')
