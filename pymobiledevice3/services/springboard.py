from enum import IntEnum
from typing import List, Optional

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class InterfaceOrientation(IntEnum):
    PORTRAIT = 1
    PORTRAIT_UPSIDE_DOWN = 2
    LANDSCAPE = 3
    LANDSCAPE_HOME_TO_LEFT = 4


class SpringBoardServicesService(LockdownService):
    RSD_SERVICE_NAME = 'com.apple.springboardservices.shim.remote'
    SERVICE_NAME = 'com.apple.springboardservices'

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def get_icon_state(self, format_version: str = '2') -> List:
        cmd = {'command': 'getIconState'}
        if format_version:
            cmd['formatVersion'] = format_version
        return self.service.send_recv_plist(cmd)

    def set_icon_state(self, newstate: Optional[List] = None) -> None:
        if newstate is None:
            newstate = {}
        self.service.send_plist({'command': 'setIconState', 'iconState': newstate})
        self.service.recv_prefixed()

    def get_icon_pngdata(self, bundle_id: str) -> bytes:
        return self.service.send_recv_plist({'command': 'getIconPNGData',
                                             'bundleId': bundle_id}).get('pngData')

    def get_interface_orientation(self) -> InterfaceOrientation:
        res = self.service.send_recv_plist({'command': 'getInterfaceOrientation'})
        return InterfaceOrientation(res.get('interfaceOrientation'))

    def get_wallpaper_pngdata(self) -> bytes:
        return self.service.send_recv_plist({'command': 'getHomeScreenWallpaperPNGData'}).get('pngData')
