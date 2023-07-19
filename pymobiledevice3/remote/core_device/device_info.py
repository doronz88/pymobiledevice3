from typing import List, Mapping

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class DeviceInfoService(CoreDeviceService):
    """
    Query device information
    """

    SERVICE_NAME = 'com.apple.coredevice.deviceinfo'

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    def get_device_info(self) -> Mapping:
        """
        Get device information
        """
        return self.invoke('com.apple.coredevice.feature.getdeviceinfo', {})

    def query_mobilegestalt(self, keys: List[str]) -> Mapping:
        """
        Query MobileGestalt.

        Can only be performed to specific devices
        """
        return self.invoke('com.apple.coredevice.feature.querymobilegestalt', {'keys': keys})

    def get_lockstate(self) -> Mapping:
        """
        Get lockstate
        """
        return self.invoke('com.apple.coredevice.feature.getlockstate', {})
