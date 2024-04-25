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

    async def get_device_info(self) -> Mapping:
        """
        Get device information
        """
        return await self.invoke('com.apple.coredevice.feature.getdeviceinfo', {})

    async def get_display_info(self) -> Mapping:
        """
        Get display information
        """
        return await self.invoke('com.apple.coredevice.feature.getdisplayinfo', {})

    async def query_mobilegestalt(self, keys: List[str]) -> Mapping:
        """
        Query MobileGestalt.

        Can only be performed to specific devices
        """
        return await self.invoke('com.apple.coredevice.feature.querymobilegestalt', {'keys': keys})

    async def get_lockstate(self) -> Mapping:
        """
        Get lockstate
        """
        return await self.invoke('com.apple.coredevice.feature.getlockstate', {})
