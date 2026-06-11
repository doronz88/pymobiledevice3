from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class LocationService(CoreDeviceService):
    """
    Simulate the device's location.
    """

    SERVICE_NAME = "com.apple.coredevice.locationservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def available_location_scenarios(self) -> dict:
        """List the device's built-in simulation scenarios."""
        return await self.invoke(
            "com.apple.coredevice.feature.simulatelocation",
            {},
            action_identifier="com.apple.coredevice.action.availablelocationscenarios",
        )
