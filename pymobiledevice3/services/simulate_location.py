import struct

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.instruments.location_simulation_base import LocationSimulationBase
from pymobiledevice3.services.lockdown_service import LockdownService


class DtSimulateLocation(LockdownService, LocationSimulationBase):
    """
    Client for the `com.apple.dt.simulatelocation` developer service.

    Overrides the device's reported GPS location with a fixed coordinate, or clears any
    previously set override. A fresh lockdown developer service connection is opened for
    each command.
    """

    SERVICE_NAME = "com.apple.dt.simulatelocation"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        LockdownService.__init__(self, lockdown, self.SERVICE_NAME)
        LocationSimulationBase.__init__(self)

    async def clear(self) -> None:
        """Stop simulating a location and restore the device's real location."""
        service = await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        await service.sendall(struct.pack(">I", 1))

    async def set(self, latitude: float, longitude: float) -> None:
        """
        Start simulating the given location.

        :param latitude: Latitude in decimal degrees.
        :param longitude: Longitude in decimal degrees.
        """
        service = await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        await service.sendall(struct.pack(">I", 0))
        encoded_latitude = str(latitude).encode()
        encoded_longitude = str(longitude).encode()
        await service.sendall(struct.pack(">I", len(encoded_latitude)) + encoded_latitude)
        await service.sendall(struct.pack(">I", len(encoded_longitude)) + encoded_longitude)
