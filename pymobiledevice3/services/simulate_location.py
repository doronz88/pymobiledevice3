import struct

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.instruments.location_simulation_base import LocationSimulationBase
from pymobiledevice3.services.lockdown_service import LockdownService


class DtSimulateLocation(LockdownService, LocationSimulationBase):
    SERVICE_NAME = "com.apple.dt.simulatelocation"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        LockdownService.__init__(self, lockdown, self.SERVICE_NAME)
        LocationSimulationBase.__init__(self)

    async def clear(self) -> None:
        """stop simulation"""
        service = await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        await service.sendall(struct.pack(">I", 1))

    async def set(self, latitude: float, longitude: float) -> None:
        """Start simulating the given location"""
        service = await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        await service.sendall(struct.pack(">I", 0))
        latitude = str(latitude).encode()
        longitude = str(longitude).encode()
        await service.sendall(struct.pack(">I", len(latitude)) + latitude)
        await service.sendall(struct.pack(">I", len(longitude)) + longitude)
