from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.services.dvt.instruments.location_simulation_base import LocationSimulationBase


class LocationSimulationService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.LocationSimulation"

    @dtx_method("simulateLocationWithLatitude:longitude:")
    async def simulate_location_with_latitude_longitude_(self, latitude: float, longitude: float) -> None: ...

    @dtx_method("stopLocationSimulation", expects_reply=False)
    async def stop_location_simulation(self) -> None: ...


class LocationSimulation(DtxService[LocationSimulationService], LocationSimulationBase):
    def __init__(self, dvt):
        DtxService.__init__(self, dvt)
        LocationSimulationBase.__init__(self)

    async def set(self, latitude: float, longitude: float) -> None:
        await self.service.simulate_location_with_latitude_longitude_(latitude, longitude)

    async def clear(self) -> None:
        await self.service.stop_location_simulation()
