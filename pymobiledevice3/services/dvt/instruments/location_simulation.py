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
    """
    Override the device's reported GPS location over the
    `com.apple.instruments.server.services.LocationSimulation` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``LocationSimulation(DvtProvider(service_provider))``,
    and used as an async context manager to open the channel.
    """

    def __init__(self, dvt):
        DtxService.__init__(self, dvt)
        LocationSimulationBase.__init__(self)

    async def set(self, latitude: float, longitude: float) -> None:
        """
        Simulate the device being at the given coordinates.

        Invokes the `simulateLocationWithLatitude:longitude:` selector.

        :param latitude: Latitude in decimal degrees.
        :param longitude: Longitude in decimal degrees.
        """
        await self.service.simulate_location_with_latitude_longitude_(latitude, longitude)

    async def clear(self) -> None:
        """
        Stop simulating the location and restore the device's real GPS.

        Invokes the `stopLocationSimulation` selector.
        """
        await self.service.stop_location_simulation()
