from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.location_simulation_base import LocationSimulationBase


class _LocationSimulationService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.LocationSimulation"

    @dtx_method("simulateLocationWithLatitude:longitude:")
    async def simulate_location_with_latitude_longitude_(self, latitude: float, longitude: float) -> None: ...

    @dtx_method("stopLocationSimulation", expects_reply=False)
    async def stop_location_simulation(self) -> None: ...


class _LocationSimulationChannel(DtxService[_LocationSimulationService]):
    pass


class LocationSimulation(LocationSimulationBase):
    IDENTIFIER = _LocationSimulationService.IDENTIFIER

    def __init__(self, dvt: DtxServiceProvider):
        super().__init__()
        self._provider = dvt
        self._channel: _LocationSimulationChannel | None = None

    async def _service_ref(self) -> _LocationSimulationService:
        if self._channel is None:
            self._channel = _LocationSimulationChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def set(self, latitude: float, longitude: float) -> None:
        await (await self._service_ref()).simulate_location_with_latitude_longitude_(latitude, longitude)

    async def clear(self) -> None:
        await (await self._service_ref()).stop_location_simulation()
