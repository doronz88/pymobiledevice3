from pymobiledevice3.services.dvt.instruments import ChannelService
from pymobiledevice3.services.dvt.instruments.location_simulation_base import LocationSimulationBase
from pymobiledevice3.services.remote_server import MessageAux


class LocationSimulation(LocationSimulationBase, ChannelService):
    IDENTIFIER = "com.apple.instruments.server.services.LocationSimulation"

    def __init__(self, dvt):
        super().__init__()
        ChannelService.__init__(self, dvt)

    async def set(self, latitude: float, longitude: float) -> None:
        channel = await self._channel_ref()
        await channel.simulateLocationWithLatitude_longitude_(MessageAux().append_obj(latitude).append_obj(longitude))
        await channel.receive_plist()

    async def clear(self) -> None:
        channel = await self._channel_ref()
        await channel.stopLocationSimulation()
