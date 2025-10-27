from pymobiledevice3.services.dvt.instruments.location_simulation_base import LocationSimulationBase
from pymobiledevice3.services.remote_server import MessageAux


class LocationSimulation(LocationSimulationBase):
    IDENTIFIER = "com.apple.instruments.server.services.LocationSimulation"

    def __init__(self, dvt):
        super().__init__()
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def set(self, latitude: float, longitude: float) -> None:
        self._channel.simulateLocationWithLatitude_longitude_(MessageAux().append_obj(latitude).append_obj(longitude))
        self._channel.receive_plist()

    def clear(self) -> None:
        self._channel.stopLocationSimulation()
