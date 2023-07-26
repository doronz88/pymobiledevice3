import logging

from pymobiledevice3.services.remote_server import MessageAux


class LocationSimulation:
    IDENTIFIER = 'com.apple.instruments.server.services.LocationSimulation'

    def __init__(self, dvt):
        self.logger = logging.getLogger(__name__)
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def simulate_location(self, latitude: float, longitude: float) -> None:
        self._channel.simulateLocationWithLatitude_longitude_(MessageAux().append_obj(latitude).append_obj(longitude))
        self._channel.receive_plist()

    def stop(self) -> None:
        self._channel.stopLocationSimulation()
