import logging
import time
from abc import abstractmethod

import gpxpy


class LocationSimulationBase:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def set(self, latitude: float, longitude: float) -> None:
        pass

    @abstractmethod
    def clear(self) -> None:
        pass

    def play_gpx_file(self, filename: str, disable_sleep: bool = False):
        with open(filename) as f:
            gpx = gpxpy.parse(f)

        last_time = None
        for track in gpx.tracks:
            for segment in track.segments:
                for point in segment.points:
                    if last_time is not None:
                        duration = (point.time - last_time).total_seconds()
                        if duration >= 0:
                            if not disable_sleep:
                                self.logger.info(f'waiting for {duration}s')
                                time.sleep(duration)
                    last_time = point.time
                    self.logger.info(f'set location to {point.latitude} {point.longitude}')
                    self.set(point.latitude, point.longitude)
