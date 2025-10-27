import logging
import random
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

    def play_gpx_file(self, filename: str, disable_sleep: bool = False, timing_randomness_range: int = 0):
        with open(filename) as f:
            gpx = gpxpy.parse(f)

        last_time = None
        gpx_timing_noise = None
        for track in gpx.tracks:
            for segment in track.segments:
                for point in segment.points:
                    if last_time is not None:
                        duration = (point.time - last_time).total_seconds()
                        if duration >= 0 and not disable_sleep:
                            if timing_randomness_range:
                                gpx_timing_noise = (
                                    random.randint(-timing_randomness_range, timing_randomness_range) / 1000
                                )
                                duration += gpx_timing_noise

                            self.logger.info(f"waiting for {duration:.3f}s")
                            time.sleep(duration)
                    last_time = point.time
                    self.logger.info(f"set location to {point.latitude} {point.longitude}")
                    self.set(point.latitude, point.longitude)
