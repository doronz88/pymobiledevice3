import logging
import struct
import time

import gpxpy

from pymobiledevice3.lockdown import LockdownClient


class DtSimulateLocation(object):
    SERVICE_NAME = 'com.apple.dt.simulatelocation'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

    def clear(self):
        """ stop simulation """
        service = self.lockdown.start_developer_service(self.SERVICE_NAME)
        service.sendall(struct.pack('>I', 1))

    def set(self, latitude, longitude):
        """ stop simulation """
        service = self.lockdown.start_developer_service(self.SERVICE_NAME)
        service.sendall(struct.pack('>I', 0))
        latitude = str(latitude).encode()
        longitude = str(longitude).encode()
        service.sendall(struct.pack('>I', len(latitude)) + latitude)
        service.sendall(struct.pack('>I', len(longitude)) + longitude)

    def play_gpx_file(self, filename, disable_sleep=False):
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
                                logging.info(f'waiting for {duration}s')
                                time.sleep(duration)
                    last_time = point.time
                    logging.info(f'set location to {point.latitude} {point.longitude}')
                    self.set(point.latitude, point.longitude)
