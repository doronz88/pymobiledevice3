#!/usr/bin/env python3
import logging
import time

from pymobiledevice3.lockdown import LockdownClient


class HeartbeatService(object):
    """
    Use to keep an active connection with lockdowd
    """
    SERVICE_NAME = 'com.apple.mobile.heartbeat'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

    def start(self, interval=None):
        start = time.time()
        service = self.lockdown.start_service(self.SERVICE_NAME)

        while True:
            response = service.recv_plist()
            self.logger.debug(response)

            if interval is not None:
                if time.time() >= start + interval:
                    break

            service.send_plist({'Command': 'Polo'})
