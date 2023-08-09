#!/usr/bin/env python3
import time

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class HeartbeatService(LockdownService):
    """
    Use to keep an active connection with lockdowd
    """
    SERVICE_NAME = 'com.apple.mobile.heartbeat'
    RSD_SERVICE_NAME = 'com.apple.mobile.heartbeat.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def start(self, interval=None):
        start = time.time()
        service = self.lockdown.start_lockdown_service(self.service_name)

        while True:
            response = service.recv_plist()
            self.logger.debug(response)

            if interval is not None:
                if time.time() >= start + interval:
                    break

            service.send_plist({'Command': 'Polo'})
