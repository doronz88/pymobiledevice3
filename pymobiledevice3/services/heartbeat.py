#!/usr/bin/env python3
import logging
import time
from typing import Optional

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


class HeartbeatService:
    """
    Use to keep an active connection with lockdownd
    """

    SERVICE_NAME = "com.apple.mobile.heartbeat"
    RSD_SERVICE_NAME = "com.apple.mobile.heartbeat.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

        if isinstance(lockdown, LockdownClient):
            self.service_name = self.SERVICE_NAME
        else:
            self.service_name = self.RSD_SERVICE_NAME

    def start(self, interval: Optional[float] = None) -> None:
        start = time.time()
        service = self.lockdown.start_lockdown_service(self.service_name)

        while True:
            response = service.recv_plist()
            self.logger.debug(response)

            if interval is not None and time.time() >= start + interval:
                break

            service.send_plist({"Command": "Polo"})
