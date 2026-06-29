#!/usr/bin/env python3
import logging
import time
from typing import Optional

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


class HeartbeatService:
    """
    Keep an active connection alive with the device's heartbeat lockdown service.

    The device periodically sends ``Marco`` messages over ``com.apple.mobile.heartbeat`` and expects a
    ``Polo`` reply; exchanging them prevents the connection from being torn down. The RSD/tunnel variant
    of the service is selected automatically when the provider is not a plain `LockdownClient`.
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

    async def start(self, interval: Optional[float] = None) -> None:
        """
        Start the heartbeat exchange loop.

        Opens the heartbeat service and, in a loop, receives each message from the device and replies
        with ``Polo`` to keep the connection alive.

        :param interval: when set, stop the loop once roughly this many seconds have elapsed since it
            started; when None, the loop runs indefinitely.
        """
        start = time.time()
        service = await self.lockdown.start_lockdown_service(self.service_name)

        while True:
            response = await service.recv_plist()
            self.logger.debug(response)

            if interval is not None and time.time() >= start + interval:
                break

            await service.send_plist({"Command": "Polo"})
