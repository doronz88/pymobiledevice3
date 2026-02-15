#!/usr/bin/env python3

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class PreboardService(LockdownService):
    RSD_SERVICE_NAME = "com.apple.preboardservice_v2.shim.remote"
    SERVICE_NAME = "com.apple.preboardservice_v2"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def create_stashbag(self, manifest):
        await self.service.send_plist({"Command": "CreateStashbag", "Manifest": manifest})
        return await self.service.recv_plist()

    async def commit(self, manifest):
        await self.service.send_plist({"Command": "CommitStashbag", "Manifest": manifest})
        return await self.service.recv_plist()
