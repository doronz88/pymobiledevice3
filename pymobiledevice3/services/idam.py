from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class IDAMService(LockdownService):
    RSD_SERVICE_NAME = "com.apple.idamd.shim.remote"
    SERVICE_NAME = "com.apple.idamd"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def configuration_inquiry(self) -> dict:
        await self.service.send_plist({"Configuration Inquiry": True})
        return await self.service.recv_plist()

    async def set_idam_configuration(self, value: bool) -> None:
        await self.service.send_plist({"Set IDAM Configuration": value})
        await self.service.recv_plist()
