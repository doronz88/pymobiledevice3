from pymobiledevice3.exceptions import AppNotInstalledError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService

VEND_CONTAINER = "VendContainer"
VEND_DOCUMENTS = "VendDocuments"

DOCUMENTS_ROOT = "/Documents"


class HouseArrestService(AfcService):
    SERVICE_NAME = "com.apple.mobile.house_arrest"
    RSD_SERVICE_NAME = "com.apple.mobile.house_arrest.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider, documents_only: bool = False):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)
        self.documents_only = documents_only

    @classmethod
    async def create(
        cls, lockdown: LockdownServiceProvider, bundle_id: str, documents_only: bool = False
    ) -> "HouseArrestService":
        service = cls(lockdown, documents_only=documents_only)
        cmd = VEND_DOCUMENTS if documents_only else VEND_CONTAINER
        try:
            await service.send_command(bundle_id, cmd)
        except PyMobileDevice3Exception:
            await service.close()
            raise
        return service

    async def send_command(self, bundle_id: str, cmd: str = "VendContainer") -> None:
        await self.service.send_plist({"Command": cmd, "Identifier": bundle_id})
        response = await self.service.recv_plist()
        error = response.get("Error")
        if error:
            if error == "ApplicationLookupFailed":
                raise AppNotInstalledError(f"No app with bundle id {bundle_id} found")
            else:
                raise PyMobileDevice3Exception(error)

    def shell(self) -> None:
        raise RuntimeError("AFC shell is not available in async-only mode")
