from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class IDAMService(LockdownService):
    """
    Query and set the device's IDAM configuration via the ``com.apple.idamd`` lockdown service.

    Exposes reading the current IDAM configuration and toggling it. This is a lockdown service and
    is used as an async context manager; the RSD/tunnel variant is selected automatically for
    non-`LockdownClient` providers.
    """

    RSD_SERVICE_NAME = "com.apple.idamd.shim.remote"
    SERVICE_NAME = "com.apple.idamd"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def configuration_inquiry(self) -> dict:
        """
        Read the device's current IDAM configuration.

        Sends a ``Configuration Inquiry`` request.

        :returns: the device's IDAM configuration response.
        """
        return await self.service.send_recv_plist({"Configuration Inquiry": True})

    async def set_idam_configuration(self, value: bool) -> None:
        """
        Set the device's IDAM configuration.

        Sends a ``Set IDAM Configuration`` request with the given value.

        :param value: the IDAM configuration flag to apply.
        """
        await self.service.send_recv_plist({"Set IDAM Configuration": value})
