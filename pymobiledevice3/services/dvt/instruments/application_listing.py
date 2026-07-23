from typing import Any

from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService


class ApplicationListingService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.device.applictionListing"

    @dtx_method("installedApplicationsMatching:registerUpdateToken:")
    async def installed_applications_matching_register_update_token_(
        self, options: dict[str, Any], update_token: str
    ) -> list[dict[str, Any]]: ...


class ApplicationListing(DtxService[ApplicationListingService]):
    """
    Enumerate the applications installed on the device over the
    `com.apple.instruments.server.services.device.applictionListing` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``ApplicationListing(DvtProvider(service_provider))``,
    and used as an async context manager to open the channel.
    """

    async def applist(self) -> list[dict[str, Any]]:
        """
        Get the list of installed applications.

        Invokes `installedApplicationsMatching:registerUpdateToken:` with an empty
        match filter and no update token, so every installed application is returned.

        :returns: One dict of attributes per installed application.
        """
        result = await self.service.installed_applications_matching_register_update_token_({}, "")
        assert isinstance(result, list)
        return result
