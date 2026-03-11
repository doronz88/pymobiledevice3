from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService


class ApplicationListingService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.device.applictionListing"

    @dtx_method("installedApplicationsMatching:registerUpdateToken:")
    async def installed_applications_matching_register_update_token_(
        self, options: dict, update_token: str
    ) -> list: ...


class ApplicationListing(DtxService[ApplicationListingService]):
    async def applist(self) -> list:
        """
        Get the applications list from the device.
        :return: List of applications and their attributes.
        """
        result = await self.service.installed_applications_matching_register_update_token_({}, "")
        assert isinstance(result, list)
        return result
