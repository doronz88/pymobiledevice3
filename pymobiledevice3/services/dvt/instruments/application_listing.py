from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class ApplicationListingService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.device.applictionListing"

    @dtx_method("installedApplicationsMatching:registerUpdateToken:")
    async def installed_applications_matching_register_update_token_(
        self, options: dict, update_token: str
    ) -> list: ...


class ApplicationListingChannel(DtxService[ApplicationListingService]):
    pass


class ApplicationListing:
    IDENTIFIER = ApplicationListingService.IDENTIFIER

    def __init__(self, dvt: DtxServiceProvider):
        self._provider = dvt
        self._channel: ApplicationListingChannel | None = None

    async def _service_ref(self) -> ApplicationListingService:
        if self._channel is None:
            self._channel = ApplicationListingChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def applist(self) -> list:
        """
        Get the applications list from the device.
        :return: List of applications and their attributes.
        """
        result = await (await self._service_ref()).installed_applications_matching_register_update_token_({}, "")
        assert isinstance(result, list)
        return result
