from pymobiledevice3.services.dvt.instruments import ChannelService
from pymobiledevice3.services.remote_server import MessageAux


class ApplicationListing(ChannelService):
    IDENTIFIER = "com.apple.instruments.server.services.device.applictionListing"

    def __init__(self, dvt):
        super().__init__(dvt)

    async def applist(self) -> list:
        """
        Get the applications list from the device.
        :return: List of applications and their attributes.
        """
        channel = await self._channel_ref()
        await channel.installedApplicationsMatching_registerUpdateToken_(MessageAux().append_obj({}).append_obj(""))
        result = await channel.receive_plist()
        assert isinstance(result, list)
        return result
