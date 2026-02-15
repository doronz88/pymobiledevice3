import logging

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.services.dvt.instruments import ChannelService
from pymobiledevice3.services.remote_server import MessageAux


class ConditionInducer(ChannelService):
    IDENTIFIER = "com.apple.instruments.server.services.ConditionInducer"

    def __init__(self, dvt):
        self.logger = logging.getLogger(__name__)
        super().__init__(dvt)

    async def list(self) -> list:
        channel = await self._channel_ref()
        await channel.availableConditionInducers()
        return await channel.receive_plist()

    async def set(self, profile_identifier):
        channel = await self._channel_ref()
        for group in await self.list():
            for profile in group.get("profiles"):
                if profile_identifier == profile.get("identifier"):
                    self.logger.info(profile.get("description"))
                    await channel.enableConditionWithIdentifier_profileIdentifier_(
                        MessageAux().append_obj(group.get("identifier")).append_obj(profile.get("identifier"))
                    )
                    # wait for response which may be a raised NSError
                    await channel.receive_plist()
                    return
        raise PyMobileDevice3Exception("Invalid profile identifier")

    async def clear(self):
        channel = await self._channel_ref()
        await channel.disableActiveCondition()
