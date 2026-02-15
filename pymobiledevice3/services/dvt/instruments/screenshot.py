from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments import ChannelService


class Screenshot(ChannelService):
    IDENTIFIER = "com.apple.instruments.server.services.screenshot"

    def __init__(self, dvt: DvtSecureSocketProxyService):
        super().__init__(dvt)

    async def get_screenshot(self) -> bytes:
        """get device screenshot"""
        channel = await self._channel_ref()
        await channel.takeScreenshot(expects_reply=True)
        return await channel.receive_plist()
