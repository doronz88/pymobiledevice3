from pymobiledevice3.services.dvt.instruments import ChannelService
from pymobiledevice3.services.remote_server import MessageAux


class Graphics(ChannelService):
    IDENTIFIER = "com.apple.instruments.server.services.graphics.opengl"

    def __init__(self, dvt):
        super().__init__(dvt)

    async def __aenter__(self):
        channel = await self._channel_ref()
        await channel.startSamplingAtTimeInterval_(MessageAux().append_obj(0.0))
        await channel.receive_plist()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        channel = await self._channel_ref()
        await channel.stopSampling()

    def __aiter__(self):
        while True:
            yield self._read_once()

    async def _read_once(self):
        channel = await self._channel_ref()
        return await channel.receive_plist()
