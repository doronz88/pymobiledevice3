from pymobiledevice3.services.dvt.instruments import ChannelService
from pymobiledevice3.services.remote_server import MessageAux


class EnergyMonitor(ChannelService):
    IDENTIFIER = "com.apple.xcode.debug-gauge-data-providers.Energy"

    def __init__(self, dvt, pid_list: list) -> None:
        super().__init__(dvt)
        self._pid_list = pid_list

    async def __aenter__(self):
        channel = await self._channel_ref()
        # stop monitoring if already monitored
        await channel.stopSamplingForPIDs_(MessageAux().append_obj(self._pid_list))

        await channel.startSamplingForPIDs_(MessageAux().append_obj(self._pid_list))
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        channel = await self._channel_ref()
        await channel.stopSamplingForPIDs_(MessageAux().append_obj(self._pid_list))

    def __aiter__(self):
        while True:
            yield self._sample_once()

    async def _sample_once(self):
        channel = await self._channel_ref()
        await channel.sampleAttributes_forPIDs_(MessageAux().append_obj({}).append_obj(self._pid_list))
        return await channel.receive_plist()
