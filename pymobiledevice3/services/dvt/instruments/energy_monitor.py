from collections.abc import AsyncGenerator
from typing import Any

from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService


class EnergyMonitorService(DTXService):
    IDENTIFIER = "com.apple.xcode.debug-gauge-data-providers.Energy"

    @dtx_method("startSamplingForPIDs:", expects_reply=False)
    async def start_sampling_for_pids_(self, pid_list: list[int]) -> None: ...

    @dtx_method("stopSamplingForPIDs:", expects_reply=False)
    async def stop_sampling_for_pids_(self, pid_list: list[int]) -> None: ...

    @dtx_method("sampleAttributes:forPIDs:")
    async def sample_attributes_for_pids_(self, attributes: dict, pid_list: list[int]) -> Any: ...


class EnergyMonitor(DtxService[EnergyMonitorService]):
    def __init__(self, dvt, pid_list: list[int]) -> None:
        super().__init__(dvt)
        self._pid_list = pid_list

    async def __aenter__(self):
        await self.connect()
        # stop monitoring if already monitored
        await self.service.stop_sampling_for_pids_(self._pid_list)

        await self.service.start_sampling_for_pids_(self._pid_list)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.service.stop_sampling_for_pids_(self._pid_list)

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        while True:
            yield await self._sample_once()

    async def _sample_once(self):
        return await self.service.sample_attributes_for_pids_({}, self._pid_list)
