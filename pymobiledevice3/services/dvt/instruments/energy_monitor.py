from collections.abc import AsyncGenerator
from typing import Any, Optional

from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class EnergyMonitorService(DTXService):
    IDENTIFIER = "com.apple.xcode.debug-gauge-data-providers.Energy"

    @dtx_method("startSamplingForPIDs:", expects_reply=False)
    async def start_sampling_for_pids_(self, pid_list: list[int]) -> None: ...

    @dtx_method("stopSamplingForPIDs:", expects_reply=False)
    async def stop_sampling_for_pids_(self, pid_list: list[int]) -> None: ...

    @dtx_method("sampleAttributes:forPIDs:")
    async def sample_attributes_for_pids_(self, attributes: dict, pid_list: list[int]) -> Any: ...


class EnergyMonitorChannel(DtxService[EnergyMonitorService]):
    pass


class EnergyMonitor:
    IDENTIFIER = EnergyMonitorService.IDENTIFIER

    def __init__(self, dvt: DtxServiceProvider, pid_list: list[int]) -> None:
        self._provider = dvt
        self._channel: Optional[EnergyMonitorChannel] = None
        self._pid_list = pid_list

    async def _service_ref(self) -> EnergyMonitorService:
        if self._channel is None:
            self._channel = EnergyMonitorChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def __aenter__(self):
        # stop monitoring if already monitored
        await (await self._service_ref()).stop_sampling_for_pids_(self._pid_list)

        await (await self._service_ref()).start_sampling_for_pids_(self._pid_list)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await (await self._service_ref()).stop_sampling_for_pids_(self._pid_list)

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        while True:
            yield await self._sample_once()

    async def _sample_once(self):
        return await (await self._service_ref()).sample_attributes_for_pids_({}, self._pid_list)
