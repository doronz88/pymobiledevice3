from collections.abc import AsyncGenerator
from typing import Any

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
    async def sample_attributes_for_pids_(self, attributes: dict[str, Any], pid_list: list[int]) -> Any: ...


class EnergyMonitor(DtxService[EnergyMonitorService]):
    """
    Sample per-process energy usage from the Xcode debug-gauge energy provider.

    Constructed with a `DvtProvider` and the list of PIDs to monitor. Use as an async context
    manager: entering starts sampling for those PIDs and exiting stops it. The object is
    async-iterable, yielding one energy-attribute sample for the monitored PIDs per iteration.
    """

    def __init__(self, dvt: DtxServiceProvider, pid_list: list[int]) -> None:
        """
        :param dvt: The `DvtProvider` used to open the Instruments channel.
        :param pid_list: The process IDs to sample energy usage for.
        """
        super().__init__(dvt)
        self._pid_list = pid_list

    async def __aenter__(self):
        await self.connect()
        # stop monitoring if already monitored
        await self.service.stop_sampling_for_pids_(self._pid_list)

        await self.service.start_sampling_for_pids_(self._pid_list)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        await self.service.stop_sampling_for_pids_(self._pid_list)

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        """
        Sample energy attributes for the monitored PIDs indefinitely.

        :yields: The device's energy-attributes reply for the monitored PIDs, one per iteration.
        """
        while True:
            yield await self._sample_once()

    async def _sample_once(self):
        return await self.service.sample_attributes_for_pids_({}, self._pid_list)
