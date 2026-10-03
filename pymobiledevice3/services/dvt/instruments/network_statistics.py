import asyncio
from collections.abc import AsyncGenerator
from typing import Any, Optional

from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx.ns_types import NSDate
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class NetworkStatisticsService(DTXService):
    IDENTIFIER = "com.apple.xcode.debug-gauge-data-providers.NetworkStatistics"

    @dtx_method("startSamplingForPIDs:")
    async def start_sampling_for_pids_(self, pid_list: list[int]) -> Any: ...

    @dtx_method("stopSamplingForPIDs:")
    async def stop_sampling_for_pids_(self, pid_list: list[int]) -> Any: ...

    @dtx_method("sampleAttributes:forPIDs:")
    async def sample_attributes_for_pids_(self, attributes: dict[str, Any], pid_list: list[int]) -> Any: ...


class NetworkStatistics(DtxService[NetworkStatisticsService]):
    """
    Sample per-process network traffic from the Xcode debug-gauge network provider.

    Constructed with a `DvtProvider` and the list of PIDs to monitor. Use as an async context
    manager: entering starts sampling for those PIDs and exiting stops it. The object is
    async-iterable, yielding one sample per interval that maps each PID to its counters:
    cumulative ``net.bytes``/``net.packets`` totals plus their ``net.rx.*``/``net.tx.*`` split,
    a ``.delta`` of each, the ``pid`` and the sample ``time``.
    """

    DEFAULT_INTERVAL_MS = 1000

    def __init__(self, dvt: DtxServiceProvider, pid_list: list[int], interval_ms: int = DEFAULT_INTERVAL_MS) -> None:
        """
        :param dvt: The `DvtProvider` used to open the Instruments channel.
        :param pid_list: The process IDs to sample network usage for.
        :param interval_ms: Interval in milliseconds between samples.
        """
        super().__init__(dvt)
        self._pid_list = pid_list
        self._interval_ms = interval_ms

    async def __aenter__(self) -> "NetworkStatistics":
        await self.connect()
        await self.service.start_sampling_for_pids_(self._pid_list)
        # Each reply carries the sample taken at the previous call, so the first one is left over
        # from whichever client sampled last.
        await self._sample_once()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.service.stop_sampling_for_pids_(self._pid_list)

    async def __aiter__(self) -> AsyncGenerator[dict[int, dict[str, Any]], None]:
        """
        Sample network counters for the monitored PIDs indefinitely.

        :yields: A mapping of PID to that process's counters, one per interval.
        """
        while True:
            await asyncio.sleep(self._interval_ms / 1000)
            sample = await self._sample_once()
            if sample:
                yield sample

    async def _sample_once(self) -> Optional[dict[int, dict[str, Any]]]:
        sample: Optional[dict[int, dict[str, Any]]] = await self.service.sample_attributes_for_pids_({}, self._pid_list)
        if sample is None:
            return None
        for record in sample.values():
            timestamp = record.get("time")
            if isinstance(timestamp, NSDate):
                record["time"] = timestamp.utc
        return sample
