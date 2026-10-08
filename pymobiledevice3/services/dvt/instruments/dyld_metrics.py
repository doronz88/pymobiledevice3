import json
from typing import Any

from pymobiledevice3.dtx import DTXContext, DTXQueue, DTXService, dtx_on_data
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import ProcessInspectionError


class DyldMetricsService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.dyld.metrics"

    def __init__(self, ctx: DTXContext) -> None:
        super().__init__(ctx)
        self.snapshots: DTXQueue[bytes] = DTXQueue()

    def on_closed(self, reason: str = "") -> None:
        self.shutdown_queue(self.snapshots)
        super().on_closed(reason)

    @dtx_on_data
    async def _on_data(self, payload: bytes) -> None:
        await self.snapshots.put(payload)


class DyldMetrics(DtxService[DyldMetricsService]):
    """
    Read the dynamic loader's launch metrics of a process, as Xcode does for a launched app.

    The device takes the target's task port, so on a production device this only works for apps
    that are debuggable (development-signed, with ``get-task-allow``).

    Constructed with a `DvtProvider` and used as an async context manager.
    """

    async def capture(self, pid: int, at_main: bool = False, polling_interval_ms: int = 250) -> dict[str, Any]:
        """
        Capture the loader metrics of a process.

        The snapshot is returned as the device reports it: the launch ``timing`` (``spawn``,
        ``init`` and ``main``), image and ``dlopen`` ``counts``, notifier and inserted library
        ``durations`` in seconds, and the loader's own counters under ``rawMetrics``. A process
        that has not started running yet only has its ``spawn`` time.

        :param pid: the process to inspect.
        :param at_main: wait for the process to reach ``main`` before capturing.
        :param polling_interval_ms: how often the device checks for that, in milliseconds.
        :raises ProcessInspectionError: if the device could not inspect the process.
        """
        await self.service.send_keyed_message({
            "command": "captureMetrics",
            "pid": pid,
            "atMain": int(at_main),
            "pollingIntervalMs": polling_interval_ms,
        })
        snapshot = json.loads(await self.service.snapshots.get())
        if "error" in snapshot:
            raise ProcessInspectionError(pid, "capture the loader metrics of", str(snapshot["error"]))
        return snapshot
