from collections.abc import AsyncGenerator
from typing import Any

from pymobiledevice3.dtx import DTXContext, DTXQueue, DTXService, dtx_method, dtx_on_dispatch, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService


class GraphicsService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.graphics.opengl"

    def __init__(self, ctx: DTXContext):
        super().__init__(ctx)
        self.events: DTXQueue[Any] = DTXQueue()

    def on_closed(self, reason: str = "") -> None:
        self.shutdown_queue(self.events)
        super().on_closed(reason)

    @dtx_method("startSamplingAtTimeInterval:")
    async def start_sampling_at_time_interval_(self, interval: float) -> Any: ...

    @dtx_method("stopSampling", expects_reply=False)
    async def stop_sampling(self) -> None: ...

    @dtx_on_dispatch
    async def _on_dispatch(self, selector: str, *args: Any) -> None:
        await self.events.put((selector, list(args)))

    @dtx_on_notification
    async def _on_notification(self, payload: Any) -> None:
        await self.events.put(payload)


class Graphics(DtxService[GraphicsService]):
    """
    Sample GPU/OpenGL graphics performance counters over the Instruments channel.

    Constructed with a `DvtProvider`. Use as an async context manager: entering starts sampling
    and exiting stops it. The object is async-iterable, yielding graphics sample events as they
    arrive from the device.
    """

    async def __aenter__(self):
        await self.connect()
        await self.service.start_sampling_at_time_interval_(0.0)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        await self.service.stop_sampling()

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        """
        Yield graphics sample events as they arrive from the service.

        :yields: A graphics performance sample emitted by the device.
        """
        while True:
            yield await self.service.events.get()
