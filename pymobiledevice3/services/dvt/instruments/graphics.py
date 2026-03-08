import asyncio
from collections.abc import AsyncGenerator
from typing import Any

from pymobiledevice3.dtx import DTXService, dtx_method, dtx_on_dispatch, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class GraphicsService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.graphics.opengl"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.events: asyncio.Queue[Any] = asyncio.Queue()

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


class GraphicsChannel(DtxService[GraphicsService]):
    pass


class Graphics:
    IDENTIFIER = GraphicsService.IDENTIFIER

    def __init__(self, dvt: DtxServiceProvider):
        self._provider = dvt
        self._channel: GraphicsChannel | None = None

    async def _service_ref(self) -> GraphicsService:
        if self._channel is None:
            self._channel = GraphicsChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def __aenter__(self):
        await (await self._service_ref()).start_sampling_at_time_interval_(0.0)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await (await self._service_ref()).stop_sampling()

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        while True:
            yield await (await self._service_ref()).events.get()
