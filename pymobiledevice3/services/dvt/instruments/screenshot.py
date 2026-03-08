from typing import Optional

from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class ScreenshotService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.screenshot"

    @dtx_method("takeScreenshot")
    async def take_screenshot(self) -> bytes: ...


class ScreenshotChannel(DtxService[ScreenshotService]):
    pass


class Screenshot:
    IDENTIFIER = ScreenshotService.IDENTIFIER

    def __init__(self, dvt: DtxServiceProvider):
        self._provider = dvt
        self._channel: Optional[ScreenshotChannel] = None

    async def _service_ref(self) -> ScreenshotService:
        if self._channel is None:
            self._channel = ScreenshotChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def get_screenshot(self) -> bytes:
        """Get device screenshot."""
        return await (await self._service_ref()).take_screenshot()
