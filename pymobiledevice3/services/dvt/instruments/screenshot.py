from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService


class ScreenshotService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.screenshot"

    @dtx_method("takeScreenshot")
    async def take_screenshot(self) -> bytes: ...


class Screenshot(DtxService[ScreenshotService]):
    async def get_screenshot(self) -> bytes:
        """Get device screenshot."""
        return await self.service.take_screenshot()
