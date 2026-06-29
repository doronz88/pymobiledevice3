from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService


class ScreenshotService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.screenshot"

    @dtx_method("takeScreenshot")
    async def take_screenshot(self) -> bytes: ...


class Screenshot(DtxService[ScreenshotService]):
    """
    Capture a screenshot of the device's screen over the
    `com.apple.instruments.server.services.screenshot` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``Screenshot(DvtProvider(service_provider))``,
    and used as an async context manager to open the channel.
    """

    async def get_screenshot(self) -> bytes:
        """
        Capture a screenshot of the current screen.

        Invokes the `takeScreenshot` selector.

        :returns: The screenshot image as raw bytes.
        """
        return await self.service.take_screenshot()
