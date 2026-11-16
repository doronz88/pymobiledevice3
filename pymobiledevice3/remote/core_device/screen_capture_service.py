from typing import Any, Optional

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService, select_display
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class ScreenCaptureService(CoreDeviceService):
    """
    Capture screenshots from the device
    """

    SERVICE_NAME = "com.apple.coredevice.screencaptureservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def active_display_unique_id(self) -> Optional[str]:
        """Return the ``uniqueId`` of the built-in display in use, to pass to :meth:`capture_screenshot`.

        On a foldable that is the panel currently lit (see :func:`select_display`): its primary
        display is the cover panel, which is off, and captures black, while the device is
        unfolded. ``None`` when the display in use is the primary one, or carries no ``uniqueId``.
        """
        async with DeviceInfoService(self.rsd) as info:
            display = select_display(await info.get_display_info())
        if display.get("primary"):
            return None
        return display.get("uniqueId")

    async def capture_screenshot(
        self, display_unique_id: Optional[str] = None, requested_format: str = "png"
    ) -> dict[str, Any]:
        """
        Capture a screenshot from the device.

        :param display_unique_id: Optional identifier of the display to capture. When ``None``,
                                  the primary display is captured.
        :param requested_format: Image format (currently only ``"png"`` is supported by the device).
        :return: dict containing ``image`` (raw image bytes), ``displayUniqueID`` and ``imageFormat``.
        """
        return await self.invoke(
            "com.apple.coredevice.feature.capturescreenshot",
            {
                "displayUniqueID": display_unique_id,
                "requestedFormat": requested_format,
            },
            action_identifier="com.apple.coredevice.action.capturescreenshot",
        )
