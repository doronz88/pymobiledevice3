from collections.abc import AsyncIterator
from typing import Any, Optional

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


def select_display(display_info: dict[str, Any], display_id: Optional[int] = None) -> dict[str, Any]:
    """Pick one display out of a :meth:`DeviceInfoService.get_display_info` reply.

    :param display_info: The ``get_display_info`` / ``display_info_updates`` reply.
    :param display_id: The ``displayId`` to pick. ``None`` picks the built-in display that is
                       currently in use: a foldable lights only one of its panels at a time,
                       and flags it ``active``. Falls back to the primary display.
    :return: The display's entry. A synthetic ``{"displayId": display_id}`` when the reply
             doesn't list ``display_id``, or ``{"displayId": 1}`` when it lists no display.
    """
    displays: list[dict[str, Any]] = display_info.get("displays", [])
    if display_id is not None:
        for display in displays:
            if display.get("displayId") == display_id:
                return display
        return {"displayId": display_id}
    for display in displays:
        if display.get("active") and not display.get("external"):
            return display
    for display in displays:
        if display.get("primary"):
            return display
    return {"displayId": 1}


_ORIENTATION_DEGREES = {"rot0": 0, "rot90": 90, "rot180": 180, "rot270": -90}


def display_rotation(display: dict[str, Any]) -> int:
    """Degrees (clockwise, one of 0/90/180/-90) to turn a display's captured frames to show them upright.

    The screen stream captures a display in its native orientation. A display whose UI is
    turned relative to that (a foldable's inner panel held sideways reports ``rot90``) arrives
    sideways, and turns upright by ``currentOrientation``.
    """
    return _ORIENTATION_DEGREES.get(display.get("currentOrientation", "rot0"), 0)


class DeviceInfoService(CoreDeviceService):
    """
    Query device information
    """

    SERVICE_NAME = "com.apple.coredevice.deviceinfo"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def get_device_info(self) -> dict[str, Any]:
        """
        Get device information
        """
        return await self.invoke("com.apple.coredevice.feature.getdeviceinfo", {})

    async def get_display_info(self) -> dict[str, Any]:
        """
        Get display information
        """
        return await self.invoke("com.apple.coredevice.feature.getdisplayinfo", {})

    async def display_info_updates(self) -> AsyncIterator[dict[str, Any]]:
        """
        Stream the device's display information: one :meth:`get_display_info`-shaped snapshot
        every time a display changes (e.g. a foldable switching between its panels)
        """
        async for element in self.stream_invoke("com.apple.coredevice.feature.displayinfoupdates", {}):
            yield element

    async def query_mobilegestalt(self, keys: list[str]) -> dict[str, Any]:
        """
        Query MobileGestalt.

        Can only be performed to specific devices
        """
        return await self.invoke("com.apple.coredevice.feature.querymobilegestalt", {"keys": keys})

    async def get_lockstate(self) -> dict[str, Any]:
        """
        Get lockstate
        """
        return await self.invoke("com.apple.coredevice.feature.getlockstate", {})
