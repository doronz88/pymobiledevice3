from enum import IntEnum
from typing import Any, Optional, Union, cast

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import build_plist
from pymobiledevice3.services.lockdown_service import LockdownService


class InterfaceOrientation(IntEnum):
    """SpringBoard interface orientation values."""

    PORTRAIT = 1
    PORTRAIT_UPSIDE_DOWN = 2
    LANDSCAPE = 3
    LANDSCAPE_HOME_TO_LEFT = 4


class SpringBoardServicesService(LockdownService):
    """
    Client for the ``com.apple.springboardservices`` lockdown service.

    Exposes SpringBoard operations such as reading and writing the home screen icon layout,
    fetching application icon and wallpaper images, and querying the interface orientation.
    """

    RSD_SERVICE_NAME = "com.apple.springboardservices.shim.remote"
    SERVICE_NAME = "com.apple.springboardservices"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def get_icon_state(self, format_version: str = "2") -> list[Any]:
        """
        Retrieve the current home screen icon layout.

        :param format_version: Icon state format version sent to SpringBoard as ``formatVersion``.
            When falsy, the key is omitted from the request.
        :returns: Nested list describing the home screen pages, folders and icons.
        """
        cmd = {"command": "getIconState"}
        if format_version:
            cmd["formatVersion"] = format_version
        return cast(list[Any], await self.service.send_recv_plist(cmd))

    async def set_icon_state(self, newstate: Optional[list[Any]] = None) -> None:
        """
        Apply a new home screen icon layout.

        :param newstate: Icon layout in the same structure returned by `get_icon_state`.
            When ``None``, an empty layout is sent.
        """
        state: Union[list[Any], dict[str, Any]] = {} if newstate is None else newstate
        await self.service.send_recv_prefixed(build_plist({"command": "setIconState", "iconState": state}))

    async def get_icon_pngdata(self, bundle_id: str) -> bytes:
        """
        Retrieve the home screen icon image of an installed application.

        :param bundle_id: Bundle identifier of the application whose icon is requested.
        :returns: PNG-encoded icon image bytes, or ``None`` if no ``pngData`` is returned.
        """
        return cast(
            bytes,
            (await self.service.send_recv_plist({"command": "getIconPNGData", "bundleId": bundle_id})).get("pngData"),
        )

    async def get_interface_orientation(self) -> InterfaceOrientation:
        """
        Query the current SpringBoard interface orientation.

        :returns: The current orientation as an `InterfaceOrientation` enum value.
        """
        res = await self.service.send_recv_plist({"command": "getInterfaceOrientation"})
        return InterfaceOrientation(res.get("interfaceOrientation"))

    async def get_wallpaper_pngdata(self) -> bytes:
        """
        Retrieve the current home screen wallpaper image.

        :returns: PNG-encoded wallpaper image bytes, or ``None`` if no ``pngData`` is returned.
        """
        return cast(
            bytes, (await self.service.send_recv_plist({"command": "getHomeScreenWallpaperPNGData"})).get("pngData")
        )

    async def get_homescreen_icon_metrics(self) -> dict[str, float]:
        """
        Retrieve the home screen icon layout metrics.

        :returns: Mapping of metric names to their numeric values, as reported by SpringBoard.
        """
        return cast(dict[str, float], await self.service.send_recv_plist({"command": "getHomeScreenIconMetrics"}))

    async def get_wallpaper_info(self, wallpaper_name: str) -> dict[str, Any]:
        """
        Retrieve metadata about a named wallpaper.

        :param wallpaper_name: Name of the wallpaper to query.
        :returns: Mapping describing the wallpaper, as reported by SpringBoard.
        """
        return await self.service.send_recv_plist({"command": "getWallpaperInfo", "wallpaperName": wallpaper_name})

    async def reload_icon_state(self) -> None:
        """
        Re-apply the current icon layout by reading it back and writing it unchanged.

        Fetches the current icon state via `get_icon_state` and immediately sends it back
        through `set_icon_state`, forcing SpringBoard to reload its layout.
        """
        await self.set_icon_state(await self.get_icon_state())

    async def get_wallpaper_preview_image(self, wallpaper_name: str) -> bytes:
        """
        Retrieve the preview image for a named wallpaper.

        :param wallpaper_name: Name of the wallpaper whose preview image is requested.
        :returns: PNG-encoded preview image bytes.
        """
        return cast(
            bytes,
            (
                await self.service.send_recv_plist({
                    "command": "getWallpaperPreviewImage",
                    "wallpaperName": wallpaper_name,
                })
            )["pngData"],
        )
