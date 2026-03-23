from enum import IntEnum
from typing import Optional

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import build_plist
from pymobiledevice3.services.lockdown_service import LockdownService


class InterfaceOrientation(IntEnum):
    PORTRAIT = 1
    PORTRAIT_UPSIDE_DOWN = 2
    LANDSCAPE = 3
    LANDSCAPE_HOME_TO_LEFT = 4


class SpringBoardServicesService(LockdownService):
    RSD_SERVICE_NAME = "com.apple.springboardservices.shim.remote"
    SERVICE_NAME = "com.apple.springboardservices"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def get_icon_state(self, format_version: str = "2") -> list:
        cmd = {"command": "getIconState"}
        if format_version:
            cmd["formatVersion"] = format_version
        return await self.service.send_recv_plist(cmd)

    async def set_icon_state(self, newstate: Optional[list] = None) -> None:
        if newstate is None:
            newstate = {}
        await self.service.send_recv_prefixed(build_plist({"command": "setIconState", "iconState": newstate}))

    async def get_icon_pngdata(self, bundle_id: str) -> bytes:
        return (await self.service.send_recv_plist({"command": "getIconPNGData", "bundleId": bundle_id})).get("pngData")

    async def get_interface_orientation(self) -> InterfaceOrientation:
        res = await self.service.send_recv_plist({"command": "getInterfaceOrientation"})
        return InterfaceOrientation(res.get("interfaceOrientation"))

    async def get_wallpaper_pngdata(self) -> bytes:
        return (await self.service.send_recv_plist({"command": "getHomeScreenWallpaperPNGData"})).get("pngData")

    async def get_homescreen_icon_metrics(self) -> dict[str, float]:
        return await self.service.send_recv_plist({"command": "getHomeScreenIconMetrics"})

    async def get_wallpaper_info(self, wallpaper_name: str) -> dict:
        return await self.service.send_recv_plist({"command": "getWallpaperInfo", "wallpaperName": wallpaper_name})

    async def reload_icon_state(self) -> None:
        await self.set_icon_state(await self.get_icon_state())

    async def get_wallpaper_preview_image(self, wallpaper_name: str) -> bytes:
        return (
            await self.service.send_recv_plist({"command": "getWallpaperPreviewImage", "wallpaperName": wallpaper_name})
        )["pngData"]
