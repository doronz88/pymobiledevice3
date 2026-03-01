from enum import IntEnum
from typing import Optional

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
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
        await self.service.send_plist(cmd)
        return await self.service.recv_plist()

    async def set_icon_state(self, newstate: Optional[list] = None) -> None:
        if newstate is None:
            newstate = {}
        await self.service.send_plist({"command": "setIconState", "iconState": newstate})
        await self.service.recv_prefixed()

    async def get_icon_pngdata(self, bundle_id: str) -> bytes:
        await self.service.send_plist({"command": "getIconPNGData", "bundleId": bundle_id})
        return (await self.service.recv_plist()).get("pngData")

    async def get_interface_orientation(self) -> InterfaceOrientation:
        await self.service.send_plist({"command": "getInterfaceOrientation"})
        res = await self.service.recv_plist()
        return InterfaceOrientation(res.get("interfaceOrientation"))

    async def get_wallpaper_pngdata(self) -> bytes:
        await self.service.send_plist({"command": "getHomeScreenWallpaperPNGData"})
        return (await self.service.recv_plist()).get("pngData")

    async def get_homescreen_icon_metrics(self) -> dict[str, float]:
        await self.service.send_plist({"command": "getHomeScreenIconMetrics"})
        return await self.service.recv_plist()

    async def get_wallpaper_info(self, wallpaper_name: str) -> dict:
        await self.service.send_plist({"command": "getWallpaperInfo", "wallpaperName": wallpaper_name})
        return await self.service.recv_plist()

    async def reload_icon_state(self) -> None:
        await self.set_icon_state(await self.get_icon_state())

    async def get_wallpaper_preview_image(self, wallpaper_name: str) -> bytes:
        await self.service.send_plist({"command": "getWallpaperPreviewImage", "wallpaperName": wallpaper_name})
        return (await self.service.recv_plist())["pngData"]
