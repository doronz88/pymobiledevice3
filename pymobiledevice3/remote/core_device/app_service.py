import plistlib
from typing import Optional

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type


class AppServiceService(CoreDeviceService):
    """
    Manage applications
    """

    SERVICE_NAME = "com.apple.coredevice.appservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def list_apps(
        self,
        include_app_clips: bool = True,
        include_removable_apps: bool = True,
        include_hidden_apps: bool = True,
        include_internal_apps: bool = True,
        include_default_apps: bool = True,
    ) -> list[dict]:
        """List applications"""
        return await self.invoke(
            "com.apple.coredevice.feature.listapps",
            {
                "includeAppClips": include_app_clips,
                "includeRemovableApps": include_removable_apps,
                "includeHiddenApps": include_hidden_apps,
                "includeInternalApps": include_internal_apps,
                "includeDefaultApps": include_default_apps,
            },
        )

    async def launch_application(
        self,
        bundle_id: str,
        arguments: Optional[list[str]] = None,
        kill_existing: bool = True,
        start_suspended: bool = False,
        environment: Optional[dict] = None,
        extra_options: Optional[dict] = None,
    ) -> list[dict]:
        """launch application"""
        return await self.invoke(
            "com.apple.coredevice.feature.launchapplication",
            {
                "applicationSpecifier": {
                    "bundleIdentifier": {"_0": bundle_id},
                },
                "options": {
                    "arguments": arguments if arguments is not None else [],
                    "environmentVariables": environment if environment is not None else {},
                    "standardIOUsesPseudoterminals": True,
                    "startStopped": start_suspended,
                    "terminateExisting": kill_existing,
                    "user": {"shortName": "mobile"},
                    "platformSpecificOptions": plistlib.dumps(extra_options if extra_options is not None else {}),
                },
                "standardIOIdentifiers": {},
            },
        )

    async def list_processes(self) -> list[dict]:
        """List processes"""
        return (await self.invoke("com.apple.coredevice.feature.listprocesses"))["processTokens"]

    async def list_roots(self) -> dict:
        """
        List roots.

        Can only be performed on certain devices
        """
        return await self.invoke("com.apple.coredevice.feature.listroots", {"rootPoint": {"relative": "/"}})

    async def spawn_executable(self, executable: str, arguments: list[str]) -> dict:
        """
        Spawn given executable.

        Can only be performed on certain devices
        """
        return await self.invoke(
            "com.apple.coredevice.feature.spawnexecutable",
            {
                "executableItem": {
                    "url": {
                        "_0": {
                            "relative": executable,
                        },
                    }
                },
                "standardIOIdentifiers": {},
                "options": {
                    "arguments": arguments,
                    "environmentVariables": {},
                    "standardIOUsesPseudoterminals": True,
                    "startStopped": False,
                    "user": {
                        "active": True,
                    },
                    "platformSpecificOptions": plistlib.dumps({}),
                },
            },
        )

    async def monitor_process_termination(self, pid: int) -> dict:
        """
        Monitor process termination.

        Can only be performed on certain devices
        """
        return await self.invoke(
            "com.apple.coredevice.feature.monitorprocesstermination",
            {"processToken": {"processIdentifier": XpcInt64Type(pid)}},
        )

    async def uninstall_app(self, bundle_identifier: str) -> None:
        """
        Uninstall given application by its bundle identifier
        """
        await self.invoke("com.apple.coredevice.feature.uninstallapp", {"bundleIdentifier": bundle_identifier})

    async def send_signal_to_process(self, pid: int, signal: int) -> dict:
        """
        Send signal to given process by its pid
        """
        return await self.invoke(
            "com.apple.coredevice.feature.sendsignaltoprocess",
            {
                "process": {"processIdentifier": XpcInt64Type(pid)},
                "signal": XpcInt64Type(signal),
            },
        )

    async def fetch_icons(
        self, bundle_identifier: str, width: float, height: float, scale: float, allow_placeholder: bool
    ) -> dict:
        """
        Fetch given application's icons
        """
        return await self.invoke(
            "com.apple.coredevice.feature.fetchappicons",
            {
                "width": width,
                "height": height,
                "scale": scale,
                "allowPlaceholder": allow_placeholder,
                "bundleIdentifier": bundle_identifier,
            },
        )
