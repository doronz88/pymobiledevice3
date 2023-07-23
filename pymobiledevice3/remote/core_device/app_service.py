import plistlib
from typing import List, Mapping

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type


class AppServiceService(CoreDeviceService):
    """
    Manage applications
    """

    SERVICE_NAME = 'com.apple.coredevice.appservice'

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    def list_apps(self, include_app_clips: bool = True, include_removable_apps: bool = True,
                  include_hidden_apps: bool = True, include_internal_apps: bool = True,
                  include_default_apps: bool = True) -> List[Mapping]:
        """ List applications """
        return self.invoke('com.apple.coredevice.feature.listapps', {
            'includeAppClips': include_app_clips, 'includeRemovableApps': include_removable_apps,
            'includeHiddenApps': include_hidden_apps, 'includeInternalApps': include_internal_apps,
            'includeDefaultApps': include_default_apps})

    def list_processes(self) -> List[Mapping]:
        """ List processes """
        return self.invoke('com.apple.coredevice.feature.listprocesses')['processTokens']

    def list_roots(self) -> Mapping:
        """
        List roots.

        Can only be performed on certain devices
        """
        return self.invoke('com.apple.coredevice.feature.listroots', {
            'rootPoint': {
                'relative': '/'
            }})

    def spawn_executable(self, executable: str, arguments: List[str]) -> Mapping:
        """
        Spawn given executable.

        Can only be performed on certain devices
        """
        return self.invoke('com.apple.coredevice.feature.spawnexecutable', {
            'executableItem': {
                'url': {
                    '_0': {
                        'relative': executable,
                    },
                }
            },
            'standardIOIdentifiers': {},
            'options': {
                'arguments': arguments,
                'environmentVariables': {},
                'standardIOUsesPseudoterminals': True,
                'startStopped': False,
                'user': {
                    'active': True,
                },
                'platformSpecificOptions': plistlib.dumps({}),
            },
        })

    def monitor_process_termination(self, pid: int) -> Mapping:
        """
        Monitor process termination.

        Can only be performed on certain devices
        """
        return self.invoke('com.apple.coredevice.feature.monitorprocesstermination', {
            'processToken': {'processIdentifier': XpcInt64Type(pid)}})

    def uninstall_app(self, bundle_identifier: str) -> None:
        """
        Uninstall given application by its bundle identifier
        """
        self.invoke('com.apple.coredevice.feature.uninstallapp', {'bundleIdentifier': bundle_identifier})

    def send_signal_to_process(self, pid: int, signal: int) -> Mapping:
        """
        Send signal to given process by its pid
        """
        return self.invoke('com.apple.coredevice.feature.sendsignaltoprocess', {
            'process': {'processIdentifier': XpcInt64Type(pid)},
            'signal': XpcInt64Type(signal),
        })

    def fetch_icons(self, bundle_identifier: str, width: float, height: float, scale: float,
                    allow_placeholder: bool) -> Mapping:
        """
        Fetch given application's icons
        """
        return self.invoke('com.apple.coredevice.feature.fetchappicons', {
            'width': width,
            'height': height,
            'scale': scale,
            'allowPlaceholder': allow_placeholder,
            'bundleIdentifier': bundle_identifier
        })
