from typing import Generator

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class DiagnosticsServiceService(CoreDeviceService):
    """
    Obtain device diagnostics
    """

    SERVICE_NAME = 'com.apple.coredevice.diagnosticsservice'

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    def capture_sysdiagnose(self, is_dry_run: bool) -> Generator[bytes, None, None]:
        response = self.invoke('com.apple.coredevice.feature.capturesysdiagnose', {'isDryRun': is_dry_run})
        return self.service.iter_file_chunks(response['fileTransfer']['expectedLength'])
