from typing import Generator

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class DiagnosticsServiceService(RemoteService):
    """
    Obtain device diagnostics
    """

    SERVICE_NAME = 'com.apple.coredevice.diagnosticsservice'

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    def capture_sysdiagnose(self, is_dry_run: bool) -> Generator[bytes, None, None]:
        response = self.invoke('com.apple.coredevice.feature.capturesysdiagnose', {'isDryRun': is_dry_run})
        return self.service.receive_file(response['fileTransfer']['expectedLength'])
