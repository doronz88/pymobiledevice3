import dataclasses
from collections.abc import AsyncGenerator

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


@dataclasses.dataclass
class SysDiagnoseResponse:
    preferred_filename: str
    file_size: int
    generator: AsyncGenerator[bytes, None]


class DiagnosticsServiceService(CoreDeviceService):
    """
    Obtain device diagnostics
    """

    SERVICE_NAME = "com.apple.coredevice.diagnosticsservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def capture_sysdiagnose(self, is_dry_run: bool) -> SysDiagnoseResponse:
        response = await self.invoke(
            "com.apple.coredevice.feature.capturesysdiagnose",
            {"options": {"collectFullLogs": True}, "isDryRun": is_dry_run},
        )
        return SysDiagnoseResponse(
            file_size=response["fileTransfer"]["expectedLength"],
            preferred_filename=response["preferredFilename"],
            generator=self.service.iter_file_chunks(response["fileTransfer"]["expectedLength"]),
        )
