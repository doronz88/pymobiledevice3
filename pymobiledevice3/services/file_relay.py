from typing import Optional

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

SRCFILES = """Baseband
CrashReporter
MobileAsset
VARFS
HFSMeta
Lockdown
MobileBackup
MobileDelete
MobileInstallation
MobileNotes
Network
UserDatabases
WiFi
WirelessAutomation
NANDDebugInfo
SystemConfiguration
Ubiquity
tmp
WirelessAutomation"""


class FileRelayService(LockdownService):
    """
    Retrieve diagnostic data archives from the device.

    Wraps the legacy ``com.apple.mobile.file_relay`` service, which bundles one or more
    named data sources (see `SRCFILES` for known source names) into a single gzip-compressed
    CPIO archive returned by `request_sources`.

    Being a `LockdownService`, instances may be used as an async context manager::

        async with FileRelayService(lockdown) as file_relay:
            archive = await file_relay.request_sources(["UserDatabases"])
    """

    SERVICE_NAME = "com.apple.mobile.file_relay"

    def __init__(self, lockdown: LockdownServiceProvider):
        super().__init__(lockdown, self.SERVICE_NAME)
        self.packet_num = 0

    async def stop_session(self):
        """Close the underlying service connection."""
        self.logger.info("Disconecting...")
        await self.service.close()

    async def request_sources(self, sources: Optional[list[str]] = None):
        """
        Request one or more data sources and return the combined archive.

        Sends the requested source names and, once the device acknowledges, reads the
        full response stream into memory.

        :param sources: list of source names to request (see `SRCFILES` for known names);
            defaults to ``["UserDatabases"]`` when not given.
        :returns: the gzip-compressed CPIO archive bytes on success, or None if the device
            did not acknowledge the request.
        """
        if sources is None:
            sources = ["UserDatabases"]
        await self.service.send_plist({"Sources": sources})
        while 1:
            res = await self.service.recv_plist()
            if res:
                s = res.get("Status")
                if s == "Acknowledged":
                    z = b""
                    while True:
                        x = await self.service.recv_any()
                        if not x:
                            break
                        z += x
                    return z
                else:
                    print(res.get("Error"))
                    break
        return None
