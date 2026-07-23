import plistlib
from typing import Any

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

CHUNK_SIZE = 200


class DebugServerAppList(LockdownService):
    """
    Retrieve the list of installed applications as seen by debugserver, via the
    ``com.apple.debugserver.DVTSecureSocketProxy.applist`` service.
    """

    SERVICE_NAME = "com.apple.debugserver.DVTSecureSocketProxy.applist"

    def __init__(self, lockdown: LockdownServiceProvider):
        super().__init__(lockdown, self.SERVICE_NAME)

    async def get(self) -> dict[str, Any]:
        """
        Fetch the application list.

        Reads the full plist response from the service and parses it.

        :returns: The parsed application list, keyed by bundle identifier.
        """
        buf = b""
        while b"</plist>" not in buf:
            buf += await self.service.recv_any(CHUNK_SIZE)

        return plistlib.loads(buf)
