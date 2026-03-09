import plistlib

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

CHUNK_SIZE = 200


class DebugServerAppList(LockdownService):
    SERVICE_NAME = "com.apple.debugserver.DVTSecureSocketProxy.applist"

    def __init__(self, lockdown: LockdownServiceProvider):
        super().__init__(lockdown, self.SERVICE_NAME)

    async def get(self) -> dict:
        buf = b""
        while b"</plist>" not in buf:
            buf += await self.service.recv_any(CHUNK_SIZE)

        return plistlib.loads(buf)
