import plistlib
import typing

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.lockdown_service import LockdownService

CHUNK_SIZE = 200


class DebugServerAppList(LockdownService):
    SERVICE_NAME = 'com.apple.debugserver.DVTSecureSocketProxy.applist'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME)

    def get(self) -> typing.Mapping:
        buf = b''
        while b'</plist>' not in buf:
            buf += self.service.recv(CHUNK_SIZE)

        return plistlib.loads(buf)
