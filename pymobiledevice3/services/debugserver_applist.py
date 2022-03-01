import plistlib
import typing

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService

CHUNK_SIZE = 200


class DebugServerAppList(BaseService):
    SERVICE_NAME = 'com.apple.debugserver.DVTSecureSocketProxy.applist'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME)

    def get(self) -> typing.Mapping:
        buf = b''
        while b'</plist>' not in buf:
            buf += self.service.recv(CHUNK_SIZE)

        return plistlib.loads(buf)
