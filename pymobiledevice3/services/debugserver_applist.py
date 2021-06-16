import logging
import plistlib

from pymobiledevice3.lockdown import LockdownClient

CHUNK_SIZE = 200


class DebugServerAppList(object):
    SERVICE_NAME = 'com.apple.debugserver.DVTSecureSocketProxy.applist'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_developer_service(self.SERVICE_NAME)

    def get(self) -> dict:
        buf = b''
        while b'</plist>' not in buf:
            buf += self.service.recv(CHUNK_SIZE)

        return plistlib.loads(buf)
