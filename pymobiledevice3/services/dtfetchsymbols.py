import logging
import struct
import typing

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient


class DtFetchSymbols:
    SERVICE_NAME = 'com.apple.dt.fetchsymbols'
    MAX_CHUNK = 1024 * 1024 * 10  # 10MB
    CMD_LIST_FILES_PLIST = struct.pack('>I', 0x30303030)
    CMD_GET_FILE = struct.pack('>I', 1)

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

    def list_files(self) -> typing.List[str]:
        service = self._start_command(self.CMD_LIST_FILES_PLIST)
        return service.recv_plist().get('files')

    def get_file(self, fileno: int, stream: typing.IO):
        service = self._start_command(self.CMD_GET_FILE)
        service.sendall(struct.pack('>I', fileno))

        size = struct.unpack('>Q', service.recvall(8))[0]
        self.logger.debug(f'file size: {size}')

        received = 0
        while received < size:
            buf = service.recv(min(size - received, self.MAX_CHUNK))
            stream.write(buf)
            received += len(buf)

    def _start_command(self, cmd: bytes):
        service = self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        service.sendall(cmd)

        # receive same command as an ack
        if cmd != service.recvall(len(cmd)):
            raise PyMobileDevice3Exception('bad ack')

        return service
