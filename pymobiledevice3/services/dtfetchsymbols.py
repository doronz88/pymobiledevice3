import logging
import struct
import typing

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient


class DtFetchSymbols:
    SERVICE_NAME = "com.apple.dt.fetchsymbols"
    MAX_CHUNK = 1024 * 1024 * 10  # 10MB
    CMD_LIST_FILES_PLIST = struct.pack(">I", 0x30303030)
    CMD_GET_FILE = struct.pack(">I", 1)

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

    async def list_files(self) -> list[str]:
        service = await self._start_command(self.CMD_LIST_FILES_PLIST)
        files = (await service.recv_plist()).get("files")
        await service.close()
        return files

    async def get_file(self, fileno: int, stream: typing.IO):
        service = await self._start_command(self.CMD_GET_FILE)
        await service.sendall(struct.pack(">I", fileno))

        size = struct.unpack(">Q", await service.recvall(8))[0]
        self.logger.debug(f"file size: {size}")

        received = 0
        while received < size:
            chunk_size = min(size - received, self.MAX_CHUNK)
            buf = await service.recvall(chunk_size)
            stream.write(buf)
            received += len(buf)
        await service.close()

    async def _start_command(self, cmd: bytes):
        service = await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        await service.sendall(cmd)

        # receive same command as an ack
        if cmd != await service.recvall(len(cmd)):
            raise PyMobileDevice3Exception("bad ack")

        return service
