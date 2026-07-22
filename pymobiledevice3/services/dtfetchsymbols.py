import logging
import struct
import typing

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


class DtFetchSymbols:
    """
    Client for the `com.apple.dt.fetchsymbols` developer service.

    Lists and downloads the device's shared cache (DSC) symbol files, used by debuggers
    to symbolicate addresses without a copy of the device's binaries on the host. A fresh
    lockdown developer service connection is opened for each command.
    """

    SERVICE_NAME = "com.apple.dt.fetchsymbols"
    MAX_CHUNK = 1024 * 1024 * 10  # 10MB
    CMD_LIST_FILES_PLIST = struct.pack(">I", 0x30303030)
    CMD_GET_FILE = struct.pack(">I", 1)

    def __init__(self, lockdown: LockdownServiceProvider):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

    async def list_files(self) -> list[str]:
        """
        List the symbol files available on the device.

        :returns: File names, indexed in the same order the index passed to `get_file` refers to.
        """
        service = await self._start_command(self.CMD_LIST_FILES_PLIST)
        files = (await service.recv_plist()).get("files")
        await service.close()
        if files is None:
            raise PyMobileDevice3Exception("list files response is missing the 'files' entry")
        return files

    async def get_file(self, fileno: int, stream: typing.IO, max_bytes: typing.Optional[int] = None):
        """
        Download a single symbol file and write it into the given stream.

        :param fileno: Index of the file to fetch, as returned by `list_files`.
        :param stream: Writable binary stream the file contents are written to in chunks.
        :param max_bytes: Optional cap on the number of bytes to read; when None the whole
            file is downloaded.
        """
        service = await self._start_command(self.CMD_GET_FILE)
        await service.sendall(struct.pack(">I", fileno))

        size = struct.unpack(">Q", await service.recvall(8))[0]
        self.logger.debug(f"file size: {size}")

        limit = size if max_bytes is None else min(size, max_bytes)
        received = 0
        while received < limit:
            chunk_size = min(limit - received, self.MAX_CHUNK)
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
