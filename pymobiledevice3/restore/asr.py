import asyncio
import hashlib
import logging
import os
import plistlib
import typing

from tqdm import trange

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.service_connection import ServiceConnection

ASR_VERSION = 1
ASR_STREAM_ID = 1
DEFAULT_ASR_SYNC_PORT = 12345
ASR_FEC_SLICE_STRIDE = 40
ASR_PACKETS_PER_FEC = 25
ASR_PAYLOAD_PACKET_SIZE = 1450
ASR_PAYLOAD_CHUNK_SIZE = 0x20000
ASR_CHECKSUM_CHUNK_SIZE = ASR_PAYLOAD_CHUNK_SIZE

logger = logging.getLogger(__name__)


class ASRClient:
    """
    ASR — Apple Software Restore
    """

    def __init__(self, udid: str) -> None:
        self._udid: str = udid
        self.logger = logging.getLogger(f'{asyncio.current_task().get_name()}-{__name__}')
        self.service: typing.Optional[ServiceConnection] = None
        self.checksum_chunks: bool = False

    async def connect(self, port: int = DEFAULT_ASR_SYNC_PORT) -> None:
        self.service = ServiceConnection.create_using_usbmux(self._udid, port, connection_type='USB')
        await self.service.aio_start()

        # receive Initiate command message
        data = await self.recv_plist()
        self.logger.debug(f'got command: {data}')

        command = data.get('Command')
        if command != 'Initiate':
            raise PyMobileDevice3Exception(f'invalid command received: {command}')

        self.checksum_chunks = data.get('Checksum Chunks', False)
        self.logger.debug(f'Checksum Chunks: {self.checksum_chunks}')

    async def recv_plist(self) -> typing.Mapping:
        buf = b''
        while not buf.endswith(b'</plist>\n'):
            buf += await self.service.aio_recvall(1)
        return plistlib.loads(buf)

    async def send_plist(self, plist: typing.Mapping) -> None:
        self.logger.debug(plistlib.dumps(plist).decode())
        await self.send_buffer(plistlib.dumps(plist))

    async def send_buffer(self, buf: bytes) -> None:
        await self.service.aio_sendall(buf)

    async def handle_oob_data_request(self, packet: typing.Mapping, filesystem: typing.IO):
        oob_length = packet['OOB Length']
        oob_offset = packet['OOB Offset']
        filesystem.seek(oob_offset, os.SEEK_SET)

        oob_data = filesystem.read(oob_length)
        assert len(oob_data) == oob_length

        await self.send_buffer(oob_data)

    async def perform_validation(self, filesystem: typing.IO) -> None:
        filesystem.seek(0, os.SEEK_END)
        length = filesystem.tell()
        filesystem.seek(0, os.SEEK_SET)

        payload_info = {
            'Port': 1,
            'Size': length,
        }

        packet_info = dict()
        if self.checksum_chunks:
            packet_info['Checksum Chunk Size'] = ASR_CHECKSUM_CHUNK_SIZE

        packet_info['FEC Slice Stride'] = ASR_FEC_SLICE_STRIDE
        packet_info['Packet Payload Size'] = ASR_PAYLOAD_PACKET_SIZE
        packet_info['Packets Per FEC'] = ASR_PACKETS_PER_FEC
        packet_info['Payload'] = payload_info
        packet_info['Stream ID'] = ASR_STREAM_ID
        packet_info['Version'] = ASR_VERSION

        await self.send_plist(packet_info)

        while True:
            packet = await self.recv_plist()
            self.logger.debug(f'perform_validation: {packet}')
            command = packet['Command']

            if command == 'Payload':
                break

            elif command == 'OOBData':
                await self.handle_oob_data_request(packet, filesystem)

            else:
                raise PyMobileDevice3Exception(f'unknown packet: {packet}')

    async def send_payload(self, filesystem: typing.IO) -> None:
        filesystem.seek(0, os.SEEK_END)
        length = filesystem.tell()
        filesystem.seek(0, os.SEEK_SET)

        for _ in trange(0, length, ASR_PAYLOAD_CHUNK_SIZE, dynamic_ncols=True):
            chunk = filesystem.read(ASR_PAYLOAD_CHUNK_SIZE)

            if self.checksum_chunks:
                chunk += hashlib.sha1(chunk).digest()

            await self.send_buffer(chunk)

    async def close(self) -> None:
        await self.service.aio_close()
