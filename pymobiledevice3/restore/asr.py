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
ASR_PORT = 12345
ASR_FEC_SLICE_STRIDE = 40
ASR_PACKETS_PER_FEC = 25
ASR_PAYLOAD_PACKET_SIZE = 1450
ASR_PAYLOAD_CHUNK_SIZE = 0x20000
ASR_CHECKSUM_CHUNK_SIZE = ASR_PAYLOAD_CHUNK_SIZE

logger = logging.getLogger(__name__)


class ASRClient(object):
    """
    ASR — Apple Software Restore
    """

    SERVICE_PORT = ASR_PORT

    def __init__(self, udid: str):
        self.service = ServiceConnection.create(udid, self.SERVICE_PORT)

        # receive Initiate command message
        data = self.recv_plist()
        logger.debug(f'got command: {data}')

        command = data.get('Command')
        if command != 'Initiate':
            raise PyMobileDevice3Exception(f'invalid command received: {command}')

        self.checksum_chunks = data.get('Checksum Chunks', False)
        logger.debug(f'Checksum Chunks: {self.checksum_chunks}')

    def recv_plist(self) -> typing.Mapping:
        buf = b''
        while not buf.endswith(b'</plist>\n'):
            buf += self.service.recv()
        return plistlib.loads(buf)

    def send_plist(self, plist: typing.Mapping):
        logger.debug(plistlib.dumps(plist).decode())
        self.service.sendall(plistlib.dumps(plist))

    def send_buffer(self, buf: bytes):
        self.service.sendall(buf)

    def handle_oob_data_request(self, packet: typing.Mapping, filesystem: typing.IO):
        oob_length = packet['OOB Length']
        oob_offset = packet['OOB Offset']
        filesystem.seek(oob_offset, os.SEEK_SET)

        oob_data = filesystem.read(oob_length)
        assert len(oob_data) == oob_length

        self.send_buffer(oob_data)

    def perform_validation(self, filesystem: typing.IO):
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

        self.send_plist(packet_info)

        while True:
            packet = self.recv_plist()
            logger.debug(f'perform_validation: {packet}')
            command = packet['Command']

            if command == 'Payload':
                break

            elif command == 'OOBData':
                self.handle_oob_data_request(packet, filesystem)

            else:
                raise PyMobileDevice3Exception(f'unknown packet: {packet}')

    def send_payload(self, filesystem: typing.IO):
        filesystem.seek(0, os.SEEK_END)
        length = filesystem.tell()
        filesystem.seek(0, os.SEEK_SET)

        for _ in trange(0, length, ASR_PAYLOAD_CHUNK_SIZE, dynamic_ncols=True):
            chunk = filesystem.read(ASR_PAYLOAD_CHUNK_SIZE)

            if self.checksum_chunks:
                chunk += hashlib.sha1(chunk).digest()

            self.send_buffer(chunk)
