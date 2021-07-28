#!/usr/bin/env python3
import logging
import plistlib
import struct
import tempfile
from datetime import datetime
from io import BytesIO
from tarfile import TarFile

from construct import Struct, Bytes, Int32ul, Optional, Enum, Byte, Adapter, Int16ul, this, Computed, \
    RepeatUntil
from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient

CHUNK_SIZE = 4096
TIME_FORMAT = '%H:%M:%S'
SYSLOG_LINE_SPLITTER = '\n\x00'


class TimestampAdapter(Adapter):
    def _decode(self, obj, context, path):
        return datetime.fromtimestamp(obj.seconds + (obj.microseconds / 1000000))

    def _encode(self, obj, context, path):
        return list(map(int, obj.split(".")))


timestamp_t = Struct(
    'seconds' / Int32ul,
    Bytes(4),
    'microseconds' / Int32ul
)


def try_decode(s):
    try:
        return s.decode('utf8')
    except UnicodeDecodeError:
        return s


syslog_t = Struct(
    Bytes(9),
    'pid' / Int32ul,
    Bytes(42),
    'timestamp' / TimestampAdapter(timestamp_t),
    Bytes(1),
    'level' / Enum(Byte, Notice=0, Info=0x01, Debug=0x02, Error=0x10, Fault=0x11),
    Bytes(38),
    'image_name_size' / Int16ul,
    'message_size' / Int16ul,
    Bytes(6),
    '_subsystem_size' / Int32ul,
    '_category_size' / Int32ul,
    Bytes(4),
    '_filename' / RepeatUntil(lambda x, lst, ctx: lst[-1] == 0, Byte),
    'filename' / Computed(lambda ctx: try_decode(bytearray(ctx._filename[:-1]))),
    '_image_name' / Bytes(this.image_name_size),
    'image_name' / Computed(lambda ctx: try_decode(ctx._image_name[:-1])),
    '_message' / Bytes(this.message_size),
    'message' / Computed(lambda ctx: try_decode(ctx._message[:-1])),
    'label' / Optional(Struct(
        '_subsystem' / Bytes(this._._subsystem_size),
        'subsystem' / Computed(lambda ctx: try_decode(ctx._subsystem[:-1])),
        '_category' / Bytes(this._._category_size),
        'category' / Computed(lambda ctx: try_decode(ctx._category[:-1])),
    )),
)


class OsTraceService(object):
    SERVICE_NAME = 'com.apple.os_trace_relay'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.c = self.lockdown.start_service(self.SERVICE_NAME)

    def get_pid_list(self):
        self.c.send_plist({'Request': 'PidList'})

        # ignore first received unknown byte
        self.c.recvall(1)

        response = self.c.recv_prefixed()
        return plistlib.loads(response)

    def create_archive(self, out: BytesIO):
        self.c.send_plist({'Request': 'CreateArchive'})

        assert 1 == self.c.recvall(1)[0]

        assert plistlib.loads(self.c.recv_prefixed()).get('Status') == 'RequestSuccessful', 'Invalid status'

        while True:
            try:
                assert 3 == self.c.recvall(1)[0], 'invalid magic'
            except ConnectionAbortedError:
                break
            out.write(self.c.recv_prefixed(endianity='<'))

    def collect(self, out: str):
        """
        Collect the system logs into a .logarchive that can be viewed later with tools such as log or Console.
        """
        with tempfile.NamedTemporaryFile() as tar:
            self.create_archive(tar)
            TarFile(tar.name).extractall(out)

    def syslog(self, pid=-1):
        self.c.send_plist({'Request': 'StartActivity', 'MessageFilter': 65535, 'Pid': pid, 'StreamFlags': 60})

        length_length, = struct.unpack('<I', self.c.recvall(4))
        length = int(self.c.recvall(length_length)[::-1].hex(), 16)
        response = plistlib.loads(self.c.recvall(length))

        if response.get('Status') != 'RequestSuccessful':
            raise PyMobileDevice3Exception(f'got invalid response: {response}')

        while True:
            assert b'\x02' == self.c.recvall(1)
            length, = struct.unpack('<I', self.c.recvall(4))
            line = self.c.recvall(length)
            entry = syslog_t.parse(line)
            yield entry
