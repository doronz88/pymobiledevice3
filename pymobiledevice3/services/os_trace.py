#!/usr/bin/env python3

import logging
import plistlib
import struct
from datetime import datetime

from construct import Struct, Bytes, Int32ul, CString, Optional, Enum, Byte, Adapter

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

syslog_t = Struct(
    Bytes(9),
    'pid' / Int32ul,
    Bytes(42),
    'timestamp' / TimestampAdapter(timestamp_t),
    Bytes(1),
    'level' / Enum(Byte, Notice=0, Error=0x10, Fault=0x11),
    Bytes(1),
    Bytes(60),
    'filename' / CString('utf8'),
    'image_name' / CString('utf8'),
    'message' / CString('utf8'),
    'label' / Optional(Struct(
        'bundle_id' / CString('utf8'),
        'identifier' / CString('utf8')
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
        response = self.c.recv_prefixed()
        return plistlib.loads(response[1:])

    def create_archive(self) -> tuple:
        self.c.send_plist({'Request': 'CreateArchive'})
        response = self.c.recv_prefixed()
        length = response[0]
        return plistlib.loads(response[1:length + 1]), response[length + 1:]

    def syslog(self, pid=-1):
        self.c.send_plist({'Request': 'StartActivity', 'Pid': pid})

        length_length, = struct.unpack('<I', self.c.recvall(4))
        length = int(self.c.recvall(length_length)[::-1].hex(), 16)
        response = plistlib.loads(self.c.recvall(length))

        if response['Status'] != 'RequestSuccessful':
            raise PyMobileDevice3Exception(f'got invalid response: {response}')

        while True:
            assert b'\x02' == self.c.recvall(1)
            length, = struct.unpack('<I', self.c.recvall(4))
            line = self.c.recvall(length)
            entry = syslog_t.parse(line)
            yield entry
