#!/usr/bin/env python3

import plistlib
import logging
import struct

from construct import Struct, Bytes, Int32ul, CString, Timestamp, Optional, Enum, Byte, Probe

from pymobiledevice3.lockdown import LockdownClient

CHUNK_SIZE = 4096
TIME_FORMAT = '%H:%M:%S'
SYSLOG_LINE_SPLITTER = '\n\x00'

syslog_t = Struct(
    Bytes(9),
    'pid' / Int32ul,
    Bytes(42),
    'timestamp' / Timestamp(Int32ul, 1., 1970),
    Bytes(9),
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
        response = self.c.recv_raw()
        return plistlib.loads(response[1:])

    def create_archive(self) -> tuple:
        self.c.send_plist({'Request': 'CreateArchive'})
        response = self.c.recv_raw()
        length = response[0]
        return plistlib.loads(response[1:length + 1]), response[length + 1:]

    def syslog(self, pid=-1):
        self.c.send_plist({'Request': 'StartActivity', 'Pid': pid})

        length_length, = struct.unpack('<I', self.c.recv_exact(4))
        length = int(self.c.recv_exact(length_length)[::-1].hex(), 16)
        response = plistlib.loads(self.c.recv_exact(length))

        if response['Status'] != 'RequestSuccessful':
            raise Exception(f'got invalid response: {response}')

        while True:
            assert b'\x02' == self.c.recv_exact(1)
            length, = struct.unpack('<I', self.c.recv_exact(4))
            line = self.c.recv_exact(length)
            entry = syslog_t.parse(line)
            yield entry
