#!/usr/bin/env python3
import plistlib
import struct
import tempfile
import typing
from datetime import datetime
from tarfile import TarFile

from construct import Adapter, Byte, Bytes, Computed, Enum, Int16ul, Int32ul, Optional, RepeatUntil, Struct, this

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import try_decode

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


class OsTraceService(LockdownService):
    """
    Provides API for the following operations:
    * Show process list (process name and pid)
    * Stream syslog lines in binary form with optional filtering by pid.
    * Get old stored syslog archive in PAX format (can be extracted using `pax -r < filename`).
        * Archive contain the contents are the `/var/db/diagnostics` directory
    """
    SERVICE_NAME = 'com.apple.os_trace_relay'
    RSD_SERVICE_NAME = 'com.apple.os_trace_relay.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def get_pid_list(self):
        self.service.send_plist({'Request': 'PidList'})

        # ignore first received unknown byte
        self.service.recvall(1)

        response = self.service.recv_prefixed()
        return plistlib.loads(response)

    def create_archive(self, out: typing.IO, size_limit: int = None, age_limit: int = None, start_time: int = None):
        request = {'Request': 'CreateArchive'}

        if size_limit is not None:
            request.update({'SizeLimit': size_limit})

        if age_limit is not None:
            request.update({'AgeLimit': age_limit})

        if start_time is not None:
            request.update({'StartTime': start_time})

        self.service.send_plist(request)

        assert 1 == self.service.recvall(1)[0]

        assert plistlib.loads(self.service.recv_prefixed()).get('Status') == 'RequestSuccessful', 'Invalid status'

        while True:
            try:
                assert 3 == self.service.recvall(1)[0], 'invalid magic'
            except ConnectionAbortedError:
                break
            out.write(self.service.recv_prefixed(endianity='<'))

    def collect(self, out: str, size_limit: int = None, age_limit: int = None, start_time: int = None):
        """
        Collect the system logs into a .logarchive that can be viewed later with tools such as log or Console.
        """
        with tempfile.NamedTemporaryFile() as tar:
            self.create_archive(tar, size_limit=size_limit, age_limit=age_limit, start_time=start_time)
            TarFile(tar.name).extractall(out)

    def syslog(self, pid=-1):
        self.service.send_plist({'Request': 'StartActivity', 'MessageFilter': 65535, 'Pid': pid, 'StreamFlags': 60})

        length_length, = struct.unpack('<I', self.service.recvall(4))
        length = int(self.service.recvall(length_length)[::-1].hex(), 16)
        response = plistlib.loads(self.service.recvall(length))

        if response.get('Status') != 'RequestSuccessful':
            raise PyMobileDevice3Exception(f'got invalid response: {response}')

        while True:
            assert b'\x02' == self.service.recvall(1)
            length, = struct.unpack('<I', self.service.recvall(4))
            line = self.service.recvall(length)
            entry = syslog_t.parse(line)
            yield entry
