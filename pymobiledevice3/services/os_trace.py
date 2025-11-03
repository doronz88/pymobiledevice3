#!/usr/bin/env python3
import dataclasses
import plistlib
import struct
import tempfile
import typing
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from tarfile import TarFile

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import try_decode

CHUNK_SIZE = 4096
TIME_FORMAT = "%H:%M:%S"
SYSLOG_LINE_SPLITTER = "\n\x00"


class SyslogLogLevel(IntEnum):
    NOTICE = 0x00
    INFO = 0x01
    DEBUG = 0x02

    # deducted from console-app
    USER_ACTION = 0x03
    ERROR = 0x10
    FAULT = 0x11


@dataclasses.dataclass
class SyslogLabel:
    category: str
    subsystem: str


@dataclasses.dataclass
class SyslogEntry:
    pid: int
    timestamp: datetime
    level: SyslogLogLevel
    image_name: str
    filename: str
    message: str
    label: typing.Optional[SyslogLabel] = None


def parse_syslog_entry(data: bytes) -> SyslogEntry:
    """
    Parse a syslog entry from binary data.

    :param data: Raw binary data
    :return: SyslogEntry
    """
    offset = 0

    # Skip first 9 bytes
    offset += 9

    # Parse pid (4 bytes, little-endian unsigned int)
    pid = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4

    # Skip 42 bytes
    offset += 42

    # Parse timestamp
    seconds = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4
    offset += 4  # Skip 4 bytes
    microseconds = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4
    timestamp = datetime.fromtimestamp(seconds + (microseconds / 1000000))

    # Skip 1 byte
    offset += 1

    # Parse level (1 byte)
    level = data[offset]
    offset += 1

    # Skip 38 bytes
    offset += 38

    # Parse image_name_size (2 bytes, little-endian unsigned short)
    image_name_size = struct.unpack("<H", data[offset : offset + 2])[0]
    offset += 2

    # Parse message_size (2 bytes, little-endian unsigned short)
    message_size = struct.unpack("<H", data[offset : offset + 2])[0]
    offset += 2

    # Skip 6 bytes
    offset += 6

    # Parse subsystem_size (4 bytes, little-endian unsigned int)
    subsystem_size = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4

    # Parse category_size (4 bytes, little-endian unsigned int)
    category_size = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4

    # Skip 4 bytes
    offset += 4

    # Parse filename (null-terminated)
    filename_end = data.find(b"\x00", offset)
    filename = try_decode(data[offset:filename_end])
    offset = filename_end + 1

    # Parse image_name
    image_name = try_decode(data[offset : offset + image_name_size - 1])
    offset += image_name_size

    # Parse message
    message = try_decode(data[offset : offset + message_size - 1])
    offset += message_size

    # Parse label (optional)
    label = None
    if subsystem_size > 0 and category_size > 0:
        subsystem = try_decode(data[offset : offset + subsystem_size - 1])
        offset += subsystem_size
        category = try_decode(data[offset : offset + category_size - 1])
        offset += category_size
        label = SyslogLabel(subsystem=subsystem, category=category)

    return SyslogEntry(
        pid=pid,
        timestamp=timestamp,
        level=SyslogLogLevel(level),
        image_name=image_name,
        filename=filename,
        message=message,
        label=label,
    )


class OsTraceService(LockdownService):
    """
    Provides API for the following operations:
    * Show process list (process name and pid)
    * Stream syslog lines in binary form with optional filtering by pid.
    * Get old stored syslog archive in PAX format (can be extracted using `pax -r < filename`).
        * Archive contain the contents are the `/var/db/diagnostics` directory
    """

    SERVICE_NAME = "com.apple.os_trace_relay"
    RSD_SERVICE_NAME = "com.apple.os_trace_relay.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def get_pid_list(self):
        self.service.send_plist({"Request": "PidList"})

        # ignore first received unknown byte
        self.service.recvall(1)

        response = self.service.recv_prefixed()
        return plistlib.loads(response)

    def create_archive(
        self,
        out: typing.IO,
        size_limit: typing.Optional[int] = None,
        age_limit: typing.Optional[int] = None,
        start_time: typing.Optional[int] = None,
    ):
        request = {"Request": "CreateArchive"}

        if size_limit is not None:
            request.update({"SizeLimit": size_limit})

        if age_limit is not None:
            request.update({"AgeLimit": age_limit})

        if start_time is not None:
            request.update({"StartTime": start_time})

        self.service.send_plist(request)

        assert self.service.recvall(1)[0] == 1

        assert plistlib.loads(self.service.recv_prefixed()).get("Status") == "RequestSuccessful", "Invalid status"

        while True:
            try:
                assert self.service.recvall(1)[0] == 3, "invalid magic"
            except ConnectionAbortedError:
                break
            out.write(self.service.recv_prefixed(endianity="<"))

    def collect(
        self,
        out: str,
        size_limit: typing.Optional[int] = None,
        age_limit: typing.Optional[int] = None,
        start_time: typing.Optional[int] = None,
    ) -> None:
        """
        Collect the system logs into a .logarchive that can be viewed later with tools such as log or Console.

        :param out: output file name
        :param size_limit: maximum size in bytes of logarchive
        :param age_limit: maximum age in days
        :param start_time: start time of logarchive in unix timestamp
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            file = Path(temp_dir) / "foo.tar"
            with open(file, "wb") as f:
                self.create_archive(f, size_limit=size_limit, age_limit=age_limit, start_time=start_time)
            TarFile(file).extractall(out)

    def syslog(self, pid=-1) -> typing.Generator[SyslogEntry, None, None]:
        self.service.send_plist({"Request": "StartActivity", "MessageFilter": 65535, "Pid": pid, "StreamFlags": 60})

        (length_length,) = struct.unpack("<I", self.service.recvall(4))
        length = int(self.service.recvall(length_length)[::-1].hex(), 16)
        response = plistlib.loads(self.service.recvall(length))

        if response.get("Status") != "RequestSuccessful":
            raise PyMobileDevice3Exception(f"got invalid response: {response}")

        while True:
            assert self.service.recvall(1) == b"\x02"
            (length,) = struct.unpack("<I", self.service.recvall(4))
            line = self.service.recvall(length)
            yield parse_syslog_entry(line)
