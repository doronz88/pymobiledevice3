import dataclasses
import plistlib
import struct
import tempfile
import typing
import uuid
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from tarfile import TarFile

from pymobiledevice3.exceptions import ConnectionTerminatedError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import try_decode

CHUNK_SIZE = 4096
TIME_FORMAT = "%H:%M:%S"
SYSLOG_LINE_SPLITTER = "\n\x00"


class OsActivityStreamFlag(IntEnum):
    """
    Bit flags controlling what an activity stream delivers and how it decodes entries.

    These are the exact ``os_activity_stream_flag_t`` values from Apple's private headers
    and are OR'd together to form the ``StreamFlags`` value passed to `syslog`.

    Based on: https://github.com/limneos/oslog/blob/master/ActivityStreamAPI.h
    """

    PROCESS_ONLY = 0x00000001
    SKIP_DECODE = 0x00000002
    PAYLOAD = 0x00000004
    HISTORICAL = 0x00000008
    CALLSTACK = 0x00000010
    DEBUG = 0x00000020
    NO_SENSITIVE = 0x00000080
    INFO = 0x00000100
    PROMISCUOUS = 0x00000200


class OsActivityStreamType(IntEnum):
    """
    Categories of events that may appear in an activity stream (log messages, signposts,
    activity transitions, etc.).

    These are the exact ``os_activity_stream_type_t`` values from Apple's private headers.

    Based on: https://github.com/limneos/oslog/blob/master/ActivityStreamAPI.h
    """

    ACTIVITY_CREATE = 0x0201
    ACTIVITY_TRANSITION = 0x0202
    ACTIVITY_USERACTION = 0x0203
    TRACE_MESSAGE = 0x0300
    LOG_MESSAGE = 0x0400
    LEGACY_LOG_MESSAGE = 0x0480
    TIMESYNC = 0x0500
    SIGNPOST = 0x0600
    LOSS = 0x0700
    STATEDUMP_EVENT = 0x0A00


OS_TRACE_RELAY_MESSAGE_FILTER_ALL = 0xFFFF

# Sniffed from Console.app when enabling both info and debug messages
OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT = (
    OsActivityStreamFlag.PAYLOAD
    | OsActivityStreamFlag.HISTORICAL
    | OsActivityStreamFlag.CALLSTACK
    | OsActivityStreamFlag.DEBUG
)


class SyslogLogLevel(IntEnum):
    """Severity level of a syslog entry, as carried in the raw stream's level byte."""

    NOTICE = 0x00
    INFO = 0x01
    DEBUG = 0x02

    # deducted from console-app
    USER_ACTION = 0x03
    ERROR = 0x10
    FAULT = 0x11


@dataclasses.dataclass
class SyslogLabel:
    """The os_log subsystem/category pair an entry was emitted under, when present."""

    category: str
    subsystem: str


@dataclasses.dataclass
class SyslogEntry:
    """
    A single decoded log line from the device's activity stream.

    Produced by `parse_syslog_entry` and yielded by `syslog`.
    Bundles the emitting process and thread, the entry's timestamp and severity, the
    log message text, and the image/offset metadata needed to symbolicate the call site.
    """

    pid: int
    timestamp: datetime
    level: SyslogLogLevel
    image_name: str
    image_offset: int
    filename: str
    message: str
    label: typing.Optional[SyslogLabel] = None
    # unique process id (the `procid` activity-stream field); equals `pid` in practice on iOS
    procid: typing.Optional[int] = None
    # id of the thread that emitted the entry (the `thread` activity-stream field)
    thread_id: typing.Optional[int] = None
    # UUID of the sender image (the one named by `image_name`); pair with `image_offset` to symbolicate
    image_uuid: typing.Optional[uuid.UUID] = None
    # UUID of the process' main executable (the one named by `filename`)
    process_image_uuid: typing.Optional[uuid.UUID] = None
    # raw high-resolution device timestamp in mach ticks (monotonic; clock domain unverified)
    mach_timestamp: typing.Optional[int] = None


def parse_syslog_entry(data: bytes) -> SyslogEntry:
    """
    Decode one binary syslog record from the os_trace_relay activity stream into a
    `SyslogEntry`.

    Fixed-offset fields (pid, timestamps, level, UUIDs, thread/proc ids) are unpacked from the
    record header, followed by the variable-length filename, image name, message, and optional
    subsystem/category label. The label is only populated when both subsystem and category are
    present in the record.

    :param data: The raw bytes of a single record (the payload following the stream's length prefix).
    :returns: The parsed log entry.
    """
    offset = 0

    # Skip first 9 bytes
    offset += 9

    # Parse pid (4 bytes, little-endian unsigned int)
    pid = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4

    # The next 42 bytes hold: procid at +0 (u64), then the process' main executable UUID at +8
    procid = struct.unpack("<Q", data[offset : offset + 8])[0]
    process_image_uuid = uuid.UUID(bytes=data[offset + 8 : offset + 24])

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

    # The next 38 bytes hold the raw mach timestamp at +4, the thread id at +14, and the sender image UUID at +22
    mach_timestamp = struct.unpack("<Q", data[offset + 4 : offset + 12])[0]
    thread_id = struct.unpack("<Q", data[offset + 14 : offset + 22])[0]
    image_uuid = uuid.UUID(bytes=data[offset + 22 : offset + 38])

    # Skip 38 bytes
    offset += 38

    # Parse image_name_size (2 bytes, little-endian unsigned short)
    image_name_size = struct.unpack("<H", data[offset : offset + 2])[0]
    offset += 2

    # Parse message_size (2 bytes, little-endian unsigned short)
    message_size = struct.unpack("<H", data[offset : offset + 2])[0]
    offset += 2

    # Skip 2 bytes
    offset += 2

    # Parse sender_image_offset (4 bytes, little-endian unsigned int)
    sender_image_offset = struct.unpack("<I", data[offset : offset + 4])[0]
    offset += 4

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
    filename = try_decode(data[offset:filename_end], errors="replace")
    offset = filename_end + 1

    # Parse image_name
    image_name = try_decode(data[offset : offset + image_name_size - 1], errors="replace")
    offset += image_name_size

    # Parse message
    message = try_decode(data[offset : offset + message_size - 1], errors="replace")
    offset += message_size

    # Parse label (optional)
    label = None
    if subsystem_size > 0 and category_size > 0:
        subsystem = try_decode(data[offset : offset + subsystem_size - 1], errors="replace")
        offset += subsystem_size
        category = try_decode(data[offset : offset + category_size - 1], errors="replace")
        offset += category_size
        label = SyslogLabel(subsystem=subsystem, category=category)

    return SyslogEntry(
        pid=pid,
        timestamp=timestamp,
        level=SyslogLogLevel(level),
        image_name=image_name,
        image_offset=sender_image_offset,
        filename=filename,
        message=message,
        label=label,
        procid=procid,
        thread_id=thread_id,
        image_uuid=image_uuid,
        process_image_uuid=process_image_uuid,
        mach_timestamp=mach_timestamp,
    )


class OsTraceService(LockdownService):
    """
    Client for the device's ``com.apple.os_trace_relay`` service.

    Provides API for the following operations:

    * List the running processes (pid to process name mapping).
    * Stream live syslog entries in binary form, optionally filtered by pid.
    * Retrieve the device's stored log archive (the contents of the ``/var/db/diagnostics``
      directory), either as a raw PAX-format tar stream or extracted into a ``.logarchive``
      directory consumable by ``log`` / Console.

    The service is reached over the classic lockdown service on `SERVICE_NAME`, or over the
    RemoteServiceDiscovery shim (`RSD_SERVICE_NAME`) when a non-`LockdownClient`
    provider is supplied.
    """

    SERVICE_NAME = "com.apple.os_trace_relay"
    RSD_SERVICE_NAME = "com.apple.os_trace_relay.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def get_pid_list(self):
        """
        Request the device's process list.

        :returns: The decoded ``PidList`` response plist. Its ``Payload`` entry maps each pid to a
            dict of per-process metadata (such as ``ProcessName``).
        """
        await self.connect()
        await self.service.send_plist({"Request": "PidList"})

        # ignore first received unknown byte
        await self.service.recvall(1)

        response = await self.service.recv_prefixed()
        return plistlib.loads(response)

    async def create_archive(
        self,
        out: typing.IO,
        size_limit: typing.Optional[int] = None,
        age_limit: typing.Optional[int] = None,
        start_time: typing.Optional[int] = None,
    ):
        """
        Request a log archive from the device and stream its raw bytes into ``out``.

        The device returns the archive as a PAX-format tar stream (the contents of
        ``/var/db/diagnostics``), which is written to ``out`` in chunks until the connection is
        terminated. Use `collect` instead to obtain an extracted ``.logarchive`` directory.

        :param out: A writable binary file-like object to receive the archive bytes.
        :param size_limit: Optional maximum archive size in bytes.
        :param age_limit: Optional maximum age, in days, of entries to include.
        :param start_time: Optional earliest entry time, as a unix timestamp.
        :raises AssertionError: If the device does not acknowledge the request with a successful status.
        """
        request: dict[str, typing.Any] = {"Request": "CreateArchive"}

        if size_limit is not None:
            request.update({"SizeLimit": size_limit})

        if age_limit is not None:
            request.update({"AgeLimit": age_limit})

        if start_time is not None:
            request.update({"StartTime": start_time})

        await self.connect()
        await self.service.send_plist(request)

        assert (await self.service.recvall(1))[0] == 1

        assert plistlib.loads(await self.service.recv_prefixed()).get("Status") == "RequestSuccessful", "Invalid status"

        while True:
            try:
                assert (await self.service.recvall(1))[0] == 3, "invalid magic"
            except ConnectionTerminatedError:
                break
            out.write(await self.service.recv_prefixed(endianity="<"))

    async def collect(
        self,
        out: str,
        size_limit: typing.Optional[int] = None,
        age_limit: typing.Optional[int] = None,
        start_time: typing.Optional[int] = None,
    ) -> None:
        """
        Collect the device's system logs into a ``.logarchive`` that can be inspected later with
        tools such as ``log`` or Console.

        Internally calls `create_archive` to fetch the tar stream into a temporary file, then
        extracts it into the ``out`` directory.

        :param out: Destination directory path into which the archive is extracted.
        :param size_limit: Optional maximum archive size in bytes.
        :param age_limit: Optional maximum age, in days, of entries to include.
        :param start_time: Optional earliest entry time, as a unix timestamp.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            file = Path(temp_dir) / "foo.tar"
            with open(file, "wb") as f:
                await self.create_archive(f, size_limit=size_limit, age_limit=age_limit, start_time=start_time)
            TarFile(file).extractall(out)

    async def syslog(
        self,
        pid: int = -1,
        message_filter: int = OS_TRACE_RELAY_MESSAGE_FILTER_ALL,
        stream_flags: int = OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT,
    ) -> typing.AsyncGenerator[SyslogEntry, None]:
        """
        Stream live syslog entries from the device.

        Starts an activity stream on the device and yields each incoming record, parsed via
        `parse_syslog_entry`, indefinitely until the caller stops iterating or the connection
        drops.

        :param pid: Restrict the stream to a single process by pid; ``-1`` (the default) streams
            entries from all processes.
        :param message_filter: Bitmask selecting which message levels to receive; defaults to
            `OS_TRACE_RELAY_MESSAGE_FILTER_ALL` (all levels).
        :param stream_flags: Bitmask of `OsActivityStreamFlag` values controlling stream
            contents and decoding; defaults to `OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT`.
        :yields: Each decoded log entry as it arrives.
        :raises PyMobileDevice3Exception: If the device rejects the stream-start request.
        """
        await self.connect()
        await self.service.send_plist({
            "Request": "StartActivity",
            "MessageFilter": message_filter,
            "Pid": pid,
            "StreamFlags": stream_flags,
        })

        (length_length,) = struct.unpack("<I", await self.service.recvall(4))
        length = int((await self.service.recvall(length_length))[::-1].hex(), 16)
        response = plistlib.loads(await self.service.recvall(length))

        if response.get("Status") != "RequestSuccessful":
            raise PyMobileDevice3Exception(f"got invalid response: {response}")

        while True:
            assert await self.service.recvall(1) == b"\x02"
            (length,) = struct.unpack("<I", await self.service.recvall(4))
            line = await self.service.recvall(length)
            yield parse_syslog_entry(line)
