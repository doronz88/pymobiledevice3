import dataclasses
import plistlib
import shutil
import struct
import tempfile
import typing
import uuid
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from tarfile import TarFile

from bytestruct import BinaryStruct, Bytes, OpenIntEnum, u8, u16, u32, u64, uuid_t

from pymobiledevice3.exceptions import ConnectionTerminatedError, DevicePathError, ProtocolError
from pymobiledevice3.safe_paths import resolve_device_path
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


class SyslogLogLevel(OpenIntEnum):
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
    # when the entry was logged, in mach ticks: the same value as the row's `time` in `ActivityTraceTap`
    mach_timestamp: typing.Optional[int] = None


@dataclasses.dataclass
class _SyslogRecordHeader(BinaryStruct, byte_order="<"):
    """Fixed-size header of a binary os_trace_relay syslog record; the variable-length strings follow it."""

    _unknown0: typing.Annotated[bytes, Bytes(9)]
    pid: u32
    procid: u64
    process_image_uuid: uuid_t  # the process' main executable
    _unknown1: typing.Annotated[bytes, Bytes(18)]
    seconds: u32
    _unknown2: u32
    microseconds: u32
    _unknown3: u8
    level: typing.Annotated[SyslogLogLevel, u8]
    _unknown4: typing.Annotated[bytes, Bytes(6)]
    mach_timestamp: u64
    thread_id: u64
    image_uuid: uuid_t  # the sender image
    image_name_size: u16
    message_size: u16
    _unknown5: u16
    sender_image_offset: u32
    subsystem_size: u32
    category_size: u32
    _unknown6: u32


def parse_syslog_entry(data: bytes) -> SyslogEntry:
    """
    Decode one binary syslog record from the os_trace_relay activity stream into a
    `SyslogEntry`.

    The fixed-size header is followed by the NUL-terminated filename, then the image name, message and
    optional subsystem/category label, each sized by a header field (sizes include a trailing NUL). The
    label is only populated when both subsystem and category are present in the record.

    :param data: The raw bytes of a single record (the payload following the stream's length prefix).
    :returns: The parsed log entry.
    """
    header = _SyslogRecordHeader.parse(data)

    def take(offset: int, size: int) -> str:
        return try_decode(data[offset : offset + size - 1], errors="replace")

    offset = _SyslogRecordHeader.SIZE
    filename_end = data.find(b"\x00", offset)
    filename = try_decode(data[offset:filename_end], errors="replace")
    offset = filename_end + 1
    image_name = take(offset, header.image_name_size)
    offset += header.image_name_size
    message = take(offset, header.message_size)
    offset += header.message_size

    label = None
    if header.subsystem_size > 0 and header.category_size > 0:
        subsystem = take(offset, header.subsystem_size)
        category = take(offset + header.subsystem_size, header.category_size)
        label = SyslogLabel(subsystem=subsystem, category=category)

    return SyslogEntry(
        pid=header.pid,
        timestamp=datetime.fromtimestamp(header.seconds + (header.microseconds / 1000000)),
        level=header.level,
        image_name=image_name,
        image_offset=header.sender_image_offset,
        filename=filename,
        message=message,
        label=label,
        procid=header.procid,
        thread_id=header.thread_id,
        image_uuid=header.image_uuid,
        process_image_uuid=header.process_image_uuid,
        mach_timestamp=header.mach_timestamp,
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
        out: typing.IO[bytes],
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
        :raises ProtocolError: If the device does not acknowledge the request with a successful status.
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

        response = await self.service.recvall(1)
        if response[0] != 1:
            raise ProtocolError(f"The device sent an unexpected reply to the log archive request: {response.hex()}")

        status = plistlib.loads(await self.service.recv_prefixed()).get("Status")
        if status != "RequestSuccessful":
            raise ProtocolError(f"The device refused to create the log archive: {status}")

        while True:
            try:
                magic = await self.service.recvall(1)
            except ConnectionTerminatedError:
                break
            if magic[0] != 3:
                raise ProtocolError(f"The device sent a malformed log stream (unexpected chunk marker): {magic.hex()}")
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
            # Extract only ordinary files and directories, each kept beneath `out`. extractall()
            # is unsafe with a device-supplied archive before Python 3.14 (absolute names, `..`,
            # links), and a logarchive holds nothing but files and directories anyway.
            out_path = Path(out)
            with TarFile(file) as archive:
                for member in archive:
                    destination = resolve_device_path(out_path, member.name)
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                    elif member.isreg():
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        source = archive.extractfile(member)
                        if source is None:
                            raise DevicePathError(f"the log archive entry has no data: {member.name!r}")
                        with source, destination.open("wb") as target:
                            shutil.copyfileobj(source, target)
                    else:
                        raise DevicePathError(
                            f"the log archive holds an entry that is neither a file nor a directory: {member.name!r}"
                        )

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
        :raises ProtocolError: If the device rejects the stream-start request.
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
            raise ProtocolError(f"The device refused to start the log stream: {response}")

        while True:
            magic = await self.service.recvall(1)
            if magic != b"\x02":
                raise ProtocolError(f"The device sent a malformed log stream (unexpected chunk marker): {magic.hex()}")
            (length,) = struct.unpack("<I", await self.service.recvall(4))
            line = await self.service.recvall(length)
            yield parse_syslog_entry(line)
