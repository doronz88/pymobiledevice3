"""RemoteXPC wire format: the ``XpcWrapper`` frame and the recursive XPC object encoding inside it."""

import dataclasses
import enum
import struct
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Callable, Optional, cast

from pymobiledevice3.binary import (
    F64_LE,
    I64_LE,
    U32_LE,
    U64_LE,
    BinaryStruct,
    ByteReader,
    BytesLike,
    Const,
    encode_utf8_cstring,
    pad_to,
    u32,
    u64,
)
from pymobiledevice3.exceptions import BinaryBuildError, BinaryParseError


class XpcMessageType(enum.IntEnum):
    NULL = 0x00001000
    BOOL = 0x00002000
    INT64 = 0x00003000
    UINT64 = 0x00004000
    DOUBLE = 0x00005000
    POINTER = 0x00006000
    DATE = 0x00007000
    DATA = 0x00008000
    STRING = 0x00009000
    UUID = 0x0000A000
    FD = 0x0000B000
    SHMEM = 0x0000C000
    MACH_SEND = 0x0000D000
    ARRAY = 0x0000E000
    DICTIONARY = 0x0000F000
    ERROR = 0x00010000
    CONNECTION = 0x00011000
    ENDPOINT = 0x00012000
    SERIALIZER = 0x00013000
    PIPE = 0x00014000
    MACH_RECV = 0x00015000
    BUNDLE = 0x00016000
    SERVICE = 0x00017000
    SERVICE_INSTANCE = 0x00018000
    ACTIVITY = 0x00019000
    FILE_TRANSFER = 0x0001A000


class XpcFlags(enum.IntFlag):
    ALWAYS_SET = 0x00000001
    PING = 0x00000002
    DATA_PRESENT = 0x00000100
    WANTING_REPLY = 0x00010000
    REPLY = 0x00020000
    FILE_TX_STREAM_REQUEST = 0x00100000
    FILE_TX_STREAM_RESPONSE = 0x00200000
    INIT_HANDSHAKE = 0x00400000


XPC_WRAPPER_MAGIC = 0x29B00B92
XPC_PAYLOAD_MAGIC = 0x42133742
XPC_PAYLOAD_PROTOCOL_VERSION = 0x00000005

_U32_PAIR = struct.Struct("<II")


@dataclasses.dataclass
class XpcWrapperHeader(BinaryStruct, byte_order="<"):
    """Fixed header of a RemoteXPC frame."""

    magic: Annotated[u32, Const(XPC_WRAPPER_MAGIC)]
    flags: Annotated[XpcFlags, u32]
    size: u64  # payload size, excluding message_id
    message_id: u64


@dataclasses.dataclass
class XpcPayloadHeader(BinaryStruct, byte_order="<"):
    """Header preceding the top-level XPC object of a frame's payload."""

    magic: Annotated[u32, Const(XPC_PAYLOAD_MAGIC)]
    protocol_version: Annotated[u32, Const(XPC_PAYLOAD_PROTOCOL_VERSION)]


_PAYLOAD_HEADER = XpcPayloadHeader(XPC_PAYLOAD_MAGIC, XPC_PAYLOAD_PROTOCOL_VERSION).build()


class XpcInt64Type(int):
    pass


class XpcUInt64Type(int):
    pass


@dataclasses.dataclass
class FileTransferType:
    """An XPC file-transfer object: the payload itself travels on its own HTTP/2 stream.

    ``transfer_id`` correlates the announcement with that stream. It is unset (0) on objects
    decoded from the device, whose stream is derived positionally by the receiving code.
    """

    transfer_size: int
    transfer_id: int = 0


@dataclasses.dataclass
class XpcFileTransfer:
    """Wire body of an ``XpcMessageType.FILE_TRANSFER`` object."""

    msg_id: int
    data: "XpcObject"


@dataclasses.dataclass
class XpcObject:
    """One encoded XPC object.

    ``type`` is an ``XpcMessageType``, or the raw ``int`` for a type unknown to this module. ``data``
    depends on it:

    - DICTIONARY: ``list[tuple[str, XpcObject]]`` (wire order)
    - ARRAY: ``list[XpcObject]``
    - FILE_TRANSFER: ``XpcFileTransfer``
    - BOOL, INT64, UINT64, DATE, FD: ``int`` (BOOL is the raw 32-bit word); SHMEM: ``int`` length
    - DOUBLE: ``float``; DATA, UUID: ``bytes``; STRING: ``str``
    - NULL and types without a payload decoder: ``None`` (no payload bytes)
    """

    type: int
    data: Any = None

    @classmethod
    def parse(cls, data: BytesLike) -> "XpcObject":
        return cls.parse_stream(ByteReader(data))

    @classmethod
    def parse_stream(cls, reader: ByteReader) -> "XpcObject":
        type_offset = reader.absolute
        raw_type = reader.unpack_one(U32_LE)
        try:
            object_type: int = XpcMessageType(raw_type)
        except ValueError:
            return cls(raw_type, None)
        parser = _XPC_OBJECT_PARSERS.get(object_type)
        if parser is None:
            if object_type == XpcMessageType.POINTER:
                raise BinaryParseError("XPC POINTER objects cannot be parsed", record="XpcObject", offset=type_offset)
            return cls(object_type, None)
        return cls(object_type, parser(reader))

    def build(self) -> bytes:
        builder = _XPC_OBJECT_BUILDERS.get(self.type)
        try:
            body = b"" if builder is None else builder(self.data)
            return U32_LE.pack(self.type) + body
        except struct.error as e:
            raise BinaryBuildError(f"cannot encode {self.data!r}: {e}", record="XpcObject") from e


# Padding is relative to where each object starts, not to the enclosing reader: a container whose declared length
# is not a multiple of 4 leaves the objects after it unaligned.


def _parse_string(reader: ByteReader) -> str:
    body = reader.prefixed(U32_LE)
    value = body.read_utf8_cstring()
    reader.read(-len(body.data) % 4)
    return value


def _parse_data(reader: ByteReader) -> bytes:
    value = reader.prefixed(U32_LE).read_all()
    reader.read(-len(value) % 4)
    return value


def _parse_dictionary(reader: ByteReader) -> list[tuple[str, XpcObject]]:
    body = reader.prefixed(U32_LE)
    entries: list[tuple[str, XpcObject]] = []
    for _ in range(body.unpack_one(U32_LE)):
        key_start = body.offset
        key = body.read_utf8_cstring()
        body.read(-(body.offset - key_start) % 4)
        entries.append((key, XpcObject.parse_stream(body)))
    return entries


def _parse_array(reader: ByteReader) -> list[XpcObject]:
    body = reader.prefixed(U32_LE)
    return [XpcObject.parse_stream(body) for _ in range(body.unpack_one(U32_LE))]


_XPC_OBJECT_PARSERS: dict[int, Callable[[ByteReader], Any]] = {
    XpcMessageType.DICTIONARY: _parse_dictionary,
    XpcMessageType.ARRAY: _parse_array,
    XpcMessageType.FILE_TRANSFER: lambda reader: XpcFileTransfer(
        reader.unpack_one(U64_LE), XpcObject.parse_stream(reader)
    ),
    XpcMessageType.STRING: _parse_string,
    XpcMessageType.INT64: lambda reader: reader.unpack_one(I64_LE),
    XpcMessageType.UINT64: lambda reader: reader.unpack_one(U64_LE),
    XpcMessageType.DOUBLE: lambda reader: reader.unpack_one(F64_LE),
    XpcMessageType.BOOL: lambda reader: reader.unpack_one(U32_LE),
    XpcMessageType.NULL: lambda reader: None,
    XpcMessageType.UUID: lambda reader: reader.read(16),
    XpcMessageType.DATE: lambda reader: reader.unpack_one(I64_LE),  # int64_t nanoseconds (xpc_date_create)
    XpcMessageType.DATA: _parse_data,
    XpcMessageType.FD: lambda reader: reader.unpack_one(U32_LE),
    XpcMessageType.SHMEM: lambda reader: reader.unpack(_U32_PAIR)[0],
}


def _prefixed(body: bytes) -> bytes:
    return U32_LE.pack(len(body)) + body


def _build_string_body(value: str) -> bytes:
    return pad_to(_prefixed(encode_utf8_cstring(value)), 4)


def _build_data_body(value: bytes) -> bytes:
    return pad_to(_prefixed(bytes(value)), 4)


def _build_dictionary_body(entries: list[tuple[str, XpcObject]]) -> bytes:
    body = [U32_LE.pack(len(entries))]
    for key, value in entries:
        body.append(pad_to(encode_utf8_cstring(key), 4))
        body.append(value.build())
    return _prefixed(b"".join(body))


def _build_array_body(entries: list[XpcObject]) -> bytes:
    return _prefixed(U32_LE.pack(len(entries)) + b"".join(entry.build() for entry in entries))


def _build_uuid_body(value: bytes) -> bytes:
    if len(value) != 16:
        raise BinaryBuildError(f"expected 16 bytes, got {len(value)}", record="XpcObject", field="UUID")
    return bytes(value)


def _build_file_transfer_body(value: XpcFileTransfer) -> bytes:
    return U64_LE.pack(value.msg_id) + value.data.build()


_XPC_OBJECT_BUILDERS: dict[int, Callable[[Any], bytes]] = {
    XpcMessageType.DICTIONARY: _build_dictionary_body,
    XpcMessageType.STRING: _build_string_body,
    XpcMessageType.INT64: I64_LE.pack,
    XpcMessageType.UINT64: U64_LE.pack,
    XpcMessageType.DOUBLE: F64_LE.pack,
    XpcMessageType.BOOL: U32_LE.pack,
    XpcMessageType.UUID: _build_uuid_body,
    XpcMessageType.DATE: I64_LE.pack,
    XpcMessageType.DATA: _build_data_body,
    XpcMessageType.FD: U32_LE.pack,
    XpcMessageType.SHMEM: lambda length: _U32_PAIR.pack(length, 0),
    XpcMessageType.ARRAY: _build_array_body,
    XpcMessageType.FILE_TRANSFER: _build_file_transfer_body,
}


@dataclasses.dataclass
class XpcWrapper:
    """A RemoteXPC message frame.

    ``payload`` is the top-level XPC object, or ``None`` for a frame carrying none (or one whose
    payload could not be parsed).
    """

    flags: int = XpcFlags.ALWAYS_SET
    message_id: int = 0
    payload: Optional[XpcObject] = None

    @classmethod
    def parse(cls, data: BytesLike) -> "XpcWrapper":
        """Parse one frame from the start of ``data``; trailing bytes are ignored.

        :raises TruncatedDataError: ``data`` holds only part of a frame.
        :raises UnexpectedConstantError: ``data`` does not start with the wrapper magic.
        """
        header = XpcWrapperHeader.parse(data)
        payload = ByteReader(data, XpcWrapperHeader.SIZE).sub(header.size)
        return cls(flags=header.flags, message_id=header.message_id, payload=_parse_payload(payload))

    def build(self) -> bytes:
        body = b""
        if self.payload is not None:
            body = _PAYLOAD_HEADER + self.payload.build()
        header = XpcWrapperHeader(XPC_WRAPPER_MAGIC, cast(XpcFlags, self.flags), len(body), self.message_id)
        return header.build() + body


def _parse_payload(reader: ByteReader) -> Optional[XpcObject]:
    """Parse the optional payload; anything that is not a well-formed payload (including one nested too deeply
    to recurse into) yields ``None``."""
    try:
        XpcPayloadHeader.read(reader)
        return XpcObject.parse_stream(reader)
    except (BinaryParseError, RecursionError):
        return None


def _decode_xpc_dictionary(xpc_object: XpcObject) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in xpc_object.data:
        result[key] = decode_xpc_object(value)
    return result


def _decode_xpc_array(xpc_object: XpcObject) -> list[Any]:
    return [decode_xpc_object(entry) for entry in xpc_object.data]


# The Gregorian calendar repeats every 400 years, weekdays included, so shifting a date by this many days keeps
# its month, day and weekday - everything a "second Sunday of March" daylight saving rule looks at.
_GREGORIAN_CYCLE = timedelta(days=146097)


def _decode_xpc_date(xpc_object: XpcObject) -> datetime:
    seconds = xpc_object.data / 1000000000  # signed nanoseconds since 1970
    try:
        return datetime.fromtimestamp(seconds)
    except (OverflowError, OSError, ValueError):
        # Windows cannot convert dates before 1970 to local time: convert the same instant 400 years later
        # (int64 nanoseconds reach back only to 1677) and shift the result back.
        return datetime.fromtimestamp(seconds + _GREGORIAN_CYCLE.total_seconds()) - _GREGORIAN_CYCLE


def _decode_xpc_file_transfer(xpc_object: XpcObject) -> FileTransferType:
    if xpc_object.data.data.type != XpcMessageType.DICTIONARY:
        raise TypeError(f"deserialize error: {xpc_object}")
    return FileTransferType(transfer_size=_decode_xpc_dictionary(xpc_object.data.data)["s"])


_XPC_DECODERS: dict[int, Callable[[XpcObject], Any]] = {
    XpcMessageType.DICTIONARY: _decode_xpc_dictionary,
    XpcMessageType.ARRAY: _decode_xpc_array,
    XpcMessageType.BOOL: lambda xpc_object: bool(xpc_object.data),
    XpcMessageType.INT64: lambda xpc_object: XpcInt64Type(xpc_object.data),
    XpcMessageType.UINT64: lambda xpc_object: XpcUInt64Type(xpc_object.data),
    XpcMessageType.UUID: lambda xpc_object: uuid.UUID(bytes=xpc_object.data),
    XpcMessageType.STRING: lambda xpc_object: xpc_object.data,
    XpcMessageType.DATA: lambda xpc_object: xpc_object.data,
    XpcMessageType.DATE: _decode_xpc_date,
    XpcMessageType.FILE_TRANSFER: _decode_xpc_file_transfer,
    XpcMessageType.DOUBLE: lambda xpc_object: xpc_object.data,
    XpcMessageType.NULL: lambda xpc_object: None,
}


def decode_xpc_object(xpc_object: XpcObject) -> Any:
    decoder = _XPC_DECODERS.get(xpc_object.type)
    if decoder is None:
        raise TypeError(f"deserialize error: {xpc_object}")
    return decoder(xpc_object)


def _build_xpc_array(payload: list[Any]) -> XpcObject:
    return XpcObject(XpcMessageType.ARRAY, [_build_xpc_object(entry) for entry in payload])


def _build_xpc_dictionary(payload: dict[str, Any]) -> XpcObject:
    return XpcObject(XpcMessageType.DICTIONARY, [(key, _build_xpc_object(value)) for key, value in payload.items()])


def _build_xpc_file_transfer(payload: FileTransferType) -> XpcObject:
    return XpcObject(
        XpcMessageType.FILE_TRANSFER,
        XpcFileTransfer(
            msg_id=payload.transfer_id,
            data=_build_xpc_dictionary({"s": XpcUInt64Type(payload.transfer_size)}),
        ),
    )


def _build_xpc_object(payload: Any) -> XpcObject:
    if payload is None:
        return XpcObject(XpcMessageType.NULL)
    payload_builders: dict[Any, Callable[[Any], XpcObject]] = {
        list: _build_xpc_array,
        dict: _build_xpc_dictionary,
        bool: lambda value: XpcObject(XpcMessageType.BOOL, int(value)),
        str: lambda value: XpcObject(XpcMessageType.STRING, value),
        bytes: lambda value: XpcObject(XpcMessageType.DATA, value),
        bytearray: lambda value: XpcObject(XpcMessageType.DATA, bytes(value)),
        float: lambda value: XpcObject(XpcMessageType.DOUBLE, value),
        uuid.UUID: lambda value: XpcObject(XpcMessageType.UUID, value.bytes),
        FileTransferType: _build_xpc_file_transfer,
        "XpcUInt64Type": lambda value: XpcObject(XpcMessageType.UINT64, int(value)),
        "XpcInt64Type": lambda value: XpcObject(XpcMessageType.INT64, int(value)),
    }
    builder = payload_builders.get(type(payload), payload_builders.get(type(payload).__name__))
    if builder is None:
        raise TypeError(f"unrecognized type for: {payload} {type(payload)}")
    return builder(payload)


def create_xpc_wrapper(d: dict[str, Any], message_id: int = 0, wanting_reply: bool = False) -> bytes:
    flags = XpcFlags.ALWAYS_SET
    if len(d.keys()) > 0:
        flags |= XpcFlags.DATA_PRESENT
    if wanting_reply:
        flags |= XpcFlags.WANTING_REPLY
    return XpcWrapper(flags=flags, message_id=message_id, payload=_build_xpc_object(d)).build()
