"""RemoteXPC wire format: the ``XpcWrapper`` frame and the recursive XPC object encoding inside it."""

import dataclasses
import enum
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Callable, Optional, cast

from bytestruct import (
    CSTRING,
    F64_LE,
    GREEDY_BYTES,
    I64_LE,
    PASS,
    U32_LE,
    U64_LE,
    Aligned,
    BinaryParseError,
    BinaryStruct,
    ByteReader,
    Bytes,
    BytesLike,
    CodecBase,
    Const,
    Prefixed,
    PrefixedArray,
    Switch,
    Tuple,
    u32,
    u64,
)


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
        return cls.read(ByteReader(data))

    @classmethod
    def read(cls, reader: ByteReader) -> "XpcObject":
        object_type: int
        object_type, data = _XPC_OBJECT.read(reader)
        return cls(_XPC_MESSAGE_TYPES.get(object_type, object_type), data)

    def build(self) -> bytes:
        return _XPC_OBJECT.build((self.type, self.data))


@dataclasses.dataclass
class XpcFileTransfer(BinaryStruct, byte_order="<"):
    """Wire body of an ``XpcMessageType.FILE_TRANSFER`` object."""

    msg_id: u64
    data: Annotated[XpcObject, XpcObject]


class _Unparsable(CodecBase[None]):
    """A type whose payload layout is unknown, so nothing after it can be parsed."""

    def read(self, reader: ByteReader) -> None:
        raise BinaryParseError("XPC POINTER objects cannot be parsed", offset=reader.absolute - U32_LE.size)

    def build(self, value: None) -> bytes:
        return b""


_XPC_MESSAGE_TYPES: dict[int, int] = {member.value: member for member in XpcMessageType}

# Padding is relative to where each value starts, not to the enclosing container: a container whose declared
# length is not a multiple of 4 leaves the objects after it unaligned.
_XPC_OBJECT = Switch(
    U32_LE,
    {
        XpcMessageType.NULL: PASS,
        XpcMessageType.BOOL: U32_LE,
        XpcMessageType.INT64: I64_LE,
        XpcMessageType.UINT64: U64_LE,
        XpcMessageType.DOUBLE: F64_LE,
        XpcMessageType.POINTER: _Unparsable(),
        XpcMessageType.DATE: I64_LE,  # int64_t nanoseconds (xpc_date_create)
        XpcMessageType.DATA: Aligned(4, Prefixed(U32_LE, GREEDY_BYTES)),
        XpcMessageType.STRING: Aligned(4, Prefixed(U32_LE, CSTRING)),
        XpcMessageType.UUID: Bytes(16),
        XpcMessageType.FD: U32_LE,
        XpcMessageType.SHMEM: Aligned(8, U32_LE),  # u32 length + 4 reserved bytes
        XpcMessageType.ARRAY: Prefixed(U32_LE, PrefixedArray(U32_LE, XpcObject)),
        XpcMessageType.DICTIONARY: Prefixed(U32_LE, PrefixedArray(U32_LE, Tuple(Aligned(4, CSTRING), XpcObject))),
        XpcMessageType.FILE_TRANSFER: XpcFileTransfer,
    },
    default=PASS,  # a type without a payload layout here: no payload bytes are consumed
)


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
        return XpcObject.read(reader)
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
    builder = _PAYLOAD_BUILDERS.get(type(payload)) or _PAYLOAD_BUILDERS.get(type(payload).__name__)
    if builder is None:
        raise TypeError(f"unrecognized type for: {payload} {type(payload)}")
    return builder(payload)


_PAYLOAD_BUILDERS: dict[Any, Callable[[Any], XpcObject]] = {
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


def create_xpc_wrapper(d: dict[str, Any], message_id: int = 0, wanting_reply: bool = False) -> bytes:
    flags = XpcFlags.ALWAYS_SET
    if len(d.keys()) > 0:
        flags |= XpcFlags.DATA_PRESENT
    if wanting_reply:
        flags |= XpcFlags.WANTING_REPLY
    return XpcWrapper(flags=flags, message_id=message_id, payload=_build_xpc_object(d)).build()
