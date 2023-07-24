import dataclasses
import uuid
from datetime import datetime
from typing import Any, List, Mapping

from construct import Aligned, Array, Bytes, Const, CString, Default, Double, Enum, ExprAdapter, FlagsEnum, \
    GreedyBytes, Hex, If, Int32ul, Int64sl, Int64ul, LazyBound
from construct import Optional as ConstructOptional
from construct import Pass, Prefixed, Probe, Struct, Switch, this

XpcMessageType = Enum(Hex(Int32ul),
                      NULL=0x00001000,
                      BOOL=0x00002000,
                      INT64=0x00003000,
                      UINT64=0x00004000,
                      DOUBLE=0x00005000,
                      POINTER=0x00006000,
                      DATE=0x00007000,
                      DATA=0x00008000,
                      STRING=0x00009000,
                      UUID=0x0000a000,
                      FD=0x0000b000,
                      SHMEM=0x0000c000,
                      MACH_SEND=0x0000d000,
                      ARRAY=0x0000e000,
                      DICTIONARY=0x0000f000,
                      ERROR=0x00010000,
                      CONNECTION=0x00011000,
                      ENDPOINT=0x00012000,
                      SERIALIZER=0x00013000,
                      PIPE=0x00014000,
                      MACH_RECV=0x00015000,
                      BUNDLE=0x00016000,
                      SERVICE=0x00017000,
                      SERVICE_INSTANCE=0x00018000,
                      ACTIVITY=0x00019000,
                      FILE_TRANSFER=0x0001a000,
                      )
XpcFlags = FlagsEnum(Hex(Int32ul),
                     ALWAYS_SET=0x00000001,
                     PING=0x00000002,
                     DATA_PRESENT=0x00000100,
                     WANTING_REPLY=0x00010000,
                     REPLY=0x00020000,
                     FILE_TX_STREAM_REQUEST=0x00100000,
                     FILE_TX_STREAM_RESPONSE=0x00200000,
                     INIT_HANDSHAKE=0x00400000,
                     )
AlignedString = Aligned(4, CString('utf8'))
XpcNull = Pass
XpcBool = Int32ul
XpcInt64 = Int64sl
XpcUInt64 = Int64ul
XpcDouble = Double
XpcPointer = None
XpcDate = Int64ul
XpcData = Aligned(4, Prefixed(Int32ul, GreedyBytes))
XpcString = Aligned(4, Prefixed(Int32ul, CString('utf8')))
XpcUuid = Bytes(16)
XpcFd = Int32ul
XpcShmem = Struct('length' / Int32ul, Int32ul)
XpcArray = Prefixed(Int32ul, Struct(
    'count' / Int32ul,
    'entries' / Array(this.count, LazyBound(lambda: XpcObject))))
XpcDictionaryEntry = Struct(
    'key' / AlignedString,
    'value' / LazyBound(lambda: XpcObject),
)
XpcDictionary = Prefixed(Int32ul, Struct(
    'count' / Hex(Int32ul),
    'entries' / If(this.count > 0, Array(this.count, XpcDictionaryEntry)),
))
XpcFileTransfer = Struct(
    'msg_id' / Int64ul,
    'data' / LazyBound(lambda: XpcObject),
)
XpcObject = Struct(
    'type' / XpcMessageType,
    'data' / Switch(this.type, {
        XpcMessageType.DICTIONARY: XpcDictionary,
        XpcMessageType.STRING: XpcString,
        XpcMessageType.INT64: XpcInt64,
        XpcMessageType.UINT64: XpcUInt64,
        XpcMessageType.DOUBLE: XpcDouble,
        XpcMessageType.BOOL: XpcBool,
        XpcMessageType.NULL: XpcNull,
        XpcMessageType.UUID: XpcUuid,
        XpcMessageType.POINTER: XpcPointer,
        XpcMessageType.DATE: XpcDate,
        XpcMessageType.DATA: XpcData,
        XpcMessageType.FD: XpcFd,
        XpcMessageType.SHMEM: XpcShmem,
        XpcMessageType.ARRAY: XpcArray,
        XpcMessageType.FILE_TRANSFER: XpcFileTransfer,
    }, default=Probe(lookahead=1000)),
)
XpcPayload = Struct(
    'magic' / Hex(Const(0x42133742, Int32ul)),
    'protocol_version' / Hex(Const(0x00000005, Int32ul)),
    'obj' / XpcObject,
)
XpcWrapper = Struct(
    'magic' / Hex(Const(0x29b00b92, Int32ul)),
    'flags' / Default(XpcFlags, XpcFlags.ALWAYS_SET),
    'message' / Prefixed(
        ExprAdapter(Int64ul, lambda obj, context: obj + 8, lambda obj, context: obj - 8),
        Struct(
            'message_id' / Hex(Default(Int64ul, 0)),
            'payload' / ConstructOptional(XpcPayload),
        ))
)


class XpcInt64Type(int):
    pass


class XpcUInt64Type(int):
    pass


@dataclasses.dataclass
class FileTransferType:
    transfer_size: int


def _decode_xpc_dictionary(xpc_object) -> Mapping:
    if xpc_object.data.count == 0:
        return {}
    result = {}
    for entry in xpc_object.data.entries:
        result[entry.key] = decode_xpc_object(entry.value)
    return result


def _decode_xpc_array(xpc_object) -> List:
    result = []
    for entry in xpc_object.data.entries:
        result.append(decode_xpc_object(entry))
    return result


def _decode_xpc_bool(xpc_object) -> bool:
    return bool(xpc_object.data)


def _decode_xpc_int64(xpc_object) -> XpcInt64Type:
    return XpcInt64Type(xpc_object.data)


def _decode_xpc_uint64(xpc_object) -> XpcUInt64Type:
    return XpcUInt64Type(xpc_object.data)


def _decode_xpc_uuid(xpc_object) -> uuid.UUID:
    return uuid.UUID(bytes=xpc_object.data)


def _decode_xpc_string(xpc_object) -> str:
    return xpc_object.data


def _decode_xpc_data(xpc_object) -> bytes:
    return xpc_object.data


def _decode_xpc_date(xpc_object) -> datetime:
    # Convert from nanoseconds to seconds
    return datetime.fromtimestamp(xpc_object.data / 1000000000)


def _decode_xpc_file_transfer(xpc_object) -> FileTransferType:
    return FileTransferType(transfer_size=_decode_xpc_dictionary(xpc_object.data.data)['s'])


def _decode_xpc_double(xpc_object) -> float:
    return xpc_object.data


def _decode_xpc_null(xpc_object) -> None:
    return None


def decode_xpc_object(xpc_object) -> Any:
    decoders = {
        XpcMessageType.DICTIONARY: _decode_xpc_dictionary,
        XpcMessageType.ARRAY: _decode_xpc_array,
        XpcMessageType.BOOL: _decode_xpc_bool,
        XpcMessageType.INT64: _decode_xpc_int64,
        XpcMessageType.UINT64: _decode_xpc_uint64,
        XpcMessageType.UUID: _decode_xpc_uuid,
        XpcMessageType.STRING: _decode_xpc_string,
        XpcMessageType.DATA: _decode_xpc_data,
        XpcMessageType.DATE: _decode_xpc_date,
        XpcMessageType.FILE_TRANSFER: _decode_xpc_file_transfer,
        XpcMessageType.DOUBLE: _decode_xpc_double,
        XpcMessageType.NULL: _decode_xpc_null,
    }
    decoder = decoders.get(xpc_object.type)
    if decoder is None:
        raise TypeError(f'deserialize error: {xpc_object}')
    return decoder(xpc_object)


def _build_xpc_array(payload: List) -> Mapping:
    entries = []
    for entry in payload:
        entry = _build_xpc_object(entry)
        entries.append(entry)
    return {
        'type': XpcMessageType.ARRAY,
        'data': {
            'count': len(entries),
            'entries': entries
        }
    }


def _build_xpc_dictionary(payload: Mapping) -> Mapping:
    entries = []
    for key, value in payload.items():
        entry = {'key': key, 'value': _build_xpc_object(value)}
        entries.append(entry)
    return {
        'type': XpcMessageType.DICTIONARY,
        'data': {
            'count': len(entries),
            'entries': entries,
        }
    }


def _build_xpc_bool(payload: bool) -> Mapping:
    return {
        'type': XpcMessageType.BOOL,
        'data': payload,
    }


def _build_xpc_string(payload: str) -> Mapping:
    return {
        'type': XpcMessageType.STRING,
        'data': payload,
    }


def _build_xpc_data(payload: bool) -> Mapping:
    return {
        'type': XpcMessageType.DATA,
        'data': payload,
    }


def _build_xpc_double(payload: float) -> Mapping:
    return {
        'type': XpcMessageType.DOUBLE,
        'data': payload,
    }


def _build_xpc_uuid(payload: uuid.UUID) -> Mapping:
    return {
        'type': XpcMessageType.UUID,
        'data': payload.bytes,
    }


def _build_xpc_null(payload: None) -> Mapping:
    return {
        'type': XpcMessageType.NULL,
        'data': None,
    }


def _build_xpc_uint64(payload: XpcUInt64Type) -> Mapping:
    return {
        'type': XpcMessageType.UINT64,
        'data': payload,
    }


def _build_xpc_int64(payload: XpcInt64Type) -> Mapping:
    return {
        'type': XpcMessageType.INT64,
        'data': payload,
    }


def _build_xpc_object(payload: Any) -> Mapping:
    if payload is None:
        return _build_xpc_null(payload)
    payload_builders = {
        list: _build_xpc_array,
        dict: _build_xpc_dictionary,
        bool: _build_xpc_bool,
        str: _build_xpc_string,
        bytes: _build_xpc_data,
        bytearray: _build_xpc_data,
        float: _build_xpc_double,
        uuid.UUID: _build_xpc_uuid,
        'XpcUInt64Type': _build_xpc_uint64,
        'XpcInt64Type': _build_xpc_int64,
    }
    builder = payload_builders.get(type(payload), payload_builders.get(type(payload).__name__))
    if builder is None:
        raise TypeError(f'unrecognized type for: {payload} {type(payload)}')
    return builder(payload)


def create_xpc_wrapper(d: Mapping, message_id: int = 0, wanting_reply: bool = False) -> bytes:
    flags = XpcFlags.ALWAYS_SET
    if len(d.keys()) > 0:
        flags |= XpcFlags.DATA_PRESENT
    if wanting_reply:
        flags |= XpcFlags.WANTING_REPLY

    xpc_payload = {
        'message_id': message_id,
        'payload': {'obj': _build_xpc_object(d)}
    }

    xpc_wrapper = {
        'flags': flags,
        'message': xpc_payload
    }
    return XpcWrapper.build(xpc_wrapper)
