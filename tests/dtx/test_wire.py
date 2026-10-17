import struct

import pytest
from bytestruct import BinaryBuildError, BinaryParseError, TruncatedDataError, UnexpectedConstantError

from pymobiledevice3.dtx.message_aux import MessageAux
from pymobiledevice3.dtx.primitives import (
    PNULL,
    PBuf,
    PDict,
    PDouble,
    PInt32,
    PInt64,
    PStr,
    build_primitive,
    parse_primitive,
)
from pymobiledevice3.dtx.structs import DTX_FRAGMENT_MAGIC, DtxFragmentHeader, DtxFragmentPayloadHeader

# Built by the construct-based codec this module replaced.
_GOLDEN_PRIMITIVE_DICT = bytes.fromhex(
    "f00100000000000050000000000000000a000000010000000200000068690a00000003000000ffffffff0a000000060000000000"
    "0000000100000a00000009000000000000000000f83f0a000000020000000200000001020a0000000a000000"
)


def test_primitive_dictionary_wire_format() -> None:
    value = PDict({PNULL: [PStr("hi"), PInt32(-1), PInt64(2**40), PDouble(1.5), PBuf(b"\x01\x02"), PNULL]})
    assert build_primitive(value) == _GOLDEN_PRIMITIVE_DICT
    assert parse_primitive(_GOLDEN_PRIMITIVE_DICT) == {PNULL: ["hi", -1, 2**40, 1.5, b"\x01\x02", PNULL]}


def test_primitive_errors() -> None:
    with pytest.raises(TruncatedDataError):
        parse_primitive(_GOLDEN_PRIMITIVE_DICT[:-1])
    with pytest.raises(BinaryParseError):
        parse_primitive(struct.pack("<I", 0x77))  # unknown type code
    with pytest.raises(BinaryBuildError):
        build_primitive(PInt32(2**31))
    with pytest.raises(BinaryBuildError):
        build_primitive(object())


def test_message_aux_roundtrip() -> None:
    raw = MessageAux.build(["hi", 7, None])
    assert MessageAux.parse(raw) == ["hi", 7, None]  # None travels as an empty buffer
    assert MessageAux.parse(b"") == []


def test_fragment_headers() -> None:
    raw = struct.pack("<IIHHIIIiI", DTX_FRAGMENT_MAGIC, 32, 0, 1, 16, 5, 1, -1, 0)
    header = DtxFragmentHeader.parse(raw)
    assert (header.index, header.count, header.data_size, header.channel_code) == (0, 1, 16, -1)
    assert header.build() == raw
    assert DtxFragmentHeader(32, 0, 1, 16, 5, 1, -1, 0) == header  # the magic is not a constructor argument
    with pytest.raises(UnexpectedConstantError):
        DtxFragmentHeader.parse(b"\0" * 32)
    payload = struct.pack("<BBBBIII", 2, 0, 0, 0, 8, 24, 0)
    assert DtxFragmentPayloadHeader.parse(payload).build() == payload
