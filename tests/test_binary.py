import ipaddress
import struct
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Annotated

import pytest

from pymobiledevice3.binary import (
    Array,
    BinaryStruct,
    ByteReader,
    Bytes,
    Const,
    OpenIntEnum,
    PaddedString,
    encode_utf8_cstring,
    i32,
    ipv4,
    ipv6,
    pad_to,
    u8,
    u16,
    u32,
    u32be,
    u32le,
    uuid_t,
)
from pymobiledevice3.exceptions import BinaryBuildError, BinaryParseError, TruncatedDataError, UnexpectedConstantError

_U32 = struct.Struct("<I")


class Op(IntEnum):
    READ = 1
    WRITE = 2


@dataclass
class Record(BinaryStruct, byte_order=">"):
    magic: Annotated[bytes, Bytes(2), Const(b"RC")] = field(default=b"RC", init=False)
    op: Annotated[Op, u8]
    pid: u32le
    tag: Annotated[bytes, Bytes(3)]
    value: i32
    payload: bytes = b""  # not a wire field


RECORD = Record(Op.WRITE, 0x01020304, b"abc", -2)
RECORD_BYTES = b"RC" + b"\x02" + b"\x04\x03\x02\x01" + b"abc" + b"\xff\xff\xff\xfe"


@dataclass
class Plain(BinaryStruct, byte_order="<"):
    a: u16
    b: u32


def test_build_and_parse_mixed_byte_order() -> None:
    assert Record.SIZE == len(RECORD_BYTES) == 14
    assert RECORD.build() == RECORD_BYTES
    parsed = Record.parse(RECORD_BYTES + b"trailing")
    assert parsed == RECORD
    assert parsed.op is Op.WRITE
    assert parsed.payload == b""


def test_plain_record_round_trip() -> None:
    assert Plain(1, 2).build() == b"\x01\x00\x02\x00\x00\x00"
    assert Plain.parse(b"\x01\x00\x02\x00\x00\x00") == Plain(1, 2)


def test_mixed_byte_order_without_encoders() -> None:
    @dataclass
    class Mixed(BinaryStruct, byte_order="<"):
        a: u16
        b: u32be
        c: u8

    raw = b"\x01\x00" + b"\x00\x00\x00\x02" + b"\x03"
    assert Mixed(1, 2, 3).build() == raw
    assert Mixed.parse(raw) == Mixed(1, 2, 3)
    with pytest.raises(BinaryBuildError):
        Mixed(1, 2, 256).build()


def test_single_field_record() -> None:
    @dataclass
    class Single(BinaryStruct, byte_order="<"):
        value: u16

    assert Single.parse(b"\x01\x02").build() == b"\x01\x02"


def test_truncated_input_raises_truncated_data_error() -> None:
    for cut in range(len(RECORD_BYTES)):
        with pytest.raises(TruncatedDataError):
            Record.parse(RECORD_BYTES[:cut])


def test_constant_is_checked_before_other_conversions() -> None:
    # Wrong magic *and* an invalid enum value: the magic is what gets reported.
    with pytest.raises(UnexpectedConstantError):
        Record.parse(b"XX\x09" + RECORD_BYTES[3:])


def test_short_buffer_with_a_readable_wrong_constant_reports_the_constant() -> None:
    with pytest.raises(UnexpectedConstantError):
        Record.parse(b"XX\x02")
    with pytest.raises(TruncatedDataError):
        Record.parse(b"RC\x02")
    with pytest.raises(TruncatedDataError):
        Record.parse(b"X")  # the constant is not readable yet


def test_errors_report_record_field_and_absolute_offset() -> None:
    with pytest.raises(TruncatedDataError) as truncated:
        Record.parse(RECORD_BYTES[:8])
    assert (truncated.value.record, truncated.value.field, truncated.value.offset) == ("Record", "tag", 7)
    assert str(truncated.value) == "Record.tag at offset 7: expected 3 bytes, found 1"

    # A reader with both a base and an offset: errors report base + offset + field offset.
    reader = ByteReader(b"\0" * 5 + b"XX" + RECORD_BYTES[2:], offset=5, base=100)
    with pytest.raises(UnexpectedConstantError) as wrong_magic:
        Record.read(reader)
    assert (wrong_magic.value.field, wrong_magic.value.offset) == ("magic", 105)
    assert str(wrong_magic.value) == "Record.magic at offset 105: expected b'RC', got b'XX'"

    reader = ByteReader(b"\0" * 5 + b"RC\x09" + RECORD_BYTES[3:], offset=5, base=100)
    with pytest.raises(BinaryParseError) as bad_enum:
        Record.read(reader)
    assert (bad_enum.value.field, bad_enum.value.offset) == ("op", 107)

    with pytest.raises(TruncatedDataError) as short:
        Record.read(ByteReader(b"\0" * 5 + RECORD_BYTES[:10], offset=5, base=100))
    assert (short.value.field, short.value.offset) == ("value", 115)

    nested = ByteReader(b"\0" * 3 + RECORD_BYTES[:4], offset=3).sub(4)
    with pytest.raises(TruncatedDataError) as nested_truncated:
        Record.read(nested)
    assert nested_truncated.value.offset == 3 + 3


def test_constant_at_a_non_zero_field_offset() -> None:
    @dataclass
    class Tail(BinaryStruct):
        a: u8
        magic: Annotated[u16, Const(0x1234)] = field(default=0x1234, init=False)

    assert Tail(7).build() == b"\x07\x34\x12"
    with pytest.raises(UnexpectedConstantError) as wrong:
        Tail.parse(b"\x07\x00\x00")
    assert str(wrong.value) == "Tail.magic at offset 1: expected 0x1234, got 0x0"
    with pytest.raises(UnexpectedConstantError) as wrong_in_reader:
        Tail.read(ByteReader(b"\0\0\x07\x00\x00", offset=2, base=10))
    assert wrong_in_reader.value.offset == 13


def test_build_errors() -> None:
    record = Record(Op.READ, 0, b"abc", 0)
    record.magic = b"XX"
    with pytest.raises(BinaryBuildError) as wrong_magic:
        record.build()
    assert not isinstance(wrong_magic.value, BinaryParseError)
    assert str(wrong_magic.value) == "Record.magic: expected b'RC', got b'XX'"

    with pytest.raises(BinaryBuildError) as out_of_range:
        Record(Op.READ, -1, b"abc", 0).build()
    assert out_of_range.value.record == "Record"
    with pytest.raises(BinaryBuildError):
        Plain(1, 2**32).build()  # the single-pack path

    with pytest.raises(BinaryBuildError) as wrong_length:
        Record(Op.READ, 0, b"ab", 0).build()  # struct would silently pad
    assert (wrong_length.value.record, wrong_length.value.field) == ("Record", "tag")
    with pytest.raises(BinaryBuildError):
        Record(Op.READ, 0, b"abcd", 0).build()  # struct would silently truncate


def test_constant_fields_are_not_encoded_on_build() -> None:
    assert [f.name for f in Record._encoders] == ["tag"]


def test_padded_string() -> None:
    @dataclass
    class Named(BinaryStruct):
        name: Annotated[str, PaddedString(4)]
        lenient: Annotated[str, PaddedString(4, errors="replace")]

    assert Named.parse(b"ab\0x" + b"\xc3\0\0\0") == Named("ab", "�")
    assert Named.parse(b"abc\0" + b"\0\0\0\0").name == "abc"
    with pytest.raises(BinaryParseError, match="not terminated") as unterminated:
        Named.parse(b"abcd" + b"\0\0\0\0")
    assert (unterminated.value.field, unterminated.value.offset) == ("name", 0)
    with pytest.raises(BinaryParseError, match="invalid UTF-8") as invalid:
        Named.parse(b"\xc3\0\0\0" + b"\0\0\0\0")
    assert invalid.value.field == "name"


def test_uuid_ip_and_array_fields() -> None:
    @dataclass
    class Extras(BinaryStruct, byte_order=">"):
        id: uuid_t
        v4: ipv4
        v6: ipv6
        counts: Annotated[list[int], Array(u16, 3)]
        pinned: Annotated[list[int], Array(u32be, 1)]

    raw = (
        uuid.UUID(int=1).bytes
        + ipaddress.IPv4Address("10.0.0.1").packed
        + ipaddress.IPv6Address("fe80::1").packed
        + b"\x01\x00\x02\x00\x02\x01"  # little-endian unless pinned
        + b"\x00\x00\x00\x05"
    )
    assert len(raw) == Extras.SIZE
    assert Extras.parse(raw) == Extras(
        uuid.UUID(int=1), ipaddress.IPv4Address("10.0.0.1"), ipaddress.IPv6Address("fe80::1"), [1, 2, 0x102], [5]
    )

    @dataclass
    class V4(BinaryStruct):
        addr: ipv4

    assert V4(ipaddress.IPv4Address("1.2.3.4")).build() == b"\x01\x02\x03\x04"


def test_init_false_fields() -> None:
    @dataclass
    class Padded(BinaryStruct):
        a: u8
        pad: Annotated[bytes, Bytes(2)] = field(default=bytes(2), init=False, compare=False)
        magic: Annotated[u8, Const(7)] = field(default=7, init=False)
        b: u8

    assert Padded(1, 2).build() == b"\x01\x00\x00\x07\x02"
    parsed = Padded.parse(b"\x01\xaa\xbb\x07\x02")
    assert (parsed.a, parsed.pad, parsed.magic, parsed.b) == (1, bytes(2), 7, 2)
    with pytest.raises(UnexpectedConstantError):
        Padded.parse(b"\x01\x00\x00\x08\x02")

    @dataclass
    class OneArgument(BinaryStruct):
        magic: Annotated[u8, Const(7)] = field(default=7, init=False)
        a: u8

    assert OneArgument.parse(b"\x07\x05") == OneArgument(5)

    @dataclass
    class OnlyConstants(BinaryStruct):
        magic: Annotated[u8, Const(7)] = field(default=7, init=False)

    assert OnlyConstants.parse(b"\x07") == OnlyConstants()


def test_records_cannot_be_subclassed() -> None:
    with pytest.raises(TypeError, match="subclassed"):

        @dataclass
        class Derived(Plain):
            c: u8


def test_reader() -> None:
    reader = ByteReader(b"\x01\x02\x03\x04abc\0rest", base=10)
    assert reader.unpack(struct.Struct("<BB")) == (1, 2)
    assert reader.unpack_one(struct.Struct("<H")) == 0x0403
    assert (reader.offset, reader.absolute, reader.remaining) == (4, 14, 8)
    assert reader.read_utf8_cstring() == "abc"
    assert reader.read_all() == b"rest"
    assert reader.remaining == 0

    reader = ByteReader(b"abcdef", offset=2, base=10)
    sub = reader.sub(2)
    assert (sub.data, sub.absolute, reader.offset) == (b"cd", 12, 4)
    with pytest.raises(TruncatedDataError) as truncated:
        sub.read(3)
    assert truncated.value.offset == 12
    assert str(truncated.value) == "at offset 12: expected 3 bytes, found 2"


def test_prefixed() -> None:
    reader = ByteReader(_U32.pack(3) + b"abc" + b"next", base=10)
    body = reader.prefixed(_U32)
    assert (body.data, body.absolute) == (b"abc", 14)
    assert reader.read_all() == b"next"
    with pytest.raises(TruncatedDataError):
        ByteReader(_U32.pack(5) + b"abc").prefixed(_U32)


def test_reader_errors() -> None:
    reader = ByteReader(b"abc", offset=1, base=10)
    with pytest.raises(BinaryParseError, match="invalid size") as negative:
        reader.read(-1)
    assert not isinstance(negative.value, TruncatedDataError)
    assert reader.offset == 1
    for offset in (-1, 4):
        with pytest.raises(BinaryParseError, match="invalid offset"):
            ByteReader(b"abc", offset=offset)
    assert ByteReader(b"abc", offset=3).remaining == 0
    with pytest.raises(TruncatedDataError) as unterminated:
        ByteReader(b"xabc", offset=1, base=10).read_cstring()
    assert unterminated.value.offset == 11
    with pytest.raises(BinaryParseError, match="invalid UTF-8") as invalid:
        ByteReader(b"x\xc3\0", offset=1, base=10).read_utf8_cstring()
    assert not isinstance(invalid.value, TruncatedDataError)
    assert invalid.value.offset == 11


def test_open_int_enum_keeps_unknown_values() -> None:
    class Level(OpenIntEnum):
        INFO = 1

    assert Level(1) is Level.INFO
    unknown = Level(77)
    assert unknown == 77 and isinstance(unknown, Level) and unknown.name == "77"
    assert Level(77) is unknown
    with pytest.raises(ValueError):
        Level("x")


def test_cstring_and_padding_helpers() -> None:
    assert encode_utf8_cstring("hé") == b"h\xc3\xa9\0"
    with pytest.raises(BinaryBuildError, match="embedded NUL"):
        encode_utf8_cstring("a\0b")
    with pytest.raises(BinaryBuildError):
        encode_utf8_cstring("\udcff")
    assert pad_to(b"abc", 4) == b"abc\0"
    assert pad_to(b"abcd", 4) == b"abcd"
