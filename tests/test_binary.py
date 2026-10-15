import ipaddress
import struct
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Annotated

import pytest

from pymobiledevice3.binary import (
    CSTRING,
    GREEDY_BYTES,
    PASS,
    U8,
    U16_BE,
    U32_LE,
    Aligned,
    Array,
    BinaryStruct,
    ByteReader,
    Bytes,
    Const,
    CString,
    OpenIntEnum,
    PaddedString,
    Prefixed,
    PrefixedArray,
    Switch,
    Tuple,
    i32,
    ipv4,
    ipv6,
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
    assert reader.read_cstring() == b"abc"
    reader.skip(1)
    assert reader.read_all() == b"est"
    assert reader.remaining == 0


def test_sub_reader_is_a_window_on_the_same_buffer() -> None:
    reader = ByteReader(b"abcdef", offset=2, base=10)
    sub = reader.sub(2)
    assert sub.data is reader.data
    assert (sub.absolute, sub.remaining, reader.offset) == (12, 2, 4)
    with pytest.raises(TruncatedDataError) as truncated:
        sub.read(3)
    assert str(truncated.value) == "at offset 12: expected 3 bytes, found 2"
    for read in (lambda r: r.unpack_one(U32_LE), lambda r: r.skip(3), lambda r: r.sub(3)):
        with pytest.raises(TruncatedDataError):
            read(ByteReader(b"abcdef").sub(2))
    with pytest.raises(TruncatedDataError, match="unterminated"):
        ByteReader(b"ab\0").sub(2).read_cstring()  # the NUL is past the window
    assert sub.read_all() == b"cd"


def test_records_do_not_read_past_the_reader_window() -> None:
    data = bytes(range(1, 8))
    with pytest.raises(TruncatedDataError, match=r"^Plain\.b at offset 2: expected 4 bytes, found 3$"):
        Plain.read(ByteReader(data).sub(5))
    assert Plain.read(ByteReader(data).sub(6)) == Plain(0x0201, 0x06050403)


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


def test_open_int_enum_keeps_unknown_values() -> None:
    class Level(OpenIntEnum):
        INFO = 1

    assert Level(1) is Level.INFO
    unknown = Level(77)
    assert unknown == 77 and isinstance(unknown, Level) and unknown.name == "77"
    assert Level(77) is unknown
    with pytest.raises(ValueError):
        Level("x")


def test_cstring() -> None:
    assert CSTRING.build("hé") == b"h\xc3\xa9\0"
    assert CSTRING.parse(b"h\xc3\xa9\0rest") == "hé"
    with pytest.raises(BinaryBuildError, match="embedded NUL"):
        CSTRING.build("a\0b")
    with pytest.raises(BinaryBuildError):
        CSTRING.build("\udcff")
    with pytest.raises(BinaryParseError, match="invalid UTF-8") as invalid:
        CSTRING.read(ByteReader(b"x\xc3\0", offset=1, base=10))
    assert not isinstance(invalid.value, TruncatedDataError)
    assert invalid.value.offset == 11
    assert CString(errors="replace").parse(b"\xc3\0") == "\ufffd"


def test_scalar_and_bytes_codecs() -> None:
    assert U16_BE.build(0x1234) == b"\x12\x34"
    assert U16_BE.parse(b"\x12\x34") == 0x1234
    with pytest.raises(BinaryBuildError, match="cannot encode 256"):
        U8.build(256)
    assert Bytes(2).read(ByteReader(b"abc")) == b"ab"
    assert Bytes(2).build(bytearray(b"ab")) == b"ab"
    with pytest.raises(BinaryBuildError, match="expected 2 bytes, got 3"):
        Bytes(2).build(b"abc")
    assert PASS.parse(b"abc") is None and PASS.build(None) == b""


def test_prefixed() -> None:
    string = Prefixed(U32_LE, CSTRING)
    assert string.build("ab") == _U32.pack(3) + b"ab\0"
    reader = ByteReader(_U32.pack(3) + b"ab\0" + b"next", base=10)
    assert string.read(reader) == "ab"
    assert (reader.offset, reader.end) == (7, 11)  # the window is restored
    assert reader.read_all() == b"next"
    with pytest.raises(TruncatedDataError, match="at offset 14: expected 5 bytes, found 3"):
        Prefixed(U32_LE, GREEDY_BYTES).read(ByteReader(_U32.pack(5) + b"abc", base=10))
    with pytest.raises(TruncatedDataError, match="unterminated"):
        string.parse(_U32.pack(2) + b"ab\0")  # the terminator is outside the prefixed bytes
    # Bytes the inner value leaves unread are skipped.
    reader = ByteReader(_U32.pack(4) + b"a\0bc" + b"next")
    assert string.read(reader) == "a"
    assert reader.read_all() == b"next"
    with pytest.raises(BinaryBuildError, match="length of 256"):
        Prefixed(U8, GREEDY_BYTES).build(b"x" * 256)


def test_aligned_pads_from_where_the_value_starts() -> None:
    padded = Aligned(4, CSTRING)
    assert padded.build("ab") == b"ab\0\0"
    assert padded.build("abc") == b"abc\0"
    reader = ByteReader(b"xa\0\0\0next", offset=1)
    assert padded.read(reader) == "a"
    assert reader.read_all() == b"next"
    with pytest.raises(TruncatedDataError):
        padded.parse(b"a\0\0")


def test_prefixed_array_and_tuple() -> None:
    assert Tuple(U8, U8, CSTRING).build((1, 2, "a")) == b"\x01\x02a\0"
    assert Tuple(U8, U8, CSTRING).parse(b"\x01\x02a\0") == (1, 2, "a")
    with pytest.raises(BinaryBuildError, match="expected 3 values, got 2"):
        Tuple(U8, U8, CSTRING).build((1, 2))
    entries = PrefixedArray(U8, Tuple(CSTRING, U8))
    data = b"\x02a\0\x01b\0\x02"
    assert entries.build([("a", 1), ("b", 2)]) == data
    assert entries.parse(data) == [("a", 1), ("b", 2)]
    assert entries.parse(b"\x00") == []
    with pytest.raises(TruncatedDataError) as truncated:
        entries.parse(data[:-1])
    assert str(truncated.value) == "[1] at offset 6: expected 1 bytes, found 0"
    with pytest.raises(BinaryBuildError, match=r"^\[1\]: expected 2 values, got 1"):
        entries.build([("a", 1), ("b",)])


class Kind(IntEnum):
    TEXT = 1
    NUMBER = 2


def test_switch() -> None:
    value = Switch(U8, {Kind.TEXT: CSTRING, Kind.NUMBER: U16_BE})
    assert value.build((Kind.TEXT, "a")) == b"\x01a\0"
    assert value.parse(b"\x02\x00\x05") == (2, 5)
    with pytest.raises(BinaryParseError, match="at offset 0: unknown tag 0x3"):
        value.parse(b"\x03")
    with pytest.raises(BinaryBuildError, match="unknown tag 0x3"):
        value.build((3, None))
    with pytest.raises(TruncatedDataError) as truncated:
        value.parse(b"\x02\x00")
    assert str(truncated.value) == "NUMBER at offset 1: expected 2 bytes, found 1"
    with pytest.raises(BinaryBuildError, match=r"^TEXT: embedded NUL"):
        value.build((Kind.TEXT, "a\0"))
    with pytest.raises(BinaryBuildError, match=r"^NUMBER: cannot encode 65536"):
        value.build((Kind.NUMBER, 65536))  # a scalar case
    with pytest.raises(BinaryBuildError, match="cannot encode 256"):
        Switch(U8, {256: PASS}).build((256, None))

    with_default = Switch(U8, {1: U8}, default=PASS)
    assert with_default.parse(b"\x01\x07") == (1, 7)
    assert with_default.parse(b"\x02\x07") == (2, None)
    assert with_default.build((2, None)) == b"\x02"


def test_error_path_through_nested_codecs() -> None:
    tree = PrefixedArray(U8, Switch(U8, {Kind.TEXT: Aligned(4, Prefixed(U32_LE, CSTRING))}))
    data = b"\x02" + b"\x01" + _U32.pack(2) + b"a\0" + b"\0\0" + b"\x01" + _U32.pack(200) + b"x"
    with pytest.raises(TruncatedDataError) as truncated:
        tree.parse(data)
    assert str(truncated.value) == "[1] -> TEXT at offset 15: expected 200 bytes, found 1"
    assert truncated.value.path == ["[1]", "TEXT"]
    located = truncated.value.located(record="R")
    assert (str(located), located.path) == (
        "[1] -> TEXT -> R at offset 15: expected 200 bytes, found 1",
        ["[1]", "TEXT"],
    )


@dataclass
class Named(BinaryStruct, byte_order=">"):
    magic: Annotated[int, u16, Const(0xCAFE)] = field(default=0xCAFE, init=False)
    kind: Annotated[Kind, u8]
    name: Annotated[str, CSTRING]
    body: Annotated[bytes, Prefixed(U16_BE, GREEDY_BYTES)]


def test_record_with_codec_fields() -> None:
    record = Named(Kind.TEXT, "ab", b"xyz")
    data = b"\xca\xfe\x01ab\0\x00\x03xyz"
    assert record.build() == data
    assert Named.parse(data + b"trailing") == record
    assert isinstance(Named.parse(data).kind, Kind)
    assert Named.SIZE == 3  # the fixed-size fields
    reader = ByteReader(data + b"next")
    assert Named.read(reader) == record
    assert reader.read_all() == b"next"
    assert PrefixedArray(U8, Named).parse(b"\x01" + data) == [record]  # records are codecs

    with pytest.raises(UnexpectedConstantError, match=r"Named\.magic at offset 0"):
        Named.parse(b"\x00" * 12)
    with pytest.raises(TruncatedDataError) as truncated:
        Named.parse(data[:-1])
    assert str(truncated.value) == "Named.body at offset 8: expected 3 bytes, found 2"
    with pytest.raises(BinaryBuildError, match=r"^Named\.name: embedded NUL"):
        Named(Kind.TEXT, "a\0", b"").build()


def test_codec_fields_follow_the_fixed_size_fields() -> None:
    with pytest.raises(TypeError, match="must precede the codec fields"):

        @dataclass
        class Interleaved(BinaryStruct):
            name: Annotated[str, CSTRING]
            size: u32
