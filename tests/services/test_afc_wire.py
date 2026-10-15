import struct

import pytest

from pymobiledevice3.binary import CSTRING
from pymobiledevice3.exceptions import BinaryBuildError, TruncatedDataError, UnexpectedConstantError
from pymobiledevice3.services.afc import (
    AFCMAGIC,
    AfcError,
    AfcFileSeekRequest,
    AfcHeader,
    AfcOpcode,
    AfcReadDirResponse,
    parse_afc_status,
)


def test_header_wire_format() -> None:
    raw = AFCMAGIC + struct.pack("<QQQQ", 0x31, 0x28, 7, AfcOpcode.READ_DIR)
    header = AfcHeader.parse(raw)
    assert (header.entire_length, header.this_length, header.packet_num) == (0x31, 0x28, 7)
    assert header.operation is AfcOpcode.READ_DIR
    assert header.build() == raw
    assert AfcHeader(0x31, 0x28, 7, AfcOpcode.READ_DIR) == header  # the magic is not a constructor argument


def test_header_errors() -> None:
    raw = AFCMAGIC + struct.pack("<QQQQ", 0x28, 0x28, 0, AfcOpcode.STATUS)
    with pytest.raises(UnexpectedConstantError):
        AfcHeader.parse(b"X" + raw[1:])
    with pytest.raises(TruncatedDataError):
        AfcHeader.parse(raw[:-1])


def test_unknown_opcode_and_status_still_parse() -> None:
    header = AfcHeader.parse(AFCMAGIC + struct.pack("<QQQQ", 0x28, 0x28, 0, 0x99))
    assert header.operation == 0x99 and isinstance(header.operation, AfcOpcode)
    status = parse_afc_status(struct.pack("<Q", 0x77))
    assert status == 0x77 and status is AfcError(0x77)


def test_request_bodies() -> None:
    assert AfcFileSeekRequest(3, 1, -2).build() == struct.pack("<QQq", 3, 1, -2)
    with pytest.raises(BinaryBuildError):
        CSTRING.build("a\0b")  # a rename source would make the device rename "a" to "b"
    with pytest.raises(BinaryBuildError):
        CSTRING.build("\udcff")


def test_read_dir_response_stops_at_an_undecodable_tail() -> None:
    assert AfcReadDirResponse.parse(b".\0..\0name\0\xff\xfe\0").filenames == [".", "..", "name"]
