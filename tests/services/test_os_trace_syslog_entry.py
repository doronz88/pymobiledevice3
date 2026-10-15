from uuid import UUID

import pytest

from pymobiledevice3.exceptions import TruncatedDataError
from pymobiledevice3.services.os_trace import SyslogLogLevel, parse_syslog_entry

# a record as an iOS 27.0 device sent it
RECORD = bytes.fromhex(
    "020200000081000000f5000000f5000000000000001479ae4d23f432da85f682c2a31afb7f1700aa070100000000807308010000000080"
    "fe73cc6a00000000cef5030002011302fc06ed01c4af6d1b0a00000084500000000000001479ae4d23f432da85f682c2a31afb7f170015"
    "000000000000000000685c08000000000000002f7573722f6c6962657865632f6c6f636174696f6e64002f7573722f6c6962657865632f"
    "6c6f636174696f6e6400434c3a20496e636f6d696e67206d65737361676500"
)
_LEVEL_OFFSET = 68


def test_a_record_is_parsed_into_its_fields() -> None:
    entry = parse_syslog_entry(RECORD)

    assert entry.pid == 245
    assert entry.procid == 245
    assert entry.level is SyslogLogLevel.INFO
    assert entry.filename == "/usr/libexec/locationd"
    assert entry.image_name == "/usr/libexec/locationd"
    assert entry.message == "CL: Incoming message"
    assert entry.thread_id == 0x5084
    assert entry.image_uuid == UUID("1479ae4d-23f4-32da-85f6-82c2a31afb7f")
    assert entry.process_image_uuid == UUID("1479ae4d-23f4-32da-85f6-82c2a31afb7f")


def test_the_mach_timestamp_is_the_whole_tick_count() -> None:
    # the two bytes ahead of it (ed 01 here) are another field, not its low bits
    assert parse_syslog_entry(RECORD).mach_timestamp == 0xA1B6DAFC4


def test_parse_syslog_entry_truncated_header() -> None:
    with pytest.raises(TruncatedDataError):
        parse_syslog_entry(RECORD[:128])


def test_an_unknown_level_still_parses() -> None:
    record = bytearray(RECORD)
    record[_LEVEL_OFFSET] = 0x7F
    entry = parse_syslog_entry(bytes(record))
    assert entry.level == 0x7F and isinstance(entry.level, SyslogLogLevel)
