from io import BytesIO

import pytest
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket, InterfaceDescription, SectionHeader

from pymobiledevice3.services.bt_packet_logger import (
    PCAPNG_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR,
    PacketLoggerPacketType,
    packetlogger_record_to_hci_h4_phdr,
    parse_packetlogger_record,
    write_packetlogger_stream,
    write_pcapng_stream,
)


def _create_packetlogger_record(
    packet_type: int,
    payload: bytes,
    *,
    seconds: int = 0x01020304,
    microseconds: int = 0x05060708,
) -> bytes:
    payload_length = 9 + len(payload)
    return (
        payload_length.to_bytes(4, "big")
        + seconds.to_bytes(4, "big")
        + microseconds.to_bytes(4, "big")
        + bytes([packet_type])
        + payload
    )


def test_parse_packetlogger_record() -> None:
    payload = b"\x01\x02\x03\x04"
    raw_record = _create_packetlogger_record(PacketLoggerPacketType.HCI_EVENT, payload)

    record = parse_packetlogger_record(raw_record)

    assert record.length == 9 + len(payload)
    assert record.seconds == 0x01020304
    assert record.microseconds == 0x05060708
    assert record.packet_type == PacketLoggerPacketType.HCI_EVENT
    assert record.payload == payload


def test_parse_packetlogger_record_rejects_short_input() -> None:
    with pytest.raises(ValueError, match="too short"):
        parse_packetlogger_record(b"\x00" * 12)


@pytest.mark.parametrize(
    ("packet_type", "expected_direction", "expected_h4_type"),
    [
        (PacketLoggerPacketType.HCI_COMMAND, 0, 0x01),
        (PacketLoggerPacketType.SENT_ACL_DATA, 0, 0x02),
        (PacketLoggerPacketType.RECV_ACL_DATA, 1, 0x02),
        (PacketLoggerPacketType.SENT_SCO_DATA, 0, 0x03),
        (PacketLoggerPacketType.RECV_SCO_DATA, 1, 0x03),
        (PacketLoggerPacketType.HCI_EVENT, 1, 0x04),
    ],
)
def test_packetlogger_record_to_hci_h4_phdr(packet_type, expected_direction, expected_h4_type) -> None:
    payload = b"\xaa\xbb\xcc"
    record = parse_packetlogger_record(_create_packetlogger_record(packet_type, payload))

    frame = packetlogger_record_to_hci_h4_phdr(record)

    assert frame is not None
    assert int.from_bytes(frame[0:4], "big") == expected_direction
    assert frame[4] == expected_h4_type
    assert frame[5:] == payload


def test_packetlogger_record_to_hci_h4_phdr_skips_unknown_type() -> None:
    record = parse_packetlogger_record(_create_packetlogger_record(0xFC, b"\x00\x01"))

    assert packetlogger_record_to_hci_h4_phdr(record) is None


@pytest.mark.asyncio
async def test_write_packetlogger_stream() -> None:
    records = [
        _create_packetlogger_record(PacketLoggerPacketType.HCI_COMMAND, b"\x01"),
        _create_packetlogger_record(PacketLoggerPacketType.HCI_EVENT, b"\x02\x03"),
    ]
    out = BytesIO()

    async def generate():
        for record in records:
            yield record

    await write_packetlogger_stream(out, generate())

    assert out.getvalue() == b"".join(records)


@pytest.mark.asyncio
async def test_write_pcapng_stream() -> None:
    seconds = 0x01020304
    microseconds = 0x00050607
    payload = b"\x11\x22"
    record = _create_packetlogger_record(
        PacketLoggerPacketType.RECV_ACL_DATA, payload, seconds=seconds, microseconds=microseconds
    )
    out = BytesIO()

    async def generate():
        yield record

    await write_pcapng_stream(out, generate(), product_version="17.0")

    out.seek(0)
    parsed = list(FileScanner(out))
    assert isinstance(parsed[0], SectionHeader)
    interface = next(block for block in parsed if isinstance(block, InterfaceDescription))
    assert interface.link_type == PCAPNG_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR

    packets = [block for block in parsed if isinstance(block, EnhancedPacket)]
    assert len(packets) == 1
    # recv ACL -> direction 1, H4 type 0x02
    assert packets[0].packet_data == b"\x00\x00\x00\x01\x02" + payload
    expected_us = seconds * 1_000_000 + microseconds
    actual_us = (packets[0].timestamp_high << 32) | packets[0].timestamp_low
    assert actual_us == expected_us


@pytest.mark.asyncio
async def test_write_pcapng_stream_converts_local_time_to_utc() -> None:
    seconds = 0x01020304
    microseconds = 0x00050607
    tz_offset_seconds = 2 * 3600  # device in UTC+2
    record = _create_packetlogger_record(
        PacketLoggerPacketType.HCI_EVENT, b"\x11\x22", seconds=seconds, microseconds=microseconds
    )
    out = BytesIO()

    async def generate():
        yield record

    await write_pcapng_stream(out, generate(), tz_offset_seconds=tz_offset_seconds)

    out.seek(0)
    packets = [block for block in FileScanner(out) if isinstance(block, EnhancedPacket)]
    assert len(packets) == 1
    expected_us = (seconds - tz_offset_seconds) * 1_000_000 + microseconds
    actual_us = (packets[0].timestamp_high << 32) | packets[0].timestamp_low
    assert actual_us == expected_us


@pytest.mark.asyncio
async def test_write_pcapng_stream_accepts_float_tz_offset() -> None:
    # Lockdown reports TimeZoneOffsetFromUTC as a float, which previously made the microsecond
    # timestamp a float and broke the >> 32 bit-shift used for timestamp_high.
    seconds = 0x01020304
    microseconds = 0x00050607
    tz_offset_seconds = 2 * 3600.0  # float, as returned by a real device
    record = _create_packetlogger_record(
        PacketLoggerPacketType.HCI_EVENT, b"\x11\x22", seconds=seconds, microseconds=microseconds
    )
    out = BytesIO()

    async def generate():
        yield record

    # The float is the point of this test: devices send TimeZoneOffsetFromUTC as a float.
    await write_pcapng_stream(out, generate(), tz_offset_seconds=tz_offset_seconds)

    out.seek(0)
    packets = [block for block in FileScanner(out) if isinstance(block, EnhancedPacket)]
    assert len(packets) == 1
    expected_us = int((seconds - tz_offset_seconds) * 1_000_000 + microseconds)
    actual_us = (packets[0].timestamp_high << 32) | packets[0].timestamp_low
    assert actual_us == expected_us


@pytest.mark.asyncio
async def test_write_pcapng_stream_skips_malformed_and_unknown() -> None:
    out = BytesIO()

    async def generate():
        yield b"\x00\x01\x02"  # too short to parse
        yield _create_packetlogger_record(0xFC, b"\x00\x01")  # unknown type
        yield _create_packetlogger_record(PacketLoggerPacketType.HCI_EVENT, b"\x04\x05")

    await write_pcapng_stream(out, generate())

    out.seek(0)
    packets = [block for block in FileScanner(out) if isinstance(block, EnhancedPacket)]
    assert len(packets) == 1
    assert packets[0].packet_data == b"\x00\x00\x00\x01\x04\x04\x05"
