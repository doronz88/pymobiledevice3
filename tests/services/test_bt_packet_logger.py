from io import BytesIO

import pytest

from pymobiledevice3.services.bt_packet_logger import (
    PCAP_GLOBAL_HEADER,
    PacketLoggerPacketType,
    packetlogger_to_pcap_record,
    parse_packetlogger_record,
    write_packetlogger_stream,
    write_pcap_stream,
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
def test_packetlogger_to_pcap_record(packet_type, expected_direction, expected_h4_type) -> None:
    payload = b"\xaa\xbb\xcc"
    raw_record = _create_packetlogger_record(packet_type, payload)

    pcap_record = packetlogger_to_pcap_record(raw_record)

    assert int.from_bytes(pcap_record[0:4], "big") == 0x01020304
    assert int.from_bytes(pcap_record[4:8], "big") == 0x05060708
    assert int.from_bytes(pcap_record[8:12], "big") == 5 + len(payload)
    assert int.from_bytes(pcap_record[12:16], "big") == 5 + len(payload)
    assert int.from_bytes(pcap_record[16:20], "big") == expected_direction
    assert pcap_record[20] == expected_h4_type
    assert pcap_record[21:] == payload


def test_packetlogger_to_pcap_record_skips_unknown_type() -> None:
    raw_record = _create_packetlogger_record(0xFC, b"\x00\x01")

    assert packetlogger_to_pcap_record(raw_record) is None


def test_packetlogger_to_pcap_record_skips_short_record() -> None:
    assert packetlogger_to_pcap_record(b"\x00\x01\x02\x03\x04\x05") is None


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
async def test_write_pcap_stream() -> None:
    record = _create_packetlogger_record(PacketLoggerPacketType.RECV_ACL_DATA, b"\x11\x22")
    out = BytesIO()

    async def generate():
        yield record

    await write_pcap_stream(out, generate())

    output = out.getvalue()
    assert output.startswith(PCAP_GLOBAL_HEADER)
    assert output[len(PCAP_GLOBAL_HEADER) :] == packetlogger_to_pcap_record(record)
