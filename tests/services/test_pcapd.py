import io
import struct
from types import SimpleNamespace
from typing import Any, cast

import pytest
from bytestruct import BinaryParseError, TruncatedDataError
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.pcapd import PcapdService, parse_device_packet


def _device_packet(header_length: int = 95, data: bytes = b"\x45\x00payload") -> bytes:
    header = struct.pack(">IBIBHBIII", header_length, 2, len(data), 6, 1, 0, 2, 14, 0)
    header += b"en0\0".ljust(16, b"\xaa") + struct.pack("<I", 1234) + b"mDNSResponder\0".ljust(17, b"\xbb")
    header += struct.pack(">I", 7) + struct.pack("<I", 5678) + b"launchd\0".ljust(17, b"\xcc")
    header += struct.pack(">II", 1700000000, 123456)
    return header.ljust(header_length, b"\xdd") + data


@pytest.mark.parametrize("header_length", [95, 128])
def test_parse_device_packet(header_length: int) -> None:
    packet = parse_device_packet(_device_packet(header_length))
    assert packet.header_length == header_length
    assert packet.header_version == 2
    assert packet.packet_length == 9
    assert packet.interface_type == 6
    assert packet.unit == 1
    assert packet.protocol_family == 2
    assert packet.frame_pre_length == 14
    assert packet.interface_name == "en0"
    assert packet.pid == 1234
    assert packet.comm == "mDNSResponder"
    assert packet.svc == 7
    assert packet.epid == 5678
    assert packet.ecomm == "launchd"
    assert (packet.seconds, packet.microseconds) == (1700000000, 123456)
    assert packet.data == b"\x45\x00payload"


def test_parse_device_packet_truncated() -> None:
    raw = _device_packet(128)
    for cut in (0, 50, 95, 127, len(raw) - 1):
        with pytest.raises(TruncatedDataError):
            parse_device_packet(raw[:cut])


def test_parse_device_packet_invalid_name() -> None:
    raw = bytearray(_device_packet())
    raw[25:41] = b"\xff" + b"\0" * 15  # interface names are strict UTF-8
    with pytest.raises(BinaryParseError):
        parse_device_packet(bytes(raw))


def test_parse_device_packet_name_truncated_mid_character() -> None:
    raw = bytearray(_device_packet())
    raw[45:62] = ("a" + "\u00fc" * 8).encode()[:16] + b"\0"  # comm, cut inside the last character
    assert parse_device_packet(bytes(raw)).comm == "a" + "\u00fc" * 7 + "\ufffd"


@pytest.mark.asyncio
async def test_write_to_pcap_uses_device_timestamps() -> None:
    async def packets():
        yield parse_device_packet(_device_packet())

    service = PcapdService.__new__(PcapdService)
    service.lockdown = cast(Any, SimpleNamespace(product_version="18.0"))
    out = io.BytesIO()
    await service.write_to_pcap(out, packets())
    out.seek(0)
    (block,) = [block for block in FileScanner(out) if isinstance(block, EnhancedPacket)]
    assert (block.timestamp_high << 32) | block.timestamp_low == 1700000000 * 1_000_000 + 123456


@pytest.mark.asyncio
async def test_sniffing(lockdown: LockdownClient) -> None:
    """
    Test sniffing device traffic.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    async with PcapdService(lockdown) as pcapd:
        packets = []
        async for packet in pcapd.watch(packets_count=2):
            packets.append(packet)
        assert len(packets) == 2

        first_packet_time = packets[0].seconds + (packets[0].microseconds / 1000000)
        second_packet_time = packets[1].seconds + (packets[1].microseconds / 1000000)
        assert first_packet_time < second_packet_time

        assert len(packets[0].data) == packets[0].packet_length
        assert packets[0].header_version == 2
