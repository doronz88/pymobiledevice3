import logging
from collections.abc import AsyncGenerator, AsyncIterable
from dataclasses import dataclass
from enum import IntEnum
from struct import pack, unpack
from typing import BinaryIO, Optional

import pcapng.blocks as blocks
from pcapng import FileWriter

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

PACKETLOGGER_RECORD_HEADER_SIZE = 13
SERVICE_PACKET_SIZE_HEADER = 2
PCAPNG_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
logger = logging.getLogger(__name__)


class PacketLoggerPacketType(IntEnum):
    HCI_COMMAND = 0x00
    HCI_EVENT = 0x01
    SENT_ACL_DATA = 0x02
    RECV_ACL_DATA = 0x03
    SENT_SCO_DATA = 0x08
    RECV_SCO_DATA = 0x09


# Maps a PacketLogger record type to its HCI H4 type byte and direction (0 = sent, 1 = received).
HCI_H4_TYPE_BY_PACKET_TYPE: dict[int, tuple[int, int]] = {
    PacketLoggerPacketType.HCI_COMMAND: (0x01, 0),
    PacketLoggerPacketType.SENT_ACL_DATA: (0x02, 0),
    PacketLoggerPacketType.RECV_ACL_DATA: (0x02, 1),
    PacketLoggerPacketType.SENT_SCO_DATA: (0x03, 0),
    PacketLoggerPacketType.RECV_SCO_DATA: (0x03, 1),
    PacketLoggerPacketType.HCI_EVENT: (0x04, 1),
}


@dataclass(frozen=True)
class PacketLoggerRecord:
    length: int
    seconds: int
    microseconds: int
    packet_type: int
    payload: bytes


def parse_packetlogger_record(data: bytes) -> PacketLoggerRecord:
    if len(data) < PACKETLOGGER_RECORD_HEADER_SIZE:
        raise ValueError(f"packet logger record too short: {len(data)} bytes")

    length = unpack(">I", data[:4])[0]
    seconds = unpack(">I", data[4:8])[0]
    microseconds = unpack(">I", data[8:12])[0]
    payload = data[PACKETLOGGER_RECORD_HEADER_SIZE:]
    return PacketLoggerRecord(
        length=length,
        seconds=seconds,
        microseconds=microseconds,
        packet_type=data[12],
        payload=payload,
    )


def packetlogger_record_to_hci_h4_phdr(record: PacketLoggerRecord) -> Optional[bytes]:
    """Build a DLT_BLUETOOTH_HCI_H4_WITH_PHDR (link-type 201) frame from a PacketLogger record.

    The frame is a 4-byte big-endian direction pseudo-header (0 = sent, 1 = received), followed by
    the HCI H4 type byte and the HCI payload. Returns None for record types that don't map to HCI.
    """
    mapping = HCI_H4_TYPE_BY_PACKET_TYPE.get(record.packet_type)
    if mapping is None:
        logger.debug("skipping unsupported PacketLogger record type: 0x%02x", record.packet_type)
        return None
    hci_h4_type, direction_in = mapping
    return pack(">I", direction_in) + bytes([hci_h4_type]) + record.payload


async def write_packetlogger_stream(out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
    async for packet in packet_generator:
        out.write(packet)
        out.flush()


async def write_pcapng_stream(
    out: BinaryIO, packet_generator: AsyncIterable[bytes], product_version: str = "", tz_offset_seconds: int = 0
) -> None:
    # The BTPacketLogger service reports record timestamps as device-local wall-clock time, whereas the pcapng
    # EnhancedPacket timestamp (with the default if_tsresol of 1e-6) is interpreted as UTC. Subtract the device's
    # UTC offset so Wireshark doesn't apply the timezone shift a second time when rendering the display time.
    shb = blocks.SectionHeader(
        options={
            "shb_hardware": "artificial",
            "shb_os": "iOS",
            "shb_userappl": "pymobiledevice3",
        }
    )
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=PCAPNG_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR,
        options={"if_description": "Bluetooth HCI", "if_os": f"iOS {product_version}"},
    )
    writer = FileWriter(out, shb)

    async for packet in packet_generator:
        try:
            record = parse_packetlogger_record(packet)
        except ValueError as e:
            logger.debug("skipping malformed PacketLogger record (%s): %r", e, packet[:32])
            continue
        frame = packetlogger_record_to_hci_h4_phdr(record)
        if frame is None:
            continue

        timestamp_microseconds = int((record.seconds - tz_offset_seconds) * 1_000_000 + record.microseconds)
        enhanced_packet = shb.new_member(blocks.EnhancedPacket)
        enhanced_packet.packet_data = frame
        enhanced_packet.timestamp_high = (timestamp_microseconds >> 32) & 0xFFFFFFFF
        enhanced_packet.timestamp_low = timestamp_microseconds & 0xFFFFFFFF
        writer.write_block(enhanced_packet)
        out.flush()


class BtPacketLoggerService(LockdownService):
    SERVICE_NAME = "com.apple.bluetooth.BTPacketLogger"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown, self.SERVICE_NAME)

    async def watch(self, packets_count: int = -1) -> AsyncGenerator[bytes, None]:
        packet_index = 0
        while packet_index != packets_count:
            packet_length = unpack("<H", await self.service.recvall(SERVICE_PACKET_SIZE_HEADER))[0]
            if packet_length == 0:
                continue
            yield await self.service.recvall(packet_length)
            packet_index += 1

    async def write_to_packetlogger(self, out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
        await write_packetlogger_stream(out, packet_generator)

    async def write_to_pcapng(self, out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
        tz_offset_seconds = self.lockdown.all_values.get("TimeZoneOffsetFromUTC") or 0
        await write_pcapng_stream(out, packet_generator, self.lockdown.product_version, tz_offset_seconds)
