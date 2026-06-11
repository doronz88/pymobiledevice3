import logging
from collections.abc import AsyncGenerator, AsyncIterable
from dataclasses import dataclass
from enum import IntEnum
from struct import pack, unpack
from typing import BinaryIO, Optional

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

PACKETLOGGER_RECORD_HEADER_SIZE = 13
SERVICE_PACKET_SIZE_HEADER = 2
PCAP_SNAPLEN = 2048
PCAP_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
PCAP_GLOBAL_HEADER = b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\xc9"
logger = logging.getLogger(__name__)


class PacketLoggerPacketType(IntEnum):
    HCI_COMMAND = 0x00
    HCI_EVENT = 0x01
    SENT_ACL_DATA = 0x02
    RECV_ACL_DATA = 0x03
    SENT_SCO_DATA = 0x08
    RECV_SCO_DATA = 0x09


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


def packetlogger_to_pcap_record(data: bytes) -> Optional[bytes]:
    try:
        record = parse_packetlogger_record(data)
    except ValueError as e:
        logger.debug("skipping malformed PacketLogger record (%s): %r", e, data[:32])
        return None
    direction_in: int
    hci_h4_type: int

    if record.packet_type == PacketLoggerPacketType.HCI_COMMAND:
        hci_h4_type = 0x01
        direction_in = 0
    elif record.packet_type == PacketLoggerPacketType.SENT_ACL_DATA:
        hci_h4_type = 0x02
        direction_in = 0
    elif record.packet_type == PacketLoggerPacketType.RECV_ACL_DATA:
        hci_h4_type = 0x02
        direction_in = 1
    elif record.packet_type == PacketLoggerPacketType.SENT_SCO_DATA:
        hci_h4_type = 0x03
        direction_in = 0
    elif record.packet_type == PacketLoggerPacketType.RECV_SCO_DATA:
        hci_h4_type = 0x03
        direction_in = 1
    elif record.packet_type == PacketLoggerPacketType.HCI_EVENT:
        hci_h4_type = 0x04
        direction_in = 1
    else:
        logger.debug("skipping unsupported PacketLogger record type: 0x%02x", record.packet_type)
        return None

    captured_length = 4 + 1 + len(record.payload)
    return (
        pack(">IIIII", record.seconds, record.microseconds, captured_length, captured_length, direction_in)
        + bytes([hci_h4_type])
        + record.payload
    )


async def write_packetlogger_stream(out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
    async for packet in packet_generator:
        out.write(packet)
    out.flush()


async def write_pcap_stream(out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
    out.write(PCAP_GLOBAL_HEADER)
    async for packet in packet_generator:
        pcap_record = packetlogger_to_pcap_record(packet)
        if pcap_record is None:
            continue
        out.write(pcap_record)
    out.flush()


class BtPacketLoggerService(LockdownService):
    SERVICE_NAME = "com.apple.bluetooth.BTPacketLogger"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown, self.SERVICE_NAME)

    async def watch(self, packets_count: int = -1) -> AsyncGenerator[bytes, None]:
        packet_index = 0
        while packet_index != packets_count:
            packet_length = unpack(">H", await self.service.recvall(SERVICE_PACKET_SIZE_HEADER))[0]
            if packet_length == 0:
                continue
            yield await self.service.recvall(packet_length)
            packet_index += 1

    async def write_to_packetlogger(self, out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
        await write_packetlogger_stream(out, packet_generator)

    async def write_to_pcap(self, out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
        await write_pcap_stream(out, packet_generator)
