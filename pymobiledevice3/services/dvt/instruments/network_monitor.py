import ipaddress
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Union

from construct import Adapter, Bytes, Int8ul, Int16ub, Int32ul, Switch, this
from construct_typed import DataclassMixin, TStruct, csfield

from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments import ChannelService


class IpAddressAdapter(Adapter):
    """Decode raw address bytes into ipaddress objects."""

    def _decode(self, obj, context, path):
        return ipaddress.ip_address(obj)


@dataclass
class AddressV6(DataclassMixin):
    """IPv6 payload for a socket address."""

    flow_info: int = csfield(Int32ul)
    address: ipaddress.IPv6Address = csfield(IpAddressAdapter(Bytes(16)))
    scope_id: int = csfield(Int32ul)


@dataclass
class AddressV4(DataclassMixin):
    """IPv4 payload for a socket address."""

    address: ipaddress.IPv4Address = csfield(IpAddressAdapter(Bytes(4)))
    _zero: bytes = csfield(Bytes(8))


@dataclass
class SocketAddress(DataclassMixin):
    """Parsed socket address with family-specific payload."""

    length: int = csfield(Int8ul)
    family: int = csfield(Int8ul)
    port: int = csfield(Int16ub)
    data: Union[AddressV4, AddressV6] = csfield(
        Switch(
            this.length,
            {
                0x1C: TStruct(AddressV6),
                0x10: TStruct(AddressV4),
            },
        )
    )


address_t = TStruct(SocketAddress)

MESSAGE_TYPE_INTERFACE_DETECTION = 0
MESSAGE_TYPE_CONNECTION_DETECTION = 1
MESSAGE_TYPE_CONNECTION_UPDATE = 2


@dataclass
class InterfaceDetectionEvent:
    """Interface detection event emitted by Instruments."""

    interface_index: int
    name: str


@dataclass
class ConnectionDetectionEvent:
    """Connection detection event emitted by Instruments."""

    local_address: SocketAddress
    remote_address: SocketAddress
    interface_index: int
    pid: int
    recv_buffer_size: int
    recv_buffer_used: int
    serial_number: int
    kind: int


@dataclass
class ConnectionUpdateEvent:
    """Connection update event emitted by Instruments."""

    rx_packets: int
    rx_bytes: int
    tx_packets: int
    tx_bytes: int
    rx_dups: int
    rx000: int
    tx_retx: int
    min_rtt: int
    avg_rtt: int
    connection_serial: int
    time: int


NetworkMonitorEvent = Union[InterfaceDetectionEvent, ConnectionDetectionEvent, ConnectionUpdateEvent]


class NetworkMonitor(ChannelService):
    """Iterate over network monitoring events from the Instruments service."""

    IDENTIFIER = "com.apple.instruments.server.services.networking"

    def __init__(self, dvt: DvtSecureSocketProxyService):
        self.logger = logging.getLogger(__name__)
        super().__init__(dvt)

    async def __aenter__(self) -> "NetworkMonitor":
        channel = await self._channel_ref()
        await channel.startMonitoring(expects_reply=False)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        channel = await self._channel_ref()
        await channel.stopMonitoring()

    async def __aiter__(self) -> AsyncIterator[NetworkMonitorEvent]:
        """Yield network events as they arrive from the service."""

        while True:
            message = await self._receive_message()

            event = None

            if message is None:
                continue

            if message[0] == MESSAGE_TYPE_INTERFACE_DETECTION:
                event = InterfaceDetectionEvent(*message[1])
            elif message[0] == MESSAGE_TYPE_CONNECTION_DETECTION:
                (
                    local_address,
                    remote_address,
                    interface_index,
                    pid,
                    recv_buffer_size,
                    recv_buffer_used,
                    serial_number,
                    kind,
                ) = message[1]
                event = ConnectionDetectionEvent(
                    local_address=address_t.parse(local_address),
                    remote_address=address_t.parse(remote_address),
                    interface_index=interface_index,
                    pid=pid,
                    recv_buffer_size=recv_buffer_size,
                    recv_buffer_used=recv_buffer_used,
                    serial_number=serial_number,
                    kind=kind,
                )
            elif message[0] == MESSAGE_TYPE_CONNECTION_UPDATE:
                event = ConnectionUpdateEvent(*message[1])
            else:
                self.logger.warning(f"unsupported event type: {message[0]}")
            yield event

    async def _receive_message(self):
        channel = await self._channel_ref()
        return await channel.receive_plist()
