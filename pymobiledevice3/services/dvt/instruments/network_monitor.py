import ipaddress
import logging
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Optional, Union, cast

from bytestruct import BinaryStruct, ByteReader, Bytes, BytesLike, ipv4, ipv6, u8, u16, u32

from pymobiledevice3.dtx import DTXContext, DTXQueue, DTXService, dtx_method, dtx_on_dispatch, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider


@dataclass
class AddressV6(BinaryStruct, byte_order="<"):
    """IPv6 payload for a socket address."""

    flow_info: u32
    address: ipv6
    scope_id: u32


@dataclass
class AddressV4(BinaryStruct, byte_order="<"):
    """IPv4 payload for a socket address."""

    address: ipv4
    _zero: Annotated[bytes, Bytes(8)]


@dataclass
class SocketAddress(BinaryStruct, byte_order=">"):
    """Parsed socket address with family-specific payload."""

    length: u8
    family: u8
    port: u16
    #: ``None`` when ``length`` is neither that of a ``sockaddr_in`` nor of a ``sockaddr_in6``.
    data: Optional[Union[AddressV4, AddressV6]] = None

    @property
    def address(self) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """The IP address, or ``None`` for an address family without a payload decoder."""
        return None if self.data is None else self.data.address

    @classmethod
    def parse(cls, data: BytesLike) -> "SocketAddress":
        """Parse a raw ``sockaddr`` (big-endian port, little-endian IPv6 flow info / scope id)."""
        reader = ByteReader(data)
        address = cls.read(reader)
        if address.length == 0x1C:
            address.data = AddressV6.read(reader)
        elif address.length == 0x10:
            address.data = AddressV4.read(reader)
        return address


MESSAGE_TYPE_INTERFACE_DETECTION = 0
MESSAGE_TYPE_CONNECTION_DETECTION = 1
MESSAGE_TYPE_CONNECTION_UPDATE = 2


@dataclass
class InterfaceDetectionEvent:
    """A network interface discovered by the monitor, identified by its index and name."""

    interface_index: int
    name: str


@dataclass
class ConnectionDetectionEvent:
    """A newly detected socket connection with its endpoints, owning process and buffer state."""

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
    """Periodic traffic statistics for a previously detected connection, keyed by `connection_serial`."""

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


class NetworkMonitorService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.networking"

    def __init__(self, ctx: DTXContext) -> None:
        super().__init__(ctx)
        self.events: DTXQueue[Any] = DTXQueue()

    def on_closed(self, reason: str = "") -> None:
        self.shutdown_queue(self.events)
        super().on_closed(reason)

    @dtx_method("startMonitoring", expects_reply=False)
    async def start_monitoring(self) -> None: ...

    @dtx_method("stopMonitoring")
    async def stop_monitoring(self) -> None: ...

    @dtx_on_dispatch
    async def _on_dispatch(self, selector: str, *args: Any) -> None:
        await self.events.put((selector, list(args)))

    @dtx_on_notification
    async def _on_notification(self, payload: Any) -> None:
        await self.events.put(payload)


class NetworkMonitor(DtxService[NetworkMonitorService]):
    """
    Monitor device network activity over the Instruments networking channel.

    Constructed with a `DvtProvider`. Use as an async context manager: entering starts
    monitoring and exiting stops it. The object is async-iterable, yielding decoded
    `InterfaceDetectionEvent`, `ConnectionDetectionEvent` and `ConnectionUpdateEvent`
    instances as they arrive.
    """

    def __init__(self, dvt: DtxServiceProvider):
        super().__init__(dvt)
        self.logger = logging.getLogger(__name__)

    async def __aenter__(self) -> "NetworkMonitor":
        await self.connect()
        await self.service.start_monitoring()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.service.stop_monitoring()

    async def __aiter__(self) -> AsyncIterator[Optional[NetworkMonitorEvent]]:
        """
        Decode and yield network events as they arrive from the service.

        Each raw message is dispatched by its leading message-type code. Socket addresses on
        connection-detection events are parsed into `SocketAddress` structures. Unrecognized
        or malformed payloads are logged and skipped (no event is yielded for them).

        :yields: The decoded event, or `None` when a known message type carried no payload.
        """
        while True:
            message = await self._receive_message()

            event = None

            if message is None:
                continue
            if not isinstance(message, (list, tuple)) or len(cast(Sequence[Any], message)) < 2:
                self.logger.warning(f"unsupported event payload: {message!r}")
                continue

            if message[0] == MESSAGE_TYPE_INTERFACE_DETECTION:
                event = InterfaceDetectionEvent(*cast(tuple[Any, ...], message[1]))
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
                ) = cast(tuple[Any, ...], message[1])
                event = ConnectionDetectionEvent(
                    local_address=SocketAddress.parse(local_address),
                    remote_address=SocketAddress.parse(remote_address),
                    interface_index=interface_index,
                    pid=pid,
                    recv_buffer_size=recv_buffer_size,
                    recv_buffer_used=recv_buffer_used,
                    serial_number=serial_number,
                    kind=kind,
                )
            elif message[0] == MESSAGE_TYPE_CONNECTION_UPDATE:
                event = ConnectionUpdateEvent(*cast(tuple[Any, ...], message[1]))
            else:
                self.logger.warning(f"unsupported event type: {message[0]}")
            yield event

    async def _receive_message(self):
        return await self.service.events.get()
