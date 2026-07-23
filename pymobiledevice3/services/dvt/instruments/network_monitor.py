import ipaddress
import logging
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Union, cast

from construct import Adapter, Bytes, Int8ul, Int16ub, Int32ul, Switch, this
from construct_typed import DataclassMixin, TStruct, csfield

from pymobiledevice3.dtx import DTXContext, DTXQueue, DTXService, dtx_method, dtx_on_dispatch, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider

if TYPE_CHECKING:
    # ``construct.Adapter`` is generic in its type stubs but not subscriptable at runtime.
    _IpAddressAdapterBase = Adapter[bytes, bytes, Any, Any]
else:
    _IpAddressAdapterBase = Adapter


class IpAddressAdapter(_IpAddressAdapterBase):
    """Decode raw address bytes into ipaddress objects."""

    def _decode(self, obj: bytes, context: Any, path: str):
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
                event = ConnectionUpdateEvent(*cast(tuple[Any, ...], message[1]))
            else:
                self.logger.warning(f"unsupported event type: {message[0]}")
            yield event

    async def _receive_message(self):
        return await self.service.events.get()
