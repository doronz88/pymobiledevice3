import dataclasses
import ipaddress
import logging

from construct import Adapter, Bytes, Int8ul, Int16ub, Int32ul, Struct, Switch, this


class IpAddressAdapter(Adapter):
    def _decode(self, obj, context, path):
        return ipaddress.ip_address(obj)


address_t = Struct(
    'len' / Int8ul,
    'family' / Int8ul,
    'port' / Int16ub,
    'data' / Switch(this.len, {
        0x1c: Struct(
            'flow_info' / Int32ul,
            'address' / IpAddressAdapter(Bytes(16)),
            'scope_id' / Int32ul,
        ),
        0x10: Struct(
            'address' / IpAddressAdapter(Bytes(4)),
            '_zero' / Bytes(8)
        )
    })

)

MESSAGE_TYPE_INTERFACE_DETECTION = 0
MESSAGE_TYPE_CONNECTION_DETECTION = 1
MESSAGE_TYPE_CONNECTION_UPDATE = 2


@dataclasses.dataclass
class InterfaceDetectionEvent:
    interface_index: int
    name: str


@dataclasses.dataclass
class ConnectionDetectionEvent:
    local_address: str
    remote_address: str
    interface_index: int
    pid: int
    recv_buffer_size: int
    recv_buffer_used: int
    serial_number: int
    kind: int


@dataclasses.dataclass
class ConnectionUpdateEvent:
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


class NetworkMonitor:
    IDENTIFIER = 'com.apple.instruments.server.services.networking'

    def __init__(self, dvt):
        self.logger = logging.getLogger(__name__)
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def __enter__(self):
        self._channel.startMonitoring(expects_reply=False)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._channel.stopMonitoring()

    def __iter__(self):
        while True:
            message = self._channel.receive_plist()

            event = None

            if message is None:
                continue

            if message[0] == MESSAGE_TYPE_INTERFACE_DETECTION:
                event = InterfaceDetectionEvent(*message[1])
            elif message[0] == MESSAGE_TYPE_CONNECTION_DETECTION:
                event = ConnectionDetectionEvent(*message[1])
                event.local_address = address_t.parse(event.local_address)
                event.remote_address = address_t.parse(event.remote_address)
            elif message[0] == MESSAGE_TYPE_CONNECTION_UPDATE:
                event = ConnectionUpdateEvent(*message[1])
            else:
                self.logger.warning(f'unsupported event type: {message[0]}')
            yield event
