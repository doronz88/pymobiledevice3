import plistlib
import socket
import struct
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from construct import Struct, Prefixed, Int32ul, GreedyBytes, StreamError, Int16ul, CString, Padding, FixedSized

from pymobiledevice3.exceptions import MuxException, MuxVersionError, NotPairedError


class PacketType(Enum):
    Result = 1
    Connect = 2
    Listen = 3
    Attached = 4
    Detached = 5
    Plist = 8


class SafeStreamSocket:
    def __init__(self, address, family):
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.connect(address)

    def send(self, msg):
        self.sock.sendall(msg)
        return len(msg)

    def recv(self, size):
        msg = b''
        while len(msg) < size:
            chunk = self.sock.recv(size - len(msg))
            if not chunk:
                raise MuxException('socket connection broken')
            msg += chunk
        return msg

    def close(self):
        self.sock.close()

    read = recv
    write = send


packet_struct = Prefixed(Int32ul, Struct(
    'version' / Int32ul,
    'type_' / Int32ul,
    'tag' / Int32ul,
    'payload' / GreedyBytes,
), includelength=True)

device_struct = Struct(
    'devid' / Int32ul,
    'usbpid' / Int16ul,
    'serial' / FixedSized(256, CString('ascii')),
    Padding(2),
    'location' / Int32ul
)


class BinaryProtocol:
    VERSION = 0

    def __init__(self, sock):
        self.socket = sock
        self.connected = False
        self.tag = 1

    @staticmethod
    def get_version(sock):
        packet_struct.build_stream(
            dict(version=BinaryProtocol.VERSION, type_=PacketType.Listen.value, tag=1, payload=b''), sock)
        return packet_struct.parse_stream(sock).version

    def parse_result(self, payload):
        return Int32ul.parse(payload)

    def connect(self, device_id, port):
        payload = struct.pack('IH', device_id, port) + b'\x00\x00'
        self.send_and_validate(PacketType.Connect, payload)

    def listen(self):
        self.send_and_validate(PacketType.Listen)

    def send(self, req, payload=None):
        if self.connected:
            raise MuxException('Mux is connected, cannot issue control packets')
        if payload is None:
            payload = b''
        packet_struct.build_stream(dict(version=self.VERSION, type_=req.value, tag=self.tag, payload=payload),
                                   self.socket)
        self.tag += 1

    def recv(self):
        if self.connected:
            raise MuxException('Mux is connected, cannot issue control packets')
        data = packet_struct.parse_stream(self.socket)
        if data.version != self.VERSION:
            raise MuxVersionError('Version mismatch: expected %d, got %d' % (self.VERSION, data.version))
        return PacketType(data.type_), data.tag, data.payload

    def send_and_validate(self, req, payload=None):
        self.send(req, payload)
        type_, tag, payload = self.recv()
        if type_ != PacketType.Result:
            raise MuxException('Invalid packet type received')
        if tag != self.tag - 1:
            raise MuxException('Reply tag mismatch: expected %d, got %d' % (self.tag - 1, tag))
        ret = self.parse_result(payload)
        if ret != 0:
            raise MuxException(f'{req.name} failed: error {ret}')

    def recv_device_state(self):
        type_, tag, payload = self.recv()
        if type_ == PacketType.Attached:
            device = device_struct.parse(payload)
            return type_, MuxDevice(device.devid, device.usbpid, device.serial, device.location)
        elif type_ == PacketType.Detached:
            devid = Int32ul.parse(payload)
            return type_, devid
        else:
            raise MuxException('Invalid packet type received: %d' % type_)

    def close(self):
        self.socket.sock.close()


class PlistProtocol(BinaryProtocol):
    VERSION = 1

    def connect(self, device_id, port):
        self.send_and_validate(PacketType.Connect, {'DeviceID': device_id, 'PortNumber': port})

    def send(self, request, payload=None):
        if isinstance(request, PacketType):
            request = request.name
        if payload is None:
            payload = {}
        payload.update({'ClientVersionString': 'qt4i-usbmuxd', 'MessageType': request, 'ProgName': 'tcprelay'})
        super().send(PacketType.Plist, plistlib.dumps(payload))

    def recv(self):
        resp, tag, payload = super().recv()
        if resp != PacketType.Plist:
            raise MuxException('Received non-plist type %d' % resp)
        payload = plistlib.loads(payload)
        type_ = payload.get('MessageType')
        if type_ is not None:
            type_ = PacketType[type_]
        return type_, tag, payload

    def parse_result(self, payload):
        return payload['Number']

    def recv_device_state(self):
        type_, tag, payload = self.recv()
        if type_ == PacketType.Attached:
            return type_, MuxDevice(payload['DeviceID'], payload['Properties']['ProductID'],
                                    payload['Properties']['SerialNumber'],
                                    payload['Properties']['LocationID'])
        elif type_ == PacketType.Detached:
            return type_, payload['DeviceID']
        else:
            raise MuxException('Invalid packet type received: %d' % type_)

    def get_pair_record(self, udid):
        self.send('ReadPairRecord', {'PairRecordID': udid})
        type_, tag, payload = self.recv()
        if tag != self.tag - 1:
            raise MuxException('Reply tag mismatch: expected %d, got %d' % (self.tag - 1, tag))
        pair_record = payload.get('PairRecordData')
        if pair_record is None:
            raise NotPairedError('device should be paired first')
        pair_record = plistlib.loads(pair_record)
        return pair_record

    def save_pair_record(self, udid, device_id, data):
        self.send_and_validate('SavePairRecord', {'PairRecordID': udid, 'PairRecordData': data, 'DeviceID': device_id})


class MuxConnection(object):
    ITUNES_HOST = ('127.0.0.1', 27015)
    USBMUXD_PIPE = '/var/run/usbmuxd'

    def __init__(self, protoclass):
        self.socket = self.create_socket()
        self.proto = protoclass(self.socket)
        self.devices = []

    @staticmethod
    def create_socket():
        if sys.platform in ['win32', 'cygwin']:
            return SafeStreamSocket(MuxConnection.ITUNES_HOST, socket.AF_INET)
        else:
            return SafeStreamSocket(MuxConnection.USBMUXD_PIPE, socket.AF_UNIX)

    def listen_for_devices(self, timeout=None):
        if self.proto.connected:
            raise MuxException('Socket is connected, cannot process listener events')
        end = time.time() + timeout
        self.proto.listen()
        while time.time() < end:
            self.socket.sock.settimeout(end - time.time())
            try:
                type_, data = self.proto.recv_device_state()
                if type_ == PacketType.Attached and data.is_legal:
                    self.devices.append(data)
                elif type_ == PacketType.Detached:
                    self.devices = [device for device in self.devices if device.devid != data]
            except (BlockingIOError, StreamError):
                continue
            except IOError:
                self.socket.sock.setblocking(True)
                self.proto.close()
                raise MuxException('Exception in listener socket')

    def connect(self, device, port):
        self.proto.connect(device.devid, ((port << 8) & 0xFF00) | (port >> 8))
        self.proto.connected = True
        return self.socket.sock

    def close(self):
        self.proto.close()


def create_mux() -> MuxConnection:
    safe_sock = MuxConnection.create_socket()
    version = BinaryProtocol.get_version(safe_sock)
    safe_sock.close()

    if version == BinaryProtocol.VERSION:
        return MuxConnection(BinaryProtocol)
    elif version == PlistProtocol.VERSION:
        return MuxConnection(PlistProtocol)


@dataclass
class MuxDevice:
    devid: int
    usbprod: int
    serial: str
    location: int

    def connect(self, port) -> socket.socket:
        return create_mux().connect(self, port)

    @property
    def is_legal(self):
        return bool(self.usbprod)

    def matches_udid(self, udid):
        return self.serial.replace('-', '') == udid.replace('-', '')


def list_devices() -> List[MuxDevice]:
    mux = create_mux()
    mux.listen_for_devices(0.1)
    devices = mux.devices
    mux.close()
    return devices


def select_device(udid='') -> Optional[MuxDevice]:
    matching_devices = [
        device for device in list_devices()
        if device.is_legal and (not udid or device.matches_udid(udid))
    ]
    if not matching_devices:
        return None
    return matching_devices[0]
