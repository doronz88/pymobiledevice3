import abc
import plistlib
import socket
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Mapping

from construct import Struct, Prefixed, Int32ul, GreedyBytes, StreamError, Int16ul, CString, Padding, FixedSized, \
    Enum, Const, Switch, this

from pymobiledevice3.exceptions import MuxException, MuxVersionError, NotPairedError, UsbmuxConnectionError

usbmuxd_version = Enum(Int32ul,
                       BINARY=0,
                       PLIST=1,
                       )

usbmuxd_result = Enum(Int32ul,
                      OK=0,
                      BADCOMMAND=1,
                      BADDEV=2,
                      CONNREFUSED=3,
                      BADVERSION=6,
                      )

usbmuxd_msgtype = Enum(Int32ul,
                       RESULT=1,
                       CONNECT=2,
                       LISTEN=3,
                       ADD=4,
                       REMOVE=5,
                       PAIRED=6,
                       PLIST=8,
                       )

usbmuxd_header = Struct(
    'version' / usbmuxd_version,  # protocol version
    'message' / usbmuxd_msgtype,  # message type
    'tag' / Int32ul,  # responses to this query will echo back this tag
)

usbmuxd_request = Prefixed(Int32ul, Struct(
    'header' / usbmuxd_header,
    'data' / Switch(this.header.message, {
        usbmuxd_msgtype.CONNECT: Struct(
            'device_id' / Int32ul,
            'port' / Int16ul,  # TCP port number
            'reserved' / Const(0, Int16ul),
        ),
        usbmuxd_msgtype.PLIST: GreedyBytes,
    }),
), includelength=True)

usbmuxd_device_record = Struct(
    'device_id' / Int32ul,
    'product_id' / Int16ul,
    'serial_number' / FixedSized(256, CString('ascii')),
    Padding(2),
    'location' / Int32ul
)

usbmuxd_response = Prefixed(Int32ul, Struct(
    'header' / usbmuxd_header,
    'data' / Switch(this.header.message, {
        usbmuxd_msgtype.RESULT: Struct(
            'result' / usbmuxd_result,
        ),
        usbmuxd_msgtype.ADD: usbmuxd_device_record,
        usbmuxd_msgtype.REMOVE: Struct(
            'device_id' / Int32ul,
        ),
        usbmuxd_msgtype.PLIST: GreedyBytes,
    }),
), includelength=True)


@dataclass
class MuxDevice:
    devid: int
    serial: str
    connection_type: str

    def connect(self, port) -> socket.socket:
        return create_mux().connect(self, port)

    @property
    def is_usb(self) -> bool:
        return self.connection_type == 'USB'

    @property
    def is_network(self) -> bool:
        return self.connection_type == 'Network'

    def matches_udid(self, udid: str) -> bool:
        return self.serial.replace('-', '') == udid.replace('-', '')


class SafeStreamSocket:
    """ wrapper to native python socket object to be used with construct as a stream """

    def __init__(self, address, family):
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.connect(address)

    def send(self, msg: bytes) -> int:
        self.sock.sendall(msg)
        return len(msg)

    def recv(self, size: int) -> bytes:
        msg = b''
        while len(msg) < size:
            chunk = self.sock.recv(size - len(msg))
            if not chunk:
                raise MuxException('socket connection broken')
            msg += chunk
        return msg

    def close(self):
        self.sock.close()

    def settimeout(self, interval: float):
        self.sock.settimeout(interval)

    def setblocking(self, blocking: bool):
        self.sock.setblocking(blocking)

    read = recv
    write = send


class MuxConnection:
    # used on Windows
    ITUNES_HOST = ('127.0.0.1', 27015)

    # used for macOS and Linux
    USBMUXD_PIPE = '/var/run/usbmuxd'

    @staticmethod
    def create_usbmux_socket() -> SafeStreamSocket:
        try:
            if sys.platform in ['win32', 'cygwin']:
                return SafeStreamSocket(MuxConnection.ITUNES_HOST, socket.AF_INET)
            else:
                return SafeStreamSocket(MuxConnection.USBMUXD_PIPE, socket.AF_UNIX)
        except ConnectionRefusedError as e:
            raise UsbmuxConnectionError from e

    @staticmethod
    def create():
        # first attempt to connect with possibly the wrong version header (plist protocol)
        sock = MuxConnection.create_usbmux_socket()
        message = usbmuxd_request.build({
            'header': {'version': usbmuxd_version.PLIST, 'message': usbmuxd_msgtype.LISTEN, 'tag': 1},
            'data': b''
        })
        sock.send(message)
        response = usbmuxd_response.parse_stream(sock)

        # if we sent a bad request, we should re-create the socket in the correct version this time
        sock.close()
        sock = MuxConnection.create_usbmux_socket()

        if response.header.message != usbmuxd_msgtype.PLIST:
            return BinaryMuxConnection(sock)
        else:
            return PlistMuxConnection(sock)

    def __init__(self, sock: SafeStreamSocket):
        self._sock = sock

        # after initiating the "Connect" packet, this same socket will be used to transfer data into the service
        # residing inside the target device. when this happens, we can no longer send/receive control commands to
        # usbmux on same socket
        self._connected = False

        # message sequence number. used when verifying the response matched the request
        self._tag = 1

        self.devices = []

    @abc.abstractmethod
    def _connect(self, device_id: int, port: int):
        """ initiate a "Connect" request to target port """
        pass

    @abc.abstractmethod
    def get_device_list(self, timeout: float = None):
        """
        request an update to current device list
        """
        pass

    def connect(self, device: MuxDevice, port: int) -> socket.socket:
        """ connect to a relay port on target machine and get a raw python socket object for the connection """
        self._connect(device.devid, socket.htons(port))
        self._connected = True
        return self._sock.sock

    def close(self):
        """ close current socket """
        self._sock.close()

    def _assert_not_connected(self):
        """ verify active state is in state for control messages """
        if self._connected:
            raise MuxException('Mux is connected, cannot issue control packets')


class BinaryMuxConnection(MuxConnection):
    """ old binary protocol """

    def __init__(self, sock: SafeStreamSocket):
        super().__init__(sock)
        self._version = usbmuxd_version.BINARY

    def get_device_list(self, timeout: float = None):
        """ use timeout to wait for the device list to be fully populated """
        self._assert_not_connected()
        end = time.time() + timeout
        self.listen()
        while time.time() < end:
            self._sock.settimeout(end - time.time())
            try:
                self._receive_device_state_update()
            except (BlockingIOError, StreamError):
                continue
            except IOError:
                try:
                    self._sock.setblocking(True)
                    self.close()
                except OSError:
                    pass
                raise MuxException('Exception in listener socket')

    def listen(self):
        """ start listening for events of attached and detached devices """
        self._send_receive(usbmuxd_msgtype.LISTEN)

    def _connect(self, device_id: int, port: int):
        self._send({'header': {'version': self._version,
                               'message': usbmuxd_msgtype.CONNECT,
                               'tag': self._tag},
                    'data': {'device_id': device_id, 'port': port},
                    })
        response = self._receive()
        if response.header.message != usbmuxd_msgtype.RESULT:
            raise MuxException(f'unexpected message type received: {response}')

        if response.data.result != usbmuxd_result.OK:
            raise MuxException(f'failed to connect to device: {device_id} at port: {port}. reason: '
                               f'{response.data.result}')

    def _send(self, data: Mapping):
        self._assert_not_connected()
        self._sock.send(usbmuxd_request.build(data))
        self._tag += 1

    def _receive(self, expected_tag: int = None):
        self._assert_not_connected()
        response = usbmuxd_response.parse_stream(self._sock)
        if expected_tag and response.header.tag != expected_tag:
            raise MuxException(f'Reply tag mismatch: expected {expected_tag}, got {response.header.tag}')
        return response

    def _send_receive(self, message_type: int):
        self._send({'header': {'version': self._version, 'message': message_type, 'tag': self._tag},
                    'data': b''})
        response = self._receive(self._tag - 1)
        if response.header.message != usbmuxd_msgtype.RESULT:
            raise MuxException(f'unexpected message type received: {response}')

        result = response.data.result
        if result != usbmuxd_result.OK:
            raise MuxException(f'{message_type} failed: error {result}')

    def _add_device(self, device: MuxDevice):
        self.devices.append(device)

    def _remove_device(self, device_id: int):
        self.devices = [device for device in self.devices if device.devid != device_id]

    def _receive_device_state_update(self):
        response = self._receive()
        if response.header.message == usbmuxd_msgtype.ADD:
            # old protocol only supported USB devices
            self._add_device(MuxDevice(response.data.device_id, response.data.serial_number, 'USB'))
        elif response.header.message == usbmuxd_msgtype.REMOVE:
            self._remove_device(response.data.device_id)
        else:
            raise MuxException(f'Invalid packet type received: {response}')


class PlistMuxConnection(BinaryMuxConnection):
    def __init__(self, sock: SafeStreamSocket):
        super().__init__(sock)
        self._version = usbmuxd_version.PLIST

    def listen(self):
        self._send_receive({'MessageType': 'Listen'})

    def get_pair_record(self, serial: str) -> Mapping:
        self._send({'MessageType': 'ReadPairRecord', 'PairRecordID': serial})
        response = self._receive(self._tag - 1)
        pair_record = response.get('PairRecordData')
        if pair_record is None:
            raise NotPairedError('device should be paired first')
        return plistlib.loads(pair_record)

    def get_device_list(self, timeout: float = None):
        """ get device list synchronously without waiting the timeout """
        self.devices = []
        self._send({'MessageType': 'ListDevices'})
        for response in self._receive(self._tag - 1)['DeviceList']:
            if response['MessageType'] == 'Attached':
                super()._add_device(MuxDevice(response['DeviceID'], response['Properties']['SerialNumber'],
                                              response['Properties']['ConnectionType']))
            elif response['MessageType'] == 'Detached':
                super()._remove_device(response['DeviceID'])
            else:
                raise MuxException(f'Invalid packet type received: {response}')

    def get_buid(self) -> str:
        """ get SystemBUID """
        self._send({'MessageType': 'ReadBUID'})
        return self._receive(self._tag - 1)['BUID']

    def save_pair_record(self, serial: str, device_id: int, record_data: bytes):
        self._send_receive({'MessageType': 'SavePairRecord',
                            'PairRecordID': serial,
                            'PairRecordData': record_data,
                            'DeviceID': device_id})

    def _connect(self, device_id: int, port: int):
        self._send_receive({'MessageType': 'Connect', 'DeviceID': device_id, 'PortNumber': port})

    def _send(self, data: Mapping):
        request = {'ClientVersionString': 'qt4i-usbmuxd', 'ProgName': 'pymobiledevice3', 'kLibUSBMuxVersion': 3}
        request.update(data)
        super()._send({'header': {'version': self._version,
                                  'message': usbmuxd_msgtype.PLIST,
                                  'tag': self._tag},
                       'data': plistlib.dumps(request),
                       })

    def _receive(self, expected_tag: int = None) -> Mapping:
        response = super()._receive(expected_tag=expected_tag)
        if response.header.message != usbmuxd_msgtype.PLIST:
            raise MuxException(f'Received non-plist type {response}')
        return plistlib.loads(response.data)

    def _send_receive(self, data: Mapping):
        self._send(data)
        response = self._receive(self._tag - 1)
        if response['MessageType'] != 'Result':
            raise MuxException(f'got an invalid message: {response}')
        if response['Number'] != 0:
            raise MuxException(f'got an error message: {response}')


def create_mux() -> MuxConnection:
    return MuxConnection.create()


def list_devices() -> List[MuxDevice]:
    mux = create_mux()
    mux.get_device_list(0.1)
    devices = mux.devices
    mux.close()
    return devices


def select_device(udid: str = None, connection_type: str = None) -> Optional[MuxDevice]:
    """
    select a UsbMux device according to given arguments.
    if more than one device could be selected, always prefer the usb one.
    """
    tmp = None
    for device in list_devices():
        if connection_type is not None and device.connection_type != connection_type:
            # if a specific connection_type was desired and not of this one then skip
            continue

        if udid is not None and not device.matches_udid(udid):
            # if a specific udid was desired and not of this one then skip
            continue

        # save best result as a temporary
        tmp = device

        if device.is_usb:
            # always prefer usb connection
            return device

    return tmp
