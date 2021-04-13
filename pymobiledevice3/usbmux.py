#!/usr/bin/python
import plistlib
import select
import socket
import struct
import sys


class MuxError(Exception):
    pass


class MuxVersionError(MuxError):
    pass


class SafeStreamSocket:
    def __init__(self, address, family):
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.connect(address)

    def send(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise MuxError("socket connection broken")
            totalsent = totalsent + sent

    def recv(self, size):
        msg = b''
        while len(msg) < size:
            chunk = self.sock.recv(size - len(msg))
            empty_chunk = b''
            if chunk == empty_chunk:
                raise MuxError("socket connection broken")
            msg = msg + chunk
        return msg


class MuxDevice(object):
    def __init__(self, devid, usbprod, serial, location):
        self.devid = devid
        self.usbprod = usbprod
        self.serial = serial
        self.location = location

    def __str__(self):
        return "<MuxDevice: ID %d ProdID 0x%04x Serial '%s' Location 0x%x>" % (
            self.devid, self.usbprod, self.serial, self.location)


class BinaryProtocol(object):
    TYPE_RESULT = 1
    TYPE_CONNECT = 2
    TYPE_LISTEN = 3
    TYPE_DEVICE_ADD = 4
    TYPE_DEVICE_REMOVE = 5
    VERSION = 0

    def __init__(self, socket):
        self.socket = socket
        self.connected = False

    def _pack(self, req, payload):
        if req == self.TYPE_CONNECT:
            connect_data = b"\x00\x00"
            return struct.pack("IH", payload['DeviceID'], payload['PortNumber']) + connect_data
        elif req == self.TYPE_LISTEN:
            return b""
        else:
            raise ValueError("Invalid outgoing request type %d" % req)

    def _unpack(self, resp, payload):
        if resp == self.TYPE_RESULT:
            return {'Number': struct.unpack("I", payload)[0]}
        elif resp == self.TYPE_DEVICE_ADD:
            devid, usbpid, serial, pad, location = struct.unpack("IH256sHI", payload)
            serial = serial.split(b"\0")[0]
            return {'DeviceID': devid,
                    'Properties': {'LocationID': location, 'SerialNumber': serial, 'ProductID': usbpid}}
        elif resp == self.TYPE_DEVICE_REMOVE:
            devid = struct.unpack("I", payload)[0]
            return {'DeviceID': devid}
        else:
            raise MuxError("Invalid incoming response type %d" % resp)

    def send_packet(self, req, tag, payload=None):
        if payload is None:
            payload = {}
        payload = self._pack(req, payload)
        if self.connected:
            raise MuxError("Mux is connected, cannot issue control packets")
        length = 16 + len(payload)
        data = struct.pack("IIII", length, self.VERSION, req, tag) + payload
        self.socket.send(data)

    def get_packet(self):
        if self.connected:
            raise MuxError("Mux is connected, cannot issue control packets")
        dlen = self.socket.recv(4)
        dlen = struct.unpack("I", dlen)[0]
        body = self.socket.recv(dlen - 4)
        version, resp, tag = struct.unpack("III", body[:0xc])
        if version != self.VERSION:
            raise MuxVersionError("Version mismatch: expected %d, got %d" % (self.VERSION, version))
        payload = self._unpack(resp, body[0xc:])
        return (resp, tag, payload)


class PlistProtocol(BinaryProtocol):
    TYPE_RESULT = "Result"
    TYPE_CONNECT = "Connect"
    TYPE_LISTEN = "Listen"
    TYPE_DEVICE_ADD = "Attached"
    TYPE_DEVICE_REMOVE = "Detached"  # ???
    TYPE_PLIST = 8
    VERSION = 1

    def __init__(self, socket):
        BinaryProtocol.__init__(self, socket)

    def _pack(self, req, payload):
        return payload

    def _unpack(self, resp, payload):
        return payload

    def send_packet(self, req, tag, payload=None):
        if payload is None:
            payload = {}
        payload['ClientVersionString'] = 'qt4i-usbmuxd'
        if isinstance(req, int):
            req = [self.TYPE_CONNECT, self.TYPE_LISTEN][req - 2]
        payload['MessageType'] = req
        payload['ProgName'] = 'tcprelay'
        wrapped_payload = plistlib.dumps(payload)
        BinaryProtocol.send_packet(self, self.TYPE_PLIST, tag, wrapped_payload)

    def get_packet(self):
        resp, tag, payload = BinaryProtocol.get_packet(self)
        if resp != self.TYPE_PLIST:
            raise MuxError("Received non-plist type %d" % resp)
        payload = plistlib.loads(payload)
        return payload.get('MessageType', ''), tag, payload


class MuxConnection(object):
    def __init__(self, socketpath, protoclass):
        self.socketpath = socketpath
        if sys.platform in ['win32', 'cygwin']:
            family = socket.AF_INET
            address = ('127.0.0.1', 27015)
        else:
            family = socket.AF_UNIX
            address = self.socketpath
        self.socket = SafeStreamSocket(address, family)
        self.proto = protoclass(self.socket)
        self.pkttag = 1
        self.devices = []

    def _getreply(self):
        while True:
            resp, tag, data = self.proto.get_packet()
            if resp == self.proto.TYPE_RESULT:
                return tag, data
            else:
                raise MuxError("Invalid packet type received: %d" % resp)

    def _processpacket(self):
        resp, tag, data = self.proto.get_packet()
        if resp == self.proto.TYPE_DEVICE_ADD:
            self.devices.append(
                MuxDevice(data['DeviceID'], data['Properties']['ProductID'], data['Properties']['SerialNumber'],
                          data['Properties']['LocationID']))
        elif resp == self.proto.TYPE_DEVICE_REMOVE:
            for dev in self.devices:
                if dev.devid == data['DeviceID']:
                    self.devices.remove(dev)
        elif resp == self.proto.TYPE_RESULT:
            raise MuxError("Unexpected result: %d" % resp)
        else:
            raise MuxError("Invalid packet type received: %d" % resp)

    def _exchange(self, req, payload=None):
        if payload is None:
            payload = {}
        mytag = self.pkttag
        self.pkttag += 1
        self.proto.send_packet(req, mytag, payload)
        recvtag, data = self._getreply()
        if recvtag != mytag:
            raise MuxError("Reply tag mismatch: expected %d, got %d" % (mytag, recvtag))
        return data['Number']

    def listen(self):
        ret = self._exchange(self.proto.TYPE_LISTEN)
        if ret != 0:
            raise MuxError("Listen failed: error %d" % ret)

    def process(self, timeout=None):
        if self.proto.connected:
            raise MuxError("Socket is connected, cannot process listener events")
        rlo, wlo, xlo = select.select([self.socket.sock], [], [self.socket.sock], timeout)
        if xlo:
            self.socket.sock.close()
            raise MuxError("Exception in listener socket")
        if rlo:
            self._processpacket()

    def connect(self, device, port):
        ret = self._exchange(self.proto.TYPE_CONNECT,
                             {'DeviceID': device.devid, 'PortNumber': ((port << 8) & 0xFF00) | (port >> 8)})
        if ret != 0:
            raise MuxError("Connect failed: error %d" % ret)
        self.proto.connected = True
        return self.socket.sock

    def close(self):
        self.socket.sock.close()


class USBMux(object):
    def __init__(self, socket_path=None):
        if socket_path is None:
            if sys.platform == 'darwin':
                socket_path = '/var/run/usbmuxd'
            else:
                socket_path = '/var/run/usbmuxd'
        self.socket_path = socket_path
        self.listener = MuxConnection(socket_path, BinaryProtocol)
        try:
            self.listener.listen()
            self.version = 0
            self.protoclass = BinaryProtocol
        except MuxVersionError:
            self.listener = MuxConnection(socket_path, PlistProtocol)
            self.listener.listen()
            self.protoclass = PlistProtocol
            self.version = 1
        self.devices = self.listener.devices

    def process(self, timeout=10.0):
        self.listener.process(timeout)

    def connect(self, device, port):
        connector = MuxConnection(self.socket_path, self.protoclass)
        return connector.connect(device, port)


class UsbmuxdClient(MuxConnection):
    def __init__(self):
        super(UsbmuxdClient, self).__init__("/var/run/usbmuxd", PlistProtocol)

    def get_pair_record(self, udid):
        tag = self.pkttag
        self.pkttag += 1
        payload = {"PairRecordID": udid}
        self.proto.send_packet("ReadPairRecord", tag, payload)
        _, recvtag, data = self.proto.get_packet()
        if recvtag != tag:
            raise MuxError("Reply tag mismatch: expected %d, got %d" % (tag, recvtag))
        pair_record = data['PairRecordData']
        pair_record = plistlib.loads(pair_record)
        return pair_record


if __name__ == "__main__":
    mux = USBMux()
    print("Waiting for devices...")
    if not mux.devices:
        mux.process(0.1)
    while True:
        for dev in mux.devices:
            print("Device:", dev)
        mux.process()
