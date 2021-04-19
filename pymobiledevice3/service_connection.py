from re import sub
import plistlib
import logging
import struct
import ssl

import IPython
from pygments import highlight, lexers, formatters

from pymobiledevice3 import usbmux


class ConnectionFailedException(Exception):
    pass


SHELL_USAGE = """
# This shell allows you to communicate directly with every service layer behind the lockdownd daemon.

# For example, you can do the following:
client.send_plist({"Command": "DoSomething"})

# and view the reply
print(client.recv_plist())

# or just send raw message
client.send(b"hello")

# and view the result
print(client.recv_exact(20))
"""


class ServiceConnection(object):
    def __init__(self, socket):
        self.logger = logging.getLogger(__name__)
        self.socket = socket

    @staticmethod
    def create(udid, port):
        mux = usbmux.USBMux()
        mux.process()
        target_device = None

        while target_device is None:
            mux.process()
            for connected_device in mux.devices:
                if connected_device.serial == udid:
                    target_device = connected_device
                    break

        try:
            socket = mux.connect(target_device, port)
        except usbmux.MuxError:
            raise ConnectionFailedException(f'Connection to device port {port} failed')

        return ServiceConnection(socket)

    def setblocking(self, blocking: bool):
        self.socket.setblocking(blocking)

    def close(self):
        self.socket.close()

    def recv(self, length=4096):
        data = self.socket.recv(length)
        return data

    def send(self, data):
        self.socket.sendall(data)

    def send_request(self, data):
        self.send_plist(data)
        return self.recv_plist()

    def recv_exact(self, size):
        data = b""
        while size > 0:
            d = self.recv(size)
            if not d or len(d) == 0:
                break
            data += d
            size -= len(d)
        return data

    def recv_raw(self):
        response = self.recv_exact(4)
        if not response or len(response) != 4:
            return
        response = struct.unpack(">L", response)[0]
        return self.recv_exact(response)

    def send_raw(self, data):
        if isinstance(data, str):
            data = data.encode()
        hdr = struct.pack(">L", len(data))
        msg = b"".join([hdr, data])
        return self.send(msg)

    def recv_plist(self):
        payload = self.recv_raw()
        if not payload:
            return
        bplist_header = b'bplist00'
        xml_header = b'<?xml'
        if payload.startswith(bplist_header):
            return plistlib.loads(payload)
        elif payload.startswith(xml_header):
            # HAX lockdown HardwarePlatform with null bytes
            payload = sub(r'[^\w<>\/ \-_0-9\"\'\\=\.\?\!\+]+', '', payload.decode('utf-8')).encode('utf-8')
            return plistlib.loads(payload)
        else:
            raise Exception(f'recv_plist invalid data: {payload[:100].hex()}')

    def send_plist(self, d):
        payload = plistlib.dumps(d)
        message = struct.pack(">L", len(payload))
        return self.send(message + payload)

    def ssl_start(self, keyfile, certfile):
        self.socket = ssl.wrap_socket(self.socket, keyfile, certfile, ssl_version=ssl.PROTOCOL_TLSv1)

    def shell(self):
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
            user_ns={
                'client': self,
            })
