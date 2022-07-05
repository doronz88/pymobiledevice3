import asyncio
import logging
import plistlib
import ssl
import struct
import time

import IPython
from pygments import highlight, lexers, formatters

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedError, PyMobileDevice3Exception, ConnectionTerminatedError, \
    NoDeviceConnectedError
from pymobiledevice3.usbmux import select_device

SHELL_USAGE = """
# This shell allows you to communicate directly with every service layer behind the lockdownd daemon.

# For example, you can do the following:
client.send_plist({"Command": "DoSomething"})

# and view the reply
print(client.recv_plist())

# or just send raw message
client.send(b"hello")

# and view the result
print(client.recvall(20))
"""


def build_plist(d, endianity='>', fmt=plistlib.FMT_XML):
    payload = plistlib.dumps(d, fmt=fmt)
    message = struct.pack(endianity + 'L', len(payload))
    return message + payload


def parse_plist(payload):
    try:
        return plistlib.loads(payload)
    except plistlib.InvalidFileException:
        raise PyMobileDevice3Exception(f'parse_plist invalid data: {payload[:100].hex()}')


def create_context(keyfile, certfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ssl.OPENSSL_VERSION.lower().startswith('openssl'):
        context.set_ciphers('ALL:!aNULL:!eNULL:@SECLEVEL=0')
    else:
        context.set_ciphers('ALL:!aNULL:!eNULL')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile, keyfile)
    return context


class ServiceConnection(object):
    """ wrapper for usbmux tcp-relay connections """

    def __init__(self, socket):
        self.logger = logging.getLogger(__name__)
        self.socket = socket
        self._reader = None  # type: asyncio.StreamReader
        self._writer = None  # type: asyncio.StreamWriter

    @staticmethod
    def create(udid: str, port: int, connection_type=None):
        target_device = select_device(udid, connection_type=connection_type)
        if target_device is None:
            raise NoDeviceConnectedError()
        try:
            socket = target_device.connect(port)
        except usbmux.MuxException:
            raise ConnectionFailedError(f'Connection to device port {port} failed')

        return ServiceConnection(socket)

    def setblocking(self, blocking: bool):
        self.socket.setblocking(blocking)

    def close(self):
        self.socket.close()

    async def aio_close(self):
        if self._writer is None:
            return
        self._writer.close()
        await self._writer.wait_closed()
        self._writer = None
        self._reader = None

    def recv(self, length=4096):
        """ socket.recv() normal behavior. attempt to receive a single chunk """
        return self.socket.recv(length)

    def sendall(self, data):
        try:
            self.socket.sendall(data)
        except ssl.SSLEOFError as e:
            raise ConnectionTerminatedError from e

    def send_recv_plist(self, data, endianity='>', fmt=plistlib.FMT_XML):
        self.send_plist(data, endianity=endianity, fmt=fmt)
        return self.recv_plist(endianity=endianity)

    def recvall(self, size):
        data = b''
        while len(data) < size:
            chunk = self.recv(size - len(data))
            if chunk is None or len(chunk) == 0:
                raise ConnectionAbortedError()
            data += chunk
        return data

    def recv_prefixed(self, endianity='>'):
        """ receive a data block prefixed with a u32 length field """
        size = self.recvall(4)
        if not size or len(size) != 4:
            return
        size = struct.unpack(endianity + 'L', size)[0]
        while True:
            try:
                return self.recvall(size)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                # Allow ssl to do stuff
                time.sleep(0)

    async def aio_recv_prefixed(self, endianity='>'):
        """ receive a data block prefixed with a u32 length field """
        size = await self._reader.readexactly(4)
        size = struct.unpack(endianity + 'L', size)[0]
        return await self._reader.readexactly(size)

    def send_prefixed(self, data):
        """ send a data block prefixed with a u32 length field """
        if isinstance(data, str):
            data = data.encode()
        hdr = struct.pack('>L', len(data))
        msg = b''.join([hdr, data])
        return self.sendall(msg)

    def recv_plist(self, endianity='>'):
        return parse_plist(self.recv_prefixed(endianity=endianity))

    async def aio_recv_plist(self, endianity='>'):
        return parse_plist(await self.aio_recv_prefixed(endianity))

    def send_plist(self, d, endianity='>', fmt=plistlib.FMT_XML):
        return self.sendall(build_plist(d, endianity, fmt))

    async def aio_send_plist(self, d, endianity='>', fmt=plistlib.FMT_XML):
        self._writer.write(build_plist(d, endianity, fmt))
        await self._writer.drain()

    def ssl_start(self, keyfile, certfile):
        self.socket = create_context(keyfile, certfile).wrap_socket(self.socket)

    async def aio_ssl_start(self, keyfile, certfile):
        self._reader, self._writer = await asyncio.open_connection(
            sock=self.socket,
            ssl=create_context(keyfile, certfile),
            server_hostname=''
        )

    def shell(self):
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
            user_ns={
                'client': self,
            })
