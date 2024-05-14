import asyncio
import logging
import plistlib
import socket
import ssl
import struct
import time
from enum import Enum
from typing import Any, Mapping, Optional

import IPython
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionTerminatedError, NoDeviceConnectedError, \
    PyMobileDevice3Exception
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.usbmux import MuxDevice, select_device

DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3
OSUTIL = get_os_utils()
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


def build_plist(d: Mapping, endianity: str = '>', fmt: Enum = plistlib.FMT_XML) -> bytes:
    payload = plistlib.dumps(d, fmt=fmt)
    message = struct.pack(endianity + 'L', len(payload))
    return message + payload


def parse_plist(payload):
    try:
        return plistlib.loads(payload)
    except plistlib.InvalidFileException:
        raise PyMobileDevice3Exception(f'parse_plist invalid data: {payload[:100].hex()}')


def create_context(certfile, keyfile=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ssl.OPENSSL_VERSION.lower().startswith('openssl'):
        context.set_ciphers('ALL:!aNULL:!eNULL:@SECLEVEL=0')
    else:
        context.set_ciphers('ALL:!aNULL:!eNULL')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile, keyfile)
    return context


class ServiceConnection:
    """ wrapper for tcp-relay connections """

    def __init__(self, sock: socket.socket, mux_device: MuxDevice = None):
        self.logger = logging.getLogger(__name__)
        self.socket = sock
        self._offset = 0

        # usbmux connections contain additional information associated with the current connection
        self.mux_device = mux_device

        self.reader = None  # type: Optional[asyncio.StreamReader]
        self.writer = None  # type: Optional[asyncio.StreamWriter]

    @staticmethod
    def create_using_tcp(hostname: str, port: int, keep_alive: bool = True) -> 'ServiceConnection':
        sock = socket.create_connection((hostname, port))
        if keep_alive:
            OSUTIL.set_keepalive(sock)
        return ServiceConnection(sock)

    @staticmethod
    def create_using_usbmux(udid: Optional[str], port: int, connection_type: str = None,
                            usbmux_address: Optional[str] = None) -> 'ServiceConnection':
        target_device = select_device(udid, connection_type=connection_type, usbmux_address=usbmux_address)
        if target_device is None:
            if udid:
                raise ConnectionFailedError()
            raise NoDeviceConnectedError()
        sock = target_device.connect(port, usbmux_address=usbmux_address)
        return ServiceConnection(sock, mux_device=target_device)

    def setblocking(self, blocking: bool) -> None:
        self.socket.setblocking(blocking)

    def close(self) -> None:
        self.socket.close()

    async def aio_close(self) -> None:
        if self.writer is None:
            return
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ssl.SSLError:
            pass
        self.writer = None
        self.reader = None

    def recv(self, length=4096) -> bytes:
        """ socket.recv() normal behavior. attempt to receive a single chunk """
        return self.socket.recv(length)

    def sendall(self, data: bytes) -> None:
        try:
            self.socket.sendall(data)
        except ssl.SSLEOFError as e:
            raise ConnectionTerminatedError from e

    def send_recv_plist(self, data: Mapping, endianity='>', fmt=plistlib.FMT_XML) -> Any:
        self.send_plist(data, endianity=endianity, fmt=fmt)
        return self.recv_plist(endianity=endianity)

    def recvall(self, size: int) -> bytes:
        data = b''
        while len(data) < size:
            chunk = self.recv(size - len(data))
            if chunk is None or len(chunk) == 0:
                raise ConnectionAbortedError()
            data += chunk
        return data

    def recv_prefixed(self, endianity='>') -> bytes:
        """ receive a data block prefixed with a u32 length field """
        size = self.recvall(4)
        if not size or len(size) != 4:
            return b''
        size = struct.unpack(endianity + 'L', size)[0]
        while True:
            try:
                return self.recvall(size)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                # Allow ssl to do stuff
                time.sleep(0)

    async def aio_recvall(self, size: int) -> bytes:
        """ receive a payload """
        return await self.reader.readexactly(size)

    async def aio_recv_prefixed(self, endianity='>') -> bytes:
        """ receive a data block prefixed with a u32 length field """
        size = await self.aio_recvall(4)
        size = struct.unpack(endianity + 'L', size)[0]
        return await self.aio_recvall(size)

    def send_prefixed(self, data: bytes) -> None:
        """ send a data block prefixed with a u32 length field """
        if isinstance(data, str):
            data = data.encode()
        hdr = struct.pack('>L', len(data))
        msg = b''.join([hdr, data])
        return self.sendall(msg)

    def recv_plist(self, endianity='>') -> Mapping:
        return parse_plist(self.recv_prefixed(endianity=endianity))

    async def aio_recv_plist(self, endianity='>') -> bytes:
        return parse_plist(await self.aio_recv_prefixed(endianity))

    def send_plist(self, d, endianity='>', fmt=plistlib.FMT_XML) -> None:
        return self.sendall(build_plist(d, endianity, fmt))

    async def aio_sendall(self, payload: bytes) -> None:
        self.writer.write(payload)
        await self.writer.drain()

    async def aio_send_plist(self, d: Mapping, endianity: str = '>', fmt: Enum = plistlib.FMT_XML) -> None:
        await self.aio_sendall(build_plist(d, endianity, fmt))

    def ssl_start(self, certfile, keyfile=None) -> None:
        self.socket = create_context(certfile, keyfile=keyfile).wrap_socket(self.socket)

    async def aio_ssl_start(self, certfile, keyfile=None) -> None:
        self.reader, self.writer = await asyncio.open_connection(
            sock=self.socket,
            ssl=create_context(certfile, keyfile=keyfile),
            server_hostname=''
        )

    async def aio_start(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(sock=self.socket)

    def shell(self) -> None:
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
            user_ns={
                'client': self,
            })

    def read(self, size: int) -> bytes:
        result = self.recvall(size)
        self._offset += size
        return result

    def write(self, data: bytes) -> None:
        self.sendall(data)
        self._offset += len(data)

    def tell(self) -> int:
        return self._offset
