import asyncio
import logging
import plistlib
import socket
import ssl
import struct
import time
import xml
from enum import Enum
from typing import Any, Optional

import IPython
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import ConnectionTerminatedError, DeviceNotFoundError, NoDeviceConnectedError, \
    PyMobileDevice3Exception
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.usbmux import MuxDevice, select_device

DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3
DEFAULT_TIMEOUT = 1
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


def build_plist(d: dict, endianity: str = '>', fmt: Enum = plistlib.FMT_XML) -> bytes:
    """
    Convert a dictionary to a plist-formatted byte string prefixed with a length field.

    :param d: The dictionary to convert.
    :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
    :param fmt: The plist format (e.g., plistlib.FMT_XML).
    :return: The plist-formatted byte string.
    """
    payload = plistlib.dumps(d, fmt=fmt)
    message = struct.pack(endianity + 'L', len(payload))
    return message + payload


def parse_plist(payload: bytes) -> dict:
    """
    Parse a plist-formatted byte string into a dictionary.

    :param payload: The plist-formatted byte string to parse.
    :return: The parsed dictionary.
    :raises PyMobileDevice3Exception: If the payload is invalid.
    :retries with a filtered payload if plistlib compains about "not well-formed (invalid token)"
    """
    try:
        return plistlib.loads(payload)
    except xml.parsers.expat.ExpatError:
        payload = bytes([b for b in payload if b not in (0x00, 0x10)])
        try:
            return plistlib.loads(payload)
        except plistlib.InvalidFileException:
            raise PyMobileDevice3Exception(f'parse_plist invalid data: {payload[:100].hex()}')
    except plistlib.InvalidFileException:
        raise PyMobileDevice3Exception(f'parse_plist invalid data: {payload[:100].hex()}')


def create_context(certfile: str, keyfile: Optional[str] = None) -> ssl.SSLContext:
    """
    Create an SSL context for a secure connection.

    :param certfile: The path to the certificate file.
    :param keyfile: The path to the key file (optional).
    :return: An SSL context object.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ssl.OPENSSL_VERSION.lower().startswith('openssl'):
        context.set_ciphers('ALL:!aNULL:!eNULL:@SECLEVEL=0')
    else:
        context.set_ciphers('ALL:!aNULL:!eNULL')
    context.options |= 0x4  # OPENSSL OP_LEGACY_SERVER_CONNECT (required for legacy iOS devices)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile, keyfile)
    return context


class ServiceConnection:
    """ wrapper for tcp-relay connections """

    def __init__(self, sock: socket.socket, mux_device: MuxDevice = None):
        """
        Initialize a ServiceConnection object.

        :param sock: The socket to use for the connection.
        :param mux_device: The MuxDevice associated with the connection (optional).
        """
        self.logger = logging.getLogger(__name__)
        self.socket = sock
        self._offset = 0

        # usbmux connections contain additional information associated with the current connection
        self.mux_device = mux_device

        self.reader = None  # type: Optional[asyncio.StreamReader]
        self.writer = None  # type: Optional[asyncio.StreamWriter]

    @staticmethod
    def create_using_tcp(hostname: str, port: int, keep_alive: bool = True,
                         create_connection_timeout: int = DEFAULT_TIMEOUT) -> 'ServiceConnection':
        """
        Create a ServiceConnection using a TCP connection.

        :param hostname: The hostname of the server to connect to.
        :param port: The port to connect to.
        :param keep_alive: Whether to enable TCP keep-alive.
        :param create_connection_timeout: The timeout for creating the connection.
        :return: A ServiceConnection object.
        """
        sock = socket.create_connection((hostname, port), timeout=create_connection_timeout)
        sock.settimeout(None)
        if keep_alive:
            OSUTIL.set_keepalive(sock)
        return ServiceConnection(sock)

    @staticmethod
    def create_using_usbmux(udid: Optional[str], port: int, connection_type: str = None,
                            usbmux_address: Optional[str] = None) -> 'ServiceConnection':
        """
        Create a ServiceConnection using a USBMux connection.

        :param udid: The UDID of the target device.
        :param port: The port to connect to.
        :param connection_type: The type of connection to use.
        :param usbmux_address: The address of the usbmuxd socket.
        :return: A ServiceConnection object.
        :raises DeviceNotFoundError: If the device with the specified UDID is not found.
        :raises NoDeviceConnectedError: If no device is connected.
        """
        target_device = select_device(udid, connection_type=connection_type, usbmux_address=usbmux_address)
        if target_device is None:
            if udid:
                raise DeviceNotFoundError(udid)
            raise NoDeviceConnectedError()
        sock = target_device.connect(port, usbmux_address=usbmux_address)
        return ServiceConnection(sock, mux_device=target_device)

    def setblocking(self, blocking: bool) -> None:
        """
        Set the blocking mode of the socket.

        :param blocking: If True, set the socket to blocking mode; otherwise, set it to non-blocking mode.
        """
        self.socket.setblocking(blocking)

    def close(self) -> None:
        """ Close the connection. """
        self.socket.close()

    async def aio_close(self) -> None:
        """ Asynchronously close the connection. """
        if self.writer is None:
            return
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ssl.SSLError:
            pass
        self.writer = None
        self.reader = None

    def recv(self, length: int = 4096) -> bytes:
        """
        Receive data from the socket.

        :param length: The maximum amount of data to receive.
        :return: The received data.
        """
        try:
            return self.socket.recv(length)
        except ssl.SSLError:
            raise ConnectionAbortedError()

    def sendall(self, data: bytes) -> None:
        """
        Send data to the socket.

        :param data: The data to send.
        :raises ConnectionTerminatedError: If the connection is terminated abruptly.
        """
        try:
            self.socket.sendall(data)
        except ssl.SSLEOFError as e:
            raise ConnectionTerminatedError from e

    def send_recv_plist(self, data: dict, endianity: str = '>', fmt: Enum = plistlib.FMT_XML) -> Any:
        """
        Send a plist to the socket and receive a plist response.

        :param data: The dictionary to send as a plist.
        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :param fmt: The plist format (e.g., plistlib.FMT_XML).
        :return: The received plist as a dictionary.
        """
        self.send_plist(data, endianity=endianity, fmt=fmt)
        return self.recv_plist(endianity=endianity)

    async def aio_send_recv_plist(self, data: dict, endianity: str = '>', fmt: Enum = plistlib.FMT_XML) -> Any:
        """
        Asynchronously send a plist to the socket and receive a plist response.

        :param data: The dictionary to send as a plist.
        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :param fmt: The plist format (e.g., plistlib.FMT_XML).
        :return: The received plist as a dictionary.
        """
        await self.aio_send_plist(data, endianity=endianity, fmt=fmt)
        return await self.aio_recv_plist(endianity=endianity)

    def recvall(self, size: int) -> bytes:
        """
        Receive all data of a specified size from the socket.

        :param size: The amount of data to receive.
        :return: The received data.
        :raises ConnectionAbortedError: If the connection is aborted.
        """
        data = b''
        while len(data) < size:
            chunk = self.recv(size - len(data))
            if chunk is None or len(chunk) == 0:
                raise ConnectionAbortedError()
            data += chunk
        return data

    def recv_prefixed(self, endianity: str = '>') -> bytes:
        """
        Receive a data block prefixed with a length field.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received data block.
        """
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
        """
        Asynchronously receive data of a specified size from the socket.

        :param size: The amount of data to receive.
        :return: The received data.
        """
        return await self.reader.readexactly(size)

    async def aio_recv_prefixed(self, endianity: str = '>') -> bytes:
        """
        Asynchronously receive a data block prefixed with a length field.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received data block.
        """
        size = await self.aio_recvall(4)
        size = struct.unpack(endianity + 'L', size)[0]
        return await self.aio_recvall(size)

    def send_prefixed(self, data: bytes) -> None:
        """
        Send a data block prefixed with a length field.

        :param data: The data to send.
        """
        if isinstance(data, str):
            data = data.encode()
        hdr = struct.pack('>L', len(data))
        msg = b''.join([hdr, data])
        return self.sendall(msg)

    def recv_plist(self, endianity: str = '>') -> dict:
        """
        Receive a plist from the socket and parse it into a dictionary.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received plist as a dictionary.
        """
        return parse_plist(self.recv_prefixed(endianity=endianity))

    async def aio_recv_plist(self, endianity: str = '>') -> dict:
        """
        Asynchronously receive a plist from the socket and parse it into a dictionary.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received plist as a dictionary.
        """
        return parse_plist(await self.aio_recv_prefixed(endianity))

    def send_plist(self, d: dict, endianity: str = '>', fmt: Enum = plistlib.FMT_XML) -> None:
        """
        Send a dictionary as a plist to the socket.

        :param d: The dictionary to send.
        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :param fmt: The plist format (e.g., plistlib.FMT_XML).
        """
        return self.sendall(build_plist(d, endianity, fmt))

    async def aio_sendall(self, payload: bytes) -> None:
        """
        Asynchronously send data to the socket.

        :param payload: The data to send.
        """
        self.writer.write(payload)
        await self.writer.drain()

    async def aio_send_plist(self, d: dict, endianity: str = '>', fmt: Enum = plistlib.FMT_XML) -> None:
        """
        Asynchronously send a dictionary as a plist to the socket.

        :param d: The dictionary to send.
        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :param fmt: The plist format (e.g., plistlib.FMT_XML).
        """
        await self.aio_sendall(build_plist(d, endianity, fmt))

    def ssl_start(self, certfile: str, keyfile: Optional[str] = None) -> None:
        """
        Start an SSL connection.

        :param certfile: The path to the certificate file.
        :param keyfile: The path to the key file (optional).
        """
        self.socket = create_context(certfile, keyfile=keyfile).wrap_socket(self.socket)

    async def aio_ssl_start(self, certfile: str, keyfile: Optional[str] = None) -> None:
        """
        Asynchronously start an SSL connection.

        :param certfile: The path to the certificate file.
        :param keyfile: The path to the key file (optional).
        """
        self.reader, self.writer = await asyncio.open_connection(
            sock=self.socket,
            ssl=create_context(certfile, keyfile=keyfile),
            server_hostname=''
        )

    async def aio_start(self) -> None:
        """ Asynchronously start a connection. """
        self.reader, self.writer = await asyncio.open_connection(sock=self.socket)

    def shell(self) -> None:
        """ Start an interactive shell. """
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style='native')),
            user_ns={
                'client': self,
            })

    def read(self, size: int) -> bytes:
        """
        Read data from the socket.

        :param size: The amount of data to read.
        :return: The read data.
        """
        result = self.recvall(size)
        self._offset += size
        return result

    def write(self, data: bytes) -> None:
        """
        Write data to the socket.

        :param data: The data to write.
        """
        self.sendall(data)
        self._offset += len(data)

    def tell(self) -> int:
        """
        Get the current offset.

        :return: The current offset.
        """
        return self._offset
