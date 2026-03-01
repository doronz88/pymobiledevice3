import asyncio
import contextlib
import logging
import plistlib
import socket
import ssl
import struct
import time
import xml
from enum import Enum
from typing import Any, Optional, Union

from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    DeviceNotFoundError,
    NoDeviceConnectedError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.usbmux import MuxDevice, select_device
from pymobiledevice3.utils import start_ipython_shell

DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3
DEFAULT_TIMEOUT = 1
DEFAULT_SSL_HANDSHAKE_TIMEOUT = 10
OSUTIL = get_os_utils()
SHELL_USAGE = """
# This shell allows you to communicate directly with every service layer behind the lockdownd daemon.

# For example, you can do the following:
await client.send_plist({"Command": "DoSomething"})

# and view the reply
print(await client.recv_plist())

# or just send raw message
client.send(b"hello")

# and view the result
print(await client.recvall(20))
"""


def build_plist(d: dict, endianity: str = ">", fmt: Enum = plistlib.FMT_XML) -> bytes:
    """
    Convert a dictionary to a plist-formatted byte string prefixed with a length field.

    :param d: The dictionary to convert.
    :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
    :param fmt: The plist format (e.g., plistlib.FMT_XML).
    :return: The plist-formatted byte string.
    """
    payload = plistlib.dumps(d, fmt=fmt)
    message = struct.pack(endianity + "L", len(payload))
    return message + payload


def parse_plist(payload: bytes) -> dict:
    """
    Parse a plist-formatted byte string into a dictionary.

    :param payload: The plist-formatted byte string to parse.
    :return: The parsed dictionary.
    :raises PyMobileDevice3Exception: If the payload is invalid.
    :retries with a filtered payload of only valid XML characters if plistlib compains about "not well-formed (invalid token)"
    """
    try:
        return plistlib.loads(payload)
    except xml.parsers.expat.ExpatError:
        payload = bytes([b for b in payload if b >= 0x20 or b in (0x09, 0x0A, 0x0D)])
        try:
            return plistlib.loads(payload)
        except plistlib.InvalidFileException as e:
            raise PyMobileDevice3Exception(f"parse_plist invalid data: {payload[:100].hex()}") from e
    except plistlib.InvalidFileException as e:
        raise PyMobileDevice3Exception(f"parse_plist invalid data: {payload[:100].hex()}") from e


class ServiceConnection:
    """wrapper for tcp-relay connections"""

    def __init__(self, sock: socket.socket, mux_device: Optional[MuxDevice] = None) -> None:
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

        # Async stream reader and writer used for stream mode.
        self.reader = None  # type: Optional[asyncio.StreamReader]
        self.writer = None  # type: Optional[asyncio.StreamWriter]

        # SSL/TLS version to be used for connecting to device
        # TLS v1.2 is supported since iOS 5
        self.min_ssl_proto = ssl.TLSVersion.TLSv1_2
        self.max_ssl_proto = ssl.TLSVersion.TLSv1_3
        self.socket.setblocking(False)

    @staticmethod
    async def create_using_tcp(
        hostname: str, port: int, keep_alive: bool = True, create_connection_timeout: int = DEFAULT_TIMEOUT
    ) -> "ServiceConnection":
        """
        Create a ServiceConnection using a TCP connection.

        :param hostname: The hostname of the server to connect to.
        :param port: The port to connect to.
        :param keep_alive: Whether to enable TCP keep-alive.
        :param create_connection_timeout: The timeout for creating the connection.
        :return: A ServiceConnection object.
        """
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=create_connection_timeout
        )
        sock = writer.get_extra_info("socket")
        if sock is None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise ConnectionError(f"failed to get socket from connection to {hostname}:{port}")
        if keep_alive:
            OSUTIL.set_keepalive(sock)
        conn = ServiceConnection(sock)
        conn.reader = reader
        conn.writer = writer
        return conn

    @staticmethod
    async def create_using_usbmux(
        udid: Optional[str], port: int, connection_type: Optional[str] = None, usbmux_address: Optional[str] = None
    ) -> "ServiceConnection":
        """
        Create a ServiceConnection through usbmuxd.

        :param udid: Target device UDID (or None for first available matching device).
        :param port: Device-side service port to connect to.
        :param connection_type: Optional transport filter (e.g. ``USB``/``Network``).
        :param usbmux_address: Optional override for the usbmuxd socket address.
        :return: A ServiceConnection bound to the selected device/port.
        :raises DeviceNotFoundError: If the requested UDID is not found.
        :raises NoDeviceConnectedError: If no matching devices are connected.
        """
        target_device = await select_device(udid, connection_type=connection_type, usbmux_address=usbmux_address)
        if target_device is None:
            if udid:
                raise DeviceNotFoundError(udid)
            raise NoDeviceConnectedError()
        sock = await target_device.connect(port, usbmux_address=usbmux_address)
        return ServiceConnection(sock, mux_device=target_device)

    def setblocking(self, blocking: bool) -> None:
        """
        Set the blocking mode of the socket.

        :param blocking: If True, set the socket to blocking mode; otherwise, set it to non-blocking mode.
        """
        self.socket.setblocking(blocking)

    async def _ensure_started(self) -> None:
        if self.reader is not None and self.writer is not None:
            return
        await self.start()

    async def aclose(self) -> None:
        """Asynchronously close the connection."""
        await self.close()

    async def close(self) -> None:
        """Asynchronously close the connection."""
        if self.writer is not None:
            with contextlib.suppress(Exception):
                self.writer.close()
            with contextlib.suppress(Exception):
                await self.writer.wait_closed()
            if self.socket is not None and self.socket.fileno() != -1:
                with contextlib.suppress(Exception):
                    self.socket.close()
        elif self.socket is not None:
            with contextlib.suppress(Exception):
                self.socket.close()
        self.socket = None
        self.writer = None
        self.reader = None

    def recv_sync(self, length: int = 4096) -> bytes:
        """
        Receive data from the socket.

        :param length: The maximum amount of data to receive.
        :return: The received data.
        """
        try:
            return self.socket.recv(length)
        except (ssl.SSLError, BrokenPipeError) as e:
            raise ConnectionTerminatedError() from e

    async def recv_any(self, length: int = 4096) -> bytes:
        """
        Asynchronously receive up to ``length`` bytes from the socket/stream.
        """
        await self._ensure_started()
        return await self.reader.read(length)

    def sendall_sync(self, data: bytes) -> None:
        """
        Send data to the socket.

        :param data: The data to send.
        :raises ConnectionTerminatedError: If the connection is terminated abruptly.
        """
        try:
            self.socket.sendall(data)
        except ssl.SSLEOFError as e:
            raise ConnectionTerminatedError from e

    async def send_recv_plist(self, data: dict, endianity: str = ">", fmt: Enum = plistlib.FMT_XML) -> Any:
        """
        Asynchronously send a plist to the socket and receive a plist response.

        :param data: The dictionary to send as a plist.
        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :param fmt: The plist format (e.g., plistlib.FMT_XML).
        :return: The received plist as a dictionary.
        """
        await self.send_plist(data, endianity=endianity, fmt=fmt)
        return await self.recv_plist(endianity=endianity)

    def recvall_sync(self, size: int) -> bytes:
        """
        Receive all data of a specified size from the socket.

        :param size: The amount of data to receive.
        :return: The received data.
        :raises ConnectionTerminatedError: If the connection is aborted.
        """
        data = b""
        while len(data) < size:
            chunk = self.recv_sync(size - len(data))
            if chunk is None or len(chunk) == 0:
                raise ConnectionTerminatedError()
            data += chunk
        return data

    def recv_prefixed_sync(self, endianity: str = ">") -> bytes:
        """
        Receive a data block prefixed with a length field.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received data block.
        """
        size = self.recvall_sync(4)
        if not size or len(size) != 4:
            return b""
        size = struct.unpack(endianity + "L", size)[0]
        while True:
            try:
                return self.recvall_sync(size)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                # Allow ssl to do stuff
                time.sleep(0)

    async def recvall(self, size: int) -> bytes:
        """
        Asynchronously receive data of a specified size from the socket.

        :param size: The amount of data to receive.
        :return: The received data.
        """
        await self._ensure_started()
        return await self.reader.readexactly(size)

    async def recv_prefixed(self, endianity: str = ">") -> bytes:
        """
        Asynchronously receive a data block prefixed with a length field.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received data block.
        """
        size = await self.recvall(4)
        size = struct.unpack(endianity + "L", size)[0]
        return await self.recvall(size)

    async def send_prefixed(self, data: bytes) -> None:
        """
        Send a data block prefixed with a length field.

        :param data: The data to send.
        """
        if isinstance(data, str):
            data = data.encode()
        hdr = struct.pack(">L", len(data))
        msg = b"".join([hdr, data])
        await self.sendall(msg)

    def recv_plist_sync(self, endianity: str = ">") -> Union[dict, list]:
        """
        Receive a plist from the socket and parse it into a native type.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received plist as a native type.
        """
        return parse_plist(self.recv_prefixed_sync(endianity=endianity))

    async def recv_plist(self, endianity: str = ">") -> dict:
        """
        Asynchronously receive a plist from the socket and parse it into a native type.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received plist as a native type.
        """
        return parse_plist(await self.recv_prefixed(endianity))

    async def sendall(self, payload: bytes) -> None:
        """
        Asynchronously send data to the socket.

        :param payload: The data to send.
        """
        await self._ensure_started()
        try:
            self.writer.write(payload)
            await self.writer.drain()
        except ssl.SSLEOFError as e:
            raise ConnectionTerminatedError from e

    async def send_plist(self, d: Union[dict, list], endianity: str = ">", fmt: Enum = plistlib.FMT_XML) -> None:
        """
        Asynchronously send a dictionary as a plist to the socket.

        :param d: The dictionary to send.
        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :param fmt: The plist format (e.g., plistlib.FMT_XML).
        """
        await self.sendall(build_plist(d, endianity, fmt))

    def create_ssl_context(self, certfile: str, keyfile: Optional[str] = None) -> ssl.SSLContext:
        """
        Create an SSL context for a secure connection.

        :param certfile: The path to the certificate file.
        :param keyfile: The path to the key file (optional).
        :return: An SSL context object.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = self.min_ssl_proto
        context.maximum_version = self.max_ssl_proto
        if ssl.OPENSSL_VERSION.lower().startswith("openssl"):
            context.set_ciphers("ALL:!aNULL:!eNULL:@SECLEVEL=0")
        else:
            context.set_ciphers("ALL:!aNULL:!eNULL")
        context.options |= 0x4  # OPENSSL OP_LEGACY_SERVER_CONNECT (required for legacy iOS devices)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(certfile, keyfile)
        return context

    def ssl_start_sync(self, certfile: str, keyfile: Optional[str] = None) -> None:
        """
        Start an SSL connection.

        :param certfile: The path to the certificate file.
        :param keyfile: The path to the key file (optional).
        """
        try:
            self.socket.settimeout(DEFAULT_SSL_HANDSHAKE_TIMEOUT)
            self.socket = self.create_ssl_context(certfile, keyfile=keyfile).wrap_socket(self.socket)
        except OSError as e:
            raise ConnectionTerminatedError() from e
        finally:
            if self.socket is not None:
                self.socket.settimeout(None)

    async def ssl_start(self, certfile: str, keyfile: Optional[str] = None) -> None:
        """
        Asynchronously start an SSL connection.

        :param certfile: The path to the certificate file.
        :param keyfile: The path to the key file (optional).
        """
        await self._ensure_started()
        try:
            await asyncio.wait_for(
                self.writer.start_tls(
                    sslcontext=self.create_ssl_context(certfile, keyfile=keyfile),
                    server_hostname="",
                    ssl_handshake_timeout=DEFAULT_SSL_HANDSHAKE_TIMEOUT,
                ),
                timeout=DEFAULT_SSL_HANDSHAKE_TIMEOUT,
            )
        except OSError as e:
            raise ConnectionTerminatedError() from e

    async def start(self) -> None:
        """Asynchronously initialize stream reader/writer for the socket."""
        if self.reader is not None and self.writer is not None:
            return
        if self.socket is None:
            raise ConnectionTerminatedError()
        self.reader, self.writer = await asyncio.open_connection(sock=self.socket)

    def shell(self) -> None:
        """Start an interactive shell."""
        start_ipython_shell(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style="native")),
            user_ns={
                "client": self,
            },
        )

    def read(self, size: int) -> bytes:
        """
        Read data from the socket.

        :param size: The amount of data to read.
        :return: The read data.
        """
        result = self.recvall_sync(size)
        self._offset += size
        return result

    def write(self, data: bytes) -> None:
        """
        Write data to the socket.

        :param data: The data to write.
        """
        self.sendall_sync(data)
        self._offset += len(data)

    def tell(self) -> int:
        """
        Get the current offset.

        :return: The current offset.
        """
        return self._offset
