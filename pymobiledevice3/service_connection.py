import asyncio
import contextlib
import logging
import plistlib
import socket
import ssl
import struct
import xml.parsers.expat
from collections.abc import Coroutine
from typing import Any, Callable, Optional, cast

from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    DeviceNotFoundError,
    NoDeviceConnectedError,
    ProtocolError,
)
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.plist_types import PlistDict, PlistSendable, PlistValue
from pymobiledevice3.usbmux import MuxDevice, select_device
from pymobiledevice3.utils import start_ipython_shell

DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3
DEFAULT_TIMEOUT = 1
DEFAULT_SSL_HANDSHAKE_TIMEOUT = 10
CLOSE_STREAM_WRITER_DEFAULT_TIMEOUT_SECONDS = 1.0
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


def build_plist(d: PlistSendable, endianity: str = ">", fmt: plistlib.PlistFormat = plistlib.FMT_XML) -> bytes:
    """
    Convert a dictionary to a plist-formatted byte string prefixed with a length field.

    :param d: The dictionary to convert.
    :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
    :param fmt: The plist format (e.g., plistlib.FMT_XML).
    :return: The plist-formatted byte string.
    """
    # ``d`` is already constrained to plist-serialisable data; plistlib.dumps' stub types its
    # parameter more narrowly than our covariant PlistSendable, so widen at this boundary only.
    payload = plistlib.dumps(cast(Any, d), fmt=fmt)
    message = struct.pack(endianity + "L", len(payload))
    return message + payload


def parse_plist(payload: bytes) -> PlistValue:
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
            raise ProtocolError(f"The device sent a reply that is not a valid plist: {payload[:100].hex()}") from e
    except plistlib.InvalidFileException as e:
        raise ProtocolError(f"The device sent a reply that is not a valid plist: {payload[:100].hex()}") from e


async def close_stream_writer(
    writer: asyncio.StreamWriter, timeout: float = CLOSE_STREAM_WRITER_DEFAULT_TIMEOUT_SECONDS
) -> None:
    """Close a stream writer gracefully, aborting its transport if its close hangs"""
    with contextlib.suppress(Exception):
        writer.close()
    with contextlib.suppress(Exception):
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                writer.transport.abort()


def create_ssl_context(
    certfile: str,
    keyfile: Optional[str] = None,
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    maximum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
) -> ssl.SSLContext:
    """
    Create the client SSL context lockdownd and the services behind it expect.

    :param certfile: The path to the certificate file.
    :param keyfile: The path to the key file (optional).
    :param minimum_version: The oldest TLS version to offer (TLS v1.2 is supported since iOS 5).
    :param maximum_version: The newest TLS version to offer.
    :return: An SSL context object.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = minimum_version
    context.maximum_version = maximum_version
    if ssl.OPENSSL_VERSION.lower().startswith("openssl"):
        context.set_ciphers("ALL:!aNULL:!eNULL:@SECLEVEL=0")
    else:
        context.set_ciphers("ALL:!aNULL:!eNULL")
    context.options |= 0x4  # OPENSSL OP_LEGACY_SERVER_CONNECT (required for legacy iOS devices)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile, keyfile)
    return context


# TLS record content types: change_cipher_spec, alert, handshake, application_data
_TLS_CONTENT_TYPES = (20, 21, 22, 23)


async def _strip_ssl(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ssl_context: ssl.SSLContext) -> None:
    """
    Complete a TLS handshake over the streams, then leave them carrying plaintext.

    Pre-iOS 14 DTX services gate on a handshake but speak raw bytes afterwards. The handshake runs
    in memory, fed one whole TLS record at a time, so nothing past its last record is consumed and
    the stream transport stays the only reader of the socket.
    """
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl_context.wrap_bio(incoming, outgoing, server_side=False)
    while True:
        try:
            tls.do_handshake()
            done = True
        except ssl.SSLWantReadError:
            done = False
        pending = outgoing.read()
        if pending:
            writer.write(pending)
            await writer.drain()
        if done:
            return
        header = await reader.readexactly(5)
        if header[0] not in _TLS_CONTENT_TYPES or header[1] != 3:
            raise ConnectionTerminatedError(f"The device answered the TLS handshake with non-TLS data: {header.hex()}")
        (length,) = struct.unpack(">H", header[3:])
        incoming.write(header + await reader.readexactly(length))


async def _strip_ssl_or_close(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ssl_context: ssl.SSLContext
) -> None:
    try:
        await asyncio.wait_for(_strip_ssl(reader, writer, ssl_context), timeout=DEFAULT_SSL_HANDSHAKE_TIMEOUT)
    except BaseException as e:
        # Wait for the close: a proactor transport releases the socket only once its pending read is cancelled.
        await close_stream_writer(writer)
        if isinstance(e, (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError)):
            raise ConnectionTerminatedError() from e
        raise


async def _dial(
    dialing: Coroutine[Any, Any, tuple[asyncio.StreamReader, asyncio.StreamWriter]], timeout: float
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Await a dial within ``timeout``, closing what it dialed if the wait ends without taking it.

    wait_for() drops a result that completes as the wait is cancelled or times out; shielded, the
    dial is cancelled here instead, and a connection it completed anyway is closed.
    """
    dial = asyncio.create_task(dialing)
    try:
        return await asyncio.wait_for(asyncio.shield(dial), timeout=timeout)
    except BaseException:
        dial.cancel()
        dial.add_done_callback(_close_dialed)
        raise


def _close_dialed(dial: "asyncio.Task[tuple[asyncio.StreamReader, asyncio.StreamWriter]]") -> None:
    if not dial.cancelled() and dial.exception() is None:
        dial.result()[1].close()


def _tls_options(ssl_context: ssl.SSLContext) -> dict[str, Any]:
    return {"ssl": ssl_context, "server_hostname": "", "ssl_handshake_timeout": DEFAULT_SSL_HANDSHAKE_TIMEOUT}


async def _start_tls(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ssl_context: ssl.SSLContext
) -> asyncio.StreamWriter:
    """Upgrade bound streams to TLS in place, returning the writer to use from now on."""
    try:
        # Python 3.11+ provides StreamWriter.start_tls(); older versions
        # need loop.start_tls() and a new StreamWriter bound to the TLS transport.
        if hasattr(writer, "start_tls"):
            await asyncio.wait_for(
                writer.start_tls(  # type: ignore[attr-defined]
                    sslcontext=ssl_context,
                    server_hostname="",
                    ssl_handshake_timeout=DEFAULT_SSL_HANDSHAKE_TIMEOUT,
                ),
                timeout=DEFAULT_SSL_HANDSHAKE_TIMEOUT,
            )
            return writer
        loop = asyncio.get_running_loop()
        protocol = cast(Any, writer)._protocol
        tls_transport = await asyncio.wait_for(
            loop.start_tls(
                writer.transport,
                protocol,
                ssl_context,
                server_side=False,
                server_hostname="",
                ssl_handshake_timeout=DEFAULT_SSL_HANDSHAKE_TIMEOUT,
            ),
            timeout=DEFAULT_SSL_HANDSHAKE_TIMEOUT,
        )
        if tls_transport is None:
            raise ConnectionTerminatedError()
        return asyncio.StreamWriter(tls_transport, protocol, reader, loop)
    except (OSError, asyncio.TimeoutError) as e:
        raise ConnectionTerminatedError() from e


class ServiceConnection:
    """
    A connection to a device service, framing its messages over one bound stream pair.

    Instances are always bound to the event loop, TLS (when asked) negotiated before they exist:
    the stream transport is the only owner of the fd. The one raw socket ever handed over is
    usbmuxd's, to `from_socket`, which binds it before the connection exists.
    """

    # Bounds one buffered response, not the total size of a streamed transfer.
    # Applications using unusually large messages may override this per instance.
    max_frame_size = 128 * 1024 * 1024

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, mux_device: Optional[MuxDevice] = None
    ) -> None:
        """
        Initialize a ServiceConnection over already-bound streams.

        :param reader: The stream reader of the connection.
        :param writer: The stream writer of the connection; closing the connection closes it.
        :param mux_device: The MuxDevice associated with the connection (optional).
        """
        self.logger = logging.getLogger(__name__)
        self.reader = reader
        self.writer = writer
        self._closed = False
        # The in-flight start_tls() upgrade, which close() cancels before closing the writer.
        self._upgrade: Optional[asyncio.Task[asyncio.StreamWriter]] = None

        # usbmux connections contain additional information associated with the current connection
        self.mux_device = mux_device

        # Held across the full send→recv pair in send_recv_plist() so that concurrent
        # callers (e.g. LockdownClient shared by many tasks) are serialised automatically.
        self._transaction_lock = asyncio.Lock()

    @classmethod
    async def from_socket(
        cls,
        sock: socket.socket,
        *,
        ssl_context: Optional[ssl.SSLContext] = None,
        strip_ssl: bool = False,
        mux_device: Optional[MuxDevice] = None,
    ) -> "ServiceConnection":
        """
        Take ownership of a connected socket and bind it to the event loop.

        Only for a socket that exists before any stream does (usbmuxd hands one over once it
        forwards to the device). The socket is closed if this fails, so the caller must not use it
        afterwards either way.

        :param sock: A connected stream socket.
        :param ssl_context: Negotiate TLS with this context before any service traffic.
        :param strip_ssl: Complete the TLS handshake, then carry the traffic in plaintext (pre-iOS 14
            DTX services gate on a handshake but speak raw bytes afterwards). Requires ``ssl_context``.
        :param mux_device: The MuxDevice the socket was connected through (optional).
        :return: A bound ServiceConnection.
        """
        try:
            sock.setblocking(False)
            options = _tls_options(ssl_context) if ssl_context is not None and not strip_ssl else {}
            try:
                reader, writer = await asyncio.open_connection(sock=sock, **options)
            except OSError as e:
                raise ConnectionTerminatedError() from e
        except BaseException:
            # A transport that took the socket is already closing it; this only covers failures
            # before one did.
            sock.close()
            raise
        if ssl_context is not None and strip_ssl:
            await _strip_ssl_or_close(reader, writer, ssl_context)
        return cls(reader, writer, mux_device=mux_device)

    @classmethod
    async def create_using_tcp(
        cls,
        hostname: str,
        port: int,
        keep_alive: bool = True,
        create_connection_timeout: float = DEFAULT_TIMEOUT,
        open_connection: Optional[Callable[..., Any]] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        strip_ssl: bool = False,
    ) -> "ServiceConnection":
        """
        Create a ServiceConnection using a TCP connection.

        :param hostname: The hostname of the server to connect to.
        :param port: The port to connect to.
        :param keep_alive: Whether to enable TCP keep-alive.
        :param create_connection_timeout: The timeout for creating the connection (the TLS handshake
            has its own).
        :param open_connection: Optional ``asyncio.open_connection``-compatible dialer. Defaults to
            ``asyncio.open_connection``; the userspace tunnel injects one that relays device-bound
            connections through its in-process stack. Keep-alive is skipped for injected dialers —
            their connection is a process-local relay leg, not the network leg to the device.
        :param ssl_context: Negotiate TLS with this context before any service traffic.
        :param strip_ssl: See `from_socket`.
        :return: A ServiceConnection object.
        """
        dialer = open_connection or asyncio.open_connection
        reader, writer = await _dial(dialer(hostname, port), create_connection_timeout)
        try:
            sock = writer.get_extra_info("socket")
            if sock is None:
                raise ConnectionError(f"failed to get socket from connection to {hostname}:{port}")
            if keep_alive and open_connection is None:
                OSUTIL.set_keepalive(sock)
            if ssl_context is not None and strip_ssl:
                await _strip_ssl_or_close(reader, writer, ssl_context)
            elif ssl_context is not None:
                writer = await _start_tls(reader, writer, ssl_context)
        except BaseException:
            # Never leak the established connection: an open writer keeps the userspace
            # tunnel's relay pumping (and its accepted transport attached) forever.
            await close_stream_writer(writer)
            raise
        return cls(reader, writer)

    @classmethod
    async def create_using_usbmux(
        cls,
        udid: Optional[str],
        port: int,
        connection_type: Optional[str] = None,
        usbmux_address: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        strip_ssl: bool = False,
    ) -> "ServiceConnection":
        """
        Create a ServiceConnection through usbmuxd.

        :param udid: Target device UDID (or None for first available matching device).
        :param port: Device-side service port to connect to.
        :param connection_type: Optional transport filter (e.g. ``USB``/``Network``).
        :param usbmux_address: Optional override for the usbmuxd socket address.
        :param ssl_context: See `from_socket`.
        :param strip_ssl: See `from_socket`.
        :return: A ServiceConnection bound to the selected device/port.
        :raises DeviceNotFoundError: If the requested UDID is not found.
        :raises NoDeviceConnectedError: If no matching devices are connected.
        """
        target_device = await select_device(udid, connection_type=connection_type, usbmux_address=usbmux_address)
        if target_device is None:
            if udid:
                over = f" over {connection_type}" if connection_type else ""
                raise DeviceNotFoundError(udid, f"Device not found: usbmux has no device matching udid {udid}{over}")
            raise NoDeviceConnectedError()
        sock = await target_device.connect(port, usbmux_address=usbmux_address)
        return await cls.from_socket(sock, ssl_context=ssl_context, strip_ssl=strip_ssl, mux_device=target_device)

    def _checked_writer(self) -> asyncio.StreamWriter:
        if self._closed:
            raise ConnectionTerminatedError()
        return self.writer

    def _checked_reader(self) -> asyncio.StreamReader:
        if self._closed:
            raise ConnectionTerminatedError()
        return self.reader

    async def aclose(self) -> None:
        """Asynchronously close the connection."""
        await self.close()

    async def close(self) -> None:
        """Asynchronously close the connection."""
        self._closed = True
        upgrade = self._upgrade
        if upgrade is not None:
            # A transport closed under the handshake makes StreamWriter.start_tls() install a
            # None transport (CPython 3.11+); cancelled first, it leaves the writer as it was.
            upgrade.cancel()
            await asyncio.wait([upgrade])
        await close_stream_writer(self.writer)

    async def recv_any(self, length: int = 4096) -> bytes:
        """
        Asynchronously receive up to ``length`` bytes from the socket/stream.

        :raises ConnectionTerminatedError: If the connection failed. A clean close returns ``b""``.
        """
        reader = self._checked_reader()
        try:
            return await reader.read(length)
        except OSError as e:
            raise ConnectionTerminatedError() from e

    async def send_recv_prefixed(self, data: bytes, endianity: str = ">") -> bytes:
        """
        Atomically send raw bytes and receive a length-prefixed response, under the
        transaction lock.

        This is the lowest-level concurrent-safe send→recv primitive. Higher-level
        methods such as :meth:`send_recv_plist` are built on top of it.

        :param data: Raw bytes to send (already serialised by the caller).
        :param endianity: The byte order for the length prefix.
        :return: The raw response bytes (may be empty).
        """
        async with self._transaction_lock:
            await self.sendall(data)
            return await self.recv_prefixed(endianity=endianity)

    async def send_recv_plist(
        self, data: PlistSendable, endianity: str = ">", fmt: plistlib.PlistFormat = plistlib.FMT_XML
    ) -> PlistDict:
        """
        Asynchronously send a plist to the socket and receive a plist response.

        This method is safe to call concurrently from multiple coroutines on the same
        connection: a per-connection lock serialises each send→recv pair atomically so
        that responses are always matched to their request.

        :param data: The dictionary to send as a plist.
        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :param fmt: The plist format (e.g., plistlib.FMT_XML).
        :return: The received plist as a dictionary.
        """
        # Every request/response service behind lockdownd answers with a dictionary-rooted plist.
        return cast(PlistDict, parse_plist(await self.send_recv_prefixed(build_plist(data, endianity, fmt), endianity)))

    async def recvall(self, size: int) -> bytes:
        """
        Asynchronously receive data of a specified size from the socket.

        :param size: The amount of data to receive.
        :return: The received data.
        :raises ConnectionTerminatedError: If the peer closed the connection or it failed.
        """
        reader = self._checked_reader()
        try:
            return await reader.readexactly(size)
        except (asyncio.IncompleteReadError, OSError) as e:
            raise ConnectionTerminatedError() from e

    async def recv_prefixed(self, endianity: str = ">") -> bytes:
        """
        Asynchronously receive a data block prefixed with a length field.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received data block.
        """
        size = await self.recvall(4)
        size = self._checked_frame_size(struct.unpack(endianity + "L", size)[0])
        return await self.recvall(size)

    def _checked_frame_size(self, size: int) -> int:
        if size > self.max_frame_size:
            raise ProtocolError(f"The device sent a {size}-byte message, over the {self.max_frame_size}-byte limit.")
        return size

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

    async def recv_plist(self, endianity: str = ">") -> PlistDict:
        """
        Asynchronously receive a plist from the socket and parse it into a native type.

        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :return: The received plist as a native type.
        """
        # Dictionary-rooted for every request/response service; DeviceLink callers that expect a
        # list-rooted message narrow the result themselves.
        return cast(PlistDict, parse_plist(await self.recv_prefixed(endianity)))

    async def sendall(self, payload: bytes) -> None:
        """
        Asynchronously send data to the socket.

        :param payload: The data to send.
        :raises ConnectionTerminatedError: If the peer closed the connection or it failed.
        """
        writer = self._checked_writer()
        try:
            writer.write(payload)
            await writer.drain()
            if self._closed:
                # close() aborted the transport while this waited: the data may not have gone out
                raise ConnectionTerminatedError()
        except OSError as e:
            raise ConnectionTerminatedError from e

    async def send_plist(
        self, d: PlistSendable, endianity: str = ">", fmt: plistlib.PlistFormat = plistlib.FMT_XML
    ) -> None:
        """
        Asynchronously send a dictionary as a plist to the socket.

        :param d: The dictionary to send.
        :param endianity: The byte order ('>' for big-endian, '<' for little-endian).
        :param fmt: The plist format (e.g., plistlib.FMT_XML).
        """
        await self.sendall(build_plist(d, endianity, fmt))

    async def start_tls(self, ssl_context: ssl.SSLContext) -> None:
        """
        Upgrade the connection to TLS in place, mid-session (lockdownd's StartSession).

        A service that is TLS from its first byte negotiates it at creation instead (the
        ``ssl_context`` of `from_socket` / `create_using_tcp`).

        :param ssl_context: The context to negotiate with (see `create_ssl_context`).
        """
        upgrade = asyncio.create_task(
            _start_tls(self.reader, self._checked_writer(), ssl_context), name="service-connection-start-tls"
        )
        self._upgrade = upgrade
        try:
            await asyncio.wait([upgrade])
        except BaseException:
            upgrade.cancel()
            raise
        finally:
            self._upgrade = None
        if upgrade.cancelled() or self._closed:
            # close() ran during the handshake
            raise ConnectionTerminatedError()
        self.writer = upgrade.result()

    async def __aenter__(self) -> "ServiceConnection":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    def shell(self) -> None:
        """Start an interactive shell."""
        start_ipython_shell(
            header=highlight(
                SHELL_USAGE, cast(Any, lexers).PythonLexer(), formatters.Terminal256Formatter(style="native")
            ),
            user_ns={
                "client": self,
            },
        )
