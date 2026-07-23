import asyncio
import contextlib
import uuid
from asyncio import IncompleteReadError
from collections.abc import AsyncIterable
from typing import Any, Callable, Optional, Union

from construct import StreamError
from hyperframe.frame import (
    DataFrame,
    Frame,
    GoAwayFrame,
    HeadersFrame,
    RstStreamFrame,
    SettingsFrame,
    WindowUpdateFrame,
)
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    NotConnectedError,
    ProtocolError,
    StreamClosedError,
)
from pymobiledevice3.remote.xpc_message import (
    XpcFlags,
    XpcInt64Type,
    XpcUInt64Type,
    XpcWrapper,
    create_xpc_wrapper,
    decode_xpc_object,
)
from pymobiledevice3.utils import start_ipython_shell

# Extracted by sniffing `remoted` traffic via Wireshark
DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS = 100
# Keep enough file-transfer data in flight to avoid frequent flow-control round trips.
DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE = 16 * 1024 * 1024
DEFAULT_WIN_SIZE_INCR = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE - 65535
WINDOW_UPDATE_THRESHOLD = 1024 * 1024

FRAME_HEADER_SIZE = 9
HTTP2_MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

ROOT_CHANNEL = 1
REPLY_CHANNEL = 3

# Announce ourselves as a modern (non-legacy) RemoteXPC peer.
REMOTE_XPC_VERSION_FLAGS = 0x0100000000000006
MESSAGING_PROTOCOL_VERSION = 7

FIRST_REPLY_TIMEOUT = 3

SHELL_USAGE = """
# This shell allows you to communicate directly with every RemoteXPC service.

# For example, you can do the following:
resp = await client.send_receive_request({"Command": "DoSomething"})
"""


class RemoteXPCConnection:
    def __init__(self, address: tuple[str, int], open_connection: Optional[Callable[..., Any]] = None):
        self._previous_frame_data = b""
        self.address = address
        # ``asyncio.open_connection``-compatible dialer. Defaults to the stdlib function; the
        # userspace tunnel injects one that relays device-bound connections through its in-process
        # stack, so no global ``asyncio.open_connection`` monkeypatch is needed.
        self._open_connection = open_connection or asyncio.open_connection
        self.next_message_id: dict[int, int] = {ROOT_CHANNEL: 0, REPLY_CHANNEL: 0}
        self.peer_info = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._pending_window_updates: dict[int, int] = {}
        self._file_chunk_queues: dict[int, asyncio.Queue[Union[bytes, BaseException]]] = {}
        self._file_chunk_reader_task: Optional[asyncio.Task[None]] = None
        # Serialise request/response round-trips. ``send_receive_request`` is a
        # write-then-read against a single shared reader + ``_previous_frame_data``
        # buffer with no per-request stream demux, so two concurrent callers
        # interleave their reads and steal each other's frames -- one observes
        # "0 bytes read" and the connection is corrupted for good. Any caller
        # that issues requests from multiple tasks (e.g. a periodic keepalive
        # alongside normal RPCs) needs this.
        self._request_lock = asyncio.Lock()

    async def __aenter__(self) -> "RemoteXPCConnection":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        self._reader, self._writer = await self._open_connection(self.address[0], self.address[1])
        try:
            await self._do_handshake()
        except Exception:
            await self.close()
            raise

    @property
    def reader(self) -> asyncio.StreamReader:
        """The stream reader.

        :raises NotConnectedError: if accessed before ``connect()`` (or after ``close()``).
        """
        if self._reader is None:
            raise NotConnectedError("RemoteXPCConnection is not open")
        return self._reader

    @property
    def writer(self) -> asyncio.StreamWriter:
        """The stream writer.

        :raises NotConnectedError: if accessed before ``connect()`` (or after ``close()``).
        """
        if self._writer is None:
            raise NotConnectedError("RemoteXPCConnection is not open")
        return self._writer

    @property
    def local_address(self) -> tuple[str, int]:
        """``(host, port)`` of the local end of the connection to the device.

        Useful when sending the device a callback endpoint that lives on this
        host's tunnel interface — e.g. an RTP receiver port in
        ``mediastreamstart``. Only valid while the connection is open.
        """
        sockname = self.writer.get_extra_info("sockname")
        return sockname[0], sockname[1]

    async def close(self) -> None:
        self._pending_window_updates.clear()
        if self._file_chunk_reader_task is not None:
            self._file_chunk_reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._file_chunk_reader_task
            self._file_chunk_reader_task = None
        self._file_chunk_queues.clear()
        if self._writer is None:
            return
        self._writer.close()
        with contextlib.suppress(Exception):
            await self._writer.wait_closed()
        self._writer = None
        self._reader = None

    async def send_device_handshake(self) -> None:
        """Announce the client as a modern (non-legacy) RemoteXPC peer.

        Send only on the RSD/remoted control connection, after the HTTP/2
        handshake and before reading ``peer_info``.
        """
        await self.send_request({
            "MessageType": "Handshake",
            "MessagingProtocolVersion": XpcUInt64Type(MESSAGING_PROTOCOL_VERSION),
            "UUID": uuid.uuid4(),
            "Properties": {
                "RemoteXPCVersionFlags": XpcUInt64Type(REMOTE_XPC_VERSION_FLAGS),
                "SensitivePropertiesVisible": True,
            },
            "Services": {},
        })

    async def send_request(self, data: dict[str, Any], wanting_reply: bool = False) -> None:
        xpc_wrapper = create_xpc_wrapper(
            data, message_id=self.next_message_id[ROOT_CHANNEL], wanting_reply=wanting_reply
        )
        writer = self.writer
        writer.write(DataFrame(stream_id=ROOT_CHANNEL, data=xpc_wrapper).serialize())
        await writer.drain()
        self.next_message_id[ROOT_CHANNEL] += 1

    async def iter_file_chunks(self, total_size: int, file_idx: int = 0) -> AsyncIterable[bytes]:
        stream_id = (file_idx + 1) * 2
        chunk_queue: asyncio.Queue[Union[bytes, BaseException]] = asyncio.Queue()
        self._file_chunk_queues[stream_id] = chunk_queue
        try:
            await self._open_channel(stream_id, XpcFlags.FILE_TX_STREAM_RESPONSE)
            if self._file_chunk_reader_task is None:
                self._file_chunk_reader_task = asyncio.create_task(self._route_file_chunks())

            size = 0
            while size < total_size:
                chunk = await chunk_queue.get()
                if isinstance(chunk, BaseException):
                    raise chunk
                size += len(chunk)
                yield chunk
        finally:
            self._file_chunk_queues.pop(stream_id, None)
            await self._replenish_receive_window(stream_id, force=True)
            if not self._file_chunk_queues and self._file_chunk_reader_task is not None:
                self._file_chunk_reader_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._file_chunk_reader_task
                self._file_chunk_reader_task = None

    async def _route_file_chunks(self) -> None:
        try:
            while self._file_chunk_queues:
                frame = await self._receive_next_data_frame()
                if "END_STREAM" in frame.flags:
                    continue

                chunk_queue = self._file_chunk_queues.get(frame.stream_id)
                if chunk_queue is not None:
                    chunk_queue.put_nowait(frame.data)
                    continue

                xpc_wrapper = XpcWrapper.parse(frame.data)
                if not xpc_wrapper.flags.FILE_TX_STREAM_REQUEST:
                    raise ProtocolError(f"Got unexpected file transfer stream: {frame.stream_id}")
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            for chunk_queue in self._file_chunk_queues.values():
                chunk_queue.put_nowait(e)

    async def receive_file(self, total_size: int) -> bytes:
        buf = b""
        async for chunk in self.iter_file_chunks(total_size):
            buf += chunk
        return buf

    async def receive_response(self) -> dict[str, Any]:
        while True:
            frame = await self._receive_next_data_frame()
            try:
                xpc_message = XpcWrapper.parse(self._previous_frame_data + frame.data).message
                self._previous_frame_data = b""
            except StreamError:
                self._previous_frame_data += frame.data
                continue
            if xpc_message.payload is None:
                continue
            if xpc_message.payload.obj.data.entries is None:
                continue
            self.next_message_id[frame.stream_id] = xpc_message.message_id + 1
            return decode_xpc_object(xpc_message.payload.obj)

    async def send_receive_request(self, data: dict[str, Any]) -> dict[str, Any]:
        async with self._request_lock:
            await self.send_request(data, wanting_reply=True)
            return await self.receive_response()

    def shell(self) -> None:
        start_ipython_shell(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style="native")),
            user_ns={
                "client": self,
                "XpcInt64Type": XpcInt64Type,
                "XpcUInt64Type": XpcUInt64Type,
            },
        )

    async def _do_handshake(self) -> None:
        writer = self.writer
        writer.write(HTTP2_MAGIC)
        await writer.drain()

        # send h2 headers
        await self._send_frame(
            SettingsFrame(
                settings={
                    SettingsFrame.MAX_CONCURRENT_STREAMS: DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS,
                    SettingsFrame.INITIAL_WINDOW_SIZE: DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
                }
            )
        )
        await self._send_frame(WindowUpdateFrame(stream_id=0, window_increment=DEFAULT_WIN_SIZE_INCR))
        await self._send_frame(HeadersFrame(stream_id=ROOT_CHANNEL, flags=["END_HEADERS"]))

        # send first actual requests — frame order matches what devicectl emits:
        #   Headers#1, Data#1(init), Headers#3, Data#1(term=0x0201), Data#3(INIT_HANDSHAKE).
        # The receiving daemon validates frame ordering at the RemoteServiceDiscovery
        # layer and rejects with "Invalid or missing remote device connection version
        # flags" + xpc_connection_cancel() if Headers#3 isn't seen before Data#1's term.
        await self.send_request({})
        await self._send_frame(HeadersFrame(stream_id=REPLY_CHANNEL, flags=["END_HEADERS"]))
        await self._send_frame(
            DataFrame(stream_id=ROOT_CHANNEL, data=XpcWrapper.build({"size": 0, "flags": 0x0201, "payload": None}))
        )
        await self._send_frame(
            DataFrame(
                stream_id=REPLY_CHANNEL,
                data=XpcWrapper.build({
                    "size": 0,
                    "flags": XpcFlags.ALWAYS_SET | XpcFlags.INIT_HANDSHAKE,
                    "payload": None,
                }),
            )
        )
        self.next_message_id[REPLY_CHANNEL] += 1

        settings_frame = await asyncio.wait_for(self._receive_frame(), FIRST_REPLY_TIMEOUT)
        if not isinstance(settings_frame, SettingsFrame):
            raise ProtocolError(f"Got unexpected frame: {settings_frame} instead of a SettingsFrame")

        await self._send_frame(SettingsFrame(flags=["ACK"]))

    async def _open_channel(self, stream_id: int, flags: Any) -> None:
        # flags is a construct FlagsEnum value (BitwisableString), not a plain int: `int()` on it
        # would try to parse the flag *name* and raise. construct resolves it to bits at build time.
        flags |= XpcFlags.ALWAYS_SET
        await self._send_frame(HeadersFrame(stream_id=stream_id, flags=["END_HEADERS"]))
        await self._send_frame(
            DataFrame(stream_id=stream_id, data=XpcWrapper.build({"size": 0, "flags": flags, "payload": None}))
        )

    async def _send_frame(self, frame: Frame) -> None:
        writer = self.writer
        writer.write(frame.serialize())
        await writer.drain()

    async def _receive_next_data_frame(self) -> DataFrame:
        while True:
            frame = await self._receive_frame()

            if isinstance(frame, GoAwayFrame):
                raise StreamClosedError(f"Got {frame}")
            if isinstance(frame, RstStreamFrame):
                raise StreamClosedError(f"Got {frame}")
            if not isinstance(frame, DataFrame):
                continue

            if frame.stream_id % 2 == 0 and frame.body_len > 0:
                await self._replenish_receive_window(frame.stream_id, frame.body_len)

            return frame

    async def _replenish_receive_window(self, stream_id: int, increment: int = 0, force: bool = False) -> None:
        pending_increment = self._pending_window_updates.get(stream_id, 0) + increment
        if not force and pending_increment < WINDOW_UPDATE_THRESHOLD:
            self._pending_window_updates[stream_id] = pending_increment
            return
        if pending_increment == 0:
            return

        self._pending_window_updates.pop(stream_id, None)
        writer = self.writer
        writer.write(WindowUpdateFrame(stream_id=0, window_increment=pending_increment).serialize())
        writer.write(WindowUpdateFrame(stream_id=stream_id, window_increment=pending_increment).serialize())
        await writer.drain()

    async def _receive_frame(self) -> Frame:
        buf = await self.reader.readexactly(FRAME_HEADER_SIZE)
        frame, additional_size = Frame.parse_frame_header(memoryview(buf))
        frame.parse_body(memoryview(await self._recvall(additional_size)))
        return frame

    async def _recvall(self, size: int) -> bytes:
        reader = self.reader
        data = b""
        while len(data) < size:
            try:
                chunk = await reader.readexactly(size - len(data))
            except IncompleteReadError as e:
                raise ConnectionTerminatedError() from e
            data += chunk
        return data
