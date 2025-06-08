import asyncio
import socket
import sys
from asyncio import IncompleteReadError
from typing import AsyncIterable, Optional

import IPython
import nest_asyncio
from construct import StreamError
from hyperframe.frame import DataFrame, Frame, GoAwayFrame, HeadersFrame, RstStreamFrame, SettingsFrame, \
    WindowUpdateFrame
from pygments import formatters, highlight, lexers
from traitlets.config import Config

from pymobiledevice3.exceptions import ProtocolError, StreamClosedError
from pymobiledevice3.remote.xpc_message import XpcFlags, XpcInt64Type, XpcUInt64Type, XpcWrapper, create_xpc_wrapper, \
    decode_xpc_object

# Extracted by sniffing `remoted` traffic via Wireshark
DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS = 100
DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE = 1048576
DEFAULT_WIN_SIZE_INCR = 983041

FRAME_HEADER_SIZE = 9
HTTP2_MAGIC = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

ROOT_CHANNEL = 1
REPLY_CHANNEL = 3

FIRST_REPLY_TIMEOUT = 3

SHELL_USAGE = """
# This shell allows you to communicate directly with every RemoteXPC service.

# For example, you can do the following:
resp = await client.send_receive_request({"Command": "DoSomething"})
"""


class RemoteXPCConnection:
    def __init__(self, address: tuple[str, int], userspace_address: "tuple[str, int] | None" = None):
        self._previous_frame_data = b''
        self.address = address
        self.userspace_address = userspace_address
        self.next_message_id: dict[int, int] = {ROOT_CHANNEL: 0, REPLY_CHANNEL: 0}
        self.peer_info = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    async def __aenter__(self) -> 'RemoteXPCConnection':
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def connect(self) -> None:
        if self.userspace_address:
            self._reader, self._writer = await asyncio.open_connection(*self.userspace_address)
            self._writer.write(
                socket.inet_pton(socket.AF_INET6, self.address[0])
                + self.address[1].to_bytes(4, "little")
            )
            await self._writer.drain()
        else:
            self._reader, self._writer = await asyncio.open_connection(self.address[0], self.address[1])
        try:
            await self._do_handshake()
        except Exception:  # noqa: E722
            await self.close()
            raise

    async def close(self) -> None:
        if self._writer is None:
            return
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except ConnectionResetError:
            pass
        self._writer = None
        self._reader = None

    async def send_request(self, data: dict, wanting_reply: bool = False) -> None:
        xpc_wrapper = create_xpc_wrapper(
            data, message_id=self.next_message_id[ROOT_CHANNEL], wanting_reply=wanting_reply)
        self._writer.write(DataFrame(stream_id=ROOT_CHANNEL, data=xpc_wrapper).serialize())
        await self._writer.drain()

    async def iter_file_chunks(self, total_size: int, file_idx: int = 0) -> AsyncIterable[bytes]:
        stream_id = (file_idx + 1) * 2
        await self._open_channel(stream_id, XpcFlags.FILE_TX_STREAM_RESPONSE)
        size = 0
        while size < total_size:
            frame = await self._receive_next_data_frame()

            if 'END_STREAM' in frame.flags:
                continue

            if frame.stream_id != stream_id:
                xpc_wrapper = XpcWrapper.parse(frame.data)
                if xpc_wrapper.flags.FILE_TX_STREAM_REQUEST:
                    continue

            assert frame.stream_id == stream_id, f'got {frame.stream_id} instead of {stream_id}'
            size += len(frame.data)
            yield frame.data

    async def receive_file(self, total_size: int) -> bytes:
        buf = b''
        async for chunk in self.iter_file_chunks(total_size):
            buf += chunk
        return buf

    async def receive_response(self) -> dict:
        while True:
            frame = await self._receive_next_data_frame()
            try:
                xpc_message = XpcWrapper.parse(self._previous_frame_data + frame.data).message
                self._previous_frame_data = b''
            except StreamError:
                self._previous_frame_data += frame.data
                continue
            if xpc_message.payload is None:
                continue
            if xpc_message.payload.obj.data.entries is None:
                continue
            self.next_message_id[frame.stream_id] = xpc_message.message_id + 1
            return decode_xpc_object(xpc_message.payload.obj)

    async def send_receive_request(self, data: dict) -> dict:
        await self.send_request(data, wanting_reply=True)
        return await self.receive_response()

    def shell(self) -> None:
        nest_asyncio.apply(asyncio.get_running_loop())
        sys.argv = ['a']
        config = Config()
        config.InteractiveShellApp.exec_lines = ['%autoawait asyncio']
        print(highlight(SHELL_USAGE, lexers.PythonLexer(),
                        formatters.Terminal256Formatter(style='native')))
        IPython.start_ipython(config=config, user_ns={
            'client': self,
            'XpcInt64Type': XpcInt64Type,
            'XpcUInt64Type': XpcUInt64Type,
        })

    async def _do_handshake(self) -> None:
        self._writer.write(HTTP2_MAGIC)
        await self._writer.drain()

        # send h2 headers
        await self._send_frame(SettingsFrame(settings={
            SettingsFrame.MAX_CONCURRENT_STREAMS: DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS,
            SettingsFrame.INITIAL_WINDOW_SIZE: DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
        }))
        await self._send_frame(WindowUpdateFrame(stream_id=0, window_increment=DEFAULT_WIN_SIZE_INCR))
        await self._send_frame(HeadersFrame(stream_id=ROOT_CHANNEL, flags=['END_HEADERS']))

        # send first actual requests
        await self.send_request({})
        await self._send_frame(DataFrame(stream_id=ROOT_CHANNEL,
                                         data=XpcWrapper.build({'size': 0, 'flags': 0x0201, 'payload': None})))
        self.next_message_id[ROOT_CHANNEL] += 1
        await self._open_channel(REPLY_CHANNEL, XpcFlags.INIT_HANDSHAKE)
        self.next_message_id[REPLY_CHANNEL] += 1

        settings_frame = await asyncio.wait_for(self._receive_frame(), FIRST_REPLY_TIMEOUT)
        if not isinstance(settings_frame, SettingsFrame):
            raise ProtocolError(f'Got unexpected frame: {settings_frame} instead of a SettingsFrame')

        await self._send_frame(SettingsFrame(flags=['ACK']))

    async def _open_channel(self, stream_id: int, flags: int) -> None:
        flags |= XpcFlags.ALWAYS_SET
        await self._send_frame(HeadersFrame(stream_id=stream_id, flags=['END_HEADERS']))
        await self._send_frame(
            DataFrame(stream_id=stream_id, data=XpcWrapper.build({'size': 0, 'flags': flags, 'payload': None})))

    async def _send_frame(self, frame: Frame) -> None:
        self._writer.write(frame.serialize())
        await self._writer.drain()

    async def _receive_next_data_frame(self) -> DataFrame:
        while True:
            frame = await self._receive_frame()

            if isinstance(frame, GoAwayFrame):
                raise StreamClosedError(f'Got {frame}')
            if isinstance(frame, RstStreamFrame):
                raise StreamClosedError(f'Got {frame}')
            if not isinstance(frame, DataFrame):
                continue

            if frame.stream_id % 2 == 0 and frame.body_len > 0:
                await self._send_frame(WindowUpdateFrame(stream_id=0, window_increment=frame.body_len))
                await self._send_frame(WindowUpdateFrame(stream_id=frame.stream_id, window_increment=frame.body_len))

            return frame

    async def _receive_frame(self) -> Frame:
        buf = await self._reader.readexactly(FRAME_HEADER_SIZE)
        frame, additional_size = Frame.parse_frame_header(memoryview(buf))
        frame.parse_body(memoryview(await self._recvall(additional_size)))
        return frame

    async def _recvall(self, size: int) -> bytes:
        data = b''
        while len(data) < size:
            try:
                chunk = await self._reader.readexactly(size - len(data))
            except IncompleteReadError:
                raise ConnectionAbortedError()
            data += chunk
        return data
