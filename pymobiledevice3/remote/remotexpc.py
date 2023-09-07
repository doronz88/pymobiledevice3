import socket
from socket import create_connection
from typing import Generator, Mapping, Optional, Tuple

import IPython
from construct import StreamError
from hyperframe.frame import DataFrame, Frame, GoAwayFrame, HeadersFrame, RstStreamFrame, SettingsFrame, \
    WindowUpdateFrame
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import StreamClosedError
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

SHELL_USAGE = """
# This shell allows you to communicate directly with every RemoteXPC service.

# For example, you can do the following:
resp = client.send_receive_request({"Command": "DoSomething"})
"""


class RemoteXPCConnection:
    def __init__(self, address: Tuple[str, int]):
        self._previous_frame_data = b''
        self.address = address
        self.sock: Optional[socket.socket] = None
        self.next_message_id: Mapping[int: int] = {ROOT_CHANNEL: 0, REPLY_CHANNEL: 0}
        self.peer_info = None

    def __enter__(self) -> 'RemoteXPCConnection':
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def connect(self) -> None:
        self.sock = create_connection(self.address)
        self._do_handshake()

    def close(self) -> None:
        self.sock.close()

    def send_request(self, data: Mapping, wanting_reply: bool = False) -> None:
        xpc_wrapper = create_xpc_wrapper(
            data, message_id=self.next_message_id[ROOT_CHANNEL], wanting_reply=wanting_reply)
        self.sock.sendall(DataFrame(stream_id=ROOT_CHANNEL, data=xpc_wrapper).serialize())

    def iter_file_chunks(self, total_size: int, file_idx: int = 0) -> Generator[bytes, None, None]:
        stream_id = (file_idx + 1) * 2
        self._open_channel(stream_id, XpcFlags.FILE_TX_STREAM_RESPONSE)
        size = 0
        while size < total_size:
            frame = self._receive_next_data_frame()

            if 'END_STREAM' in frame.flags:
                continue

            if frame.stream_id != stream_id:
                xpc_wrapper = XpcWrapper.parse(frame.data)
                if xpc_wrapper.flags.FILE_TX_STREAM_REQUEST:
                    continue

            assert frame.stream_id == stream_id, f'got {frame.stream_id} instead of {stream_id}'
            size += len(frame.data)
            yield frame.data

    def receive_file(self, total_size: int) -> bytes:
        buf = b''
        for chunk in self.iter_file_chunks(total_size):
            buf += chunk
        return buf

    def receive_response(self) -> Mapping:
        while True:
            frame = self._receive_next_data_frame()
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

    def send_receive_request(self, data: Mapping):
        self.send_request(data, wanting_reply=True)
        return self.receive_response()

    def shell(self) -> None:
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(),
                             formatters.TerminalTrueColorFormatter(style='native')),
            user_ns={
                'client': self,
                'XpcInt64Type': XpcInt64Type,
                'XpcUInt64Type': XpcUInt64Type,
            })

    def _do_handshake(self) -> None:
        self.sock.sendall(HTTP2_MAGIC)

        # send h2 headers
        self._send_frame(SettingsFrame(settings={
            SettingsFrame.MAX_CONCURRENT_STREAMS: DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS,
            SettingsFrame.INITIAL_WINDOW_SIZE: DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
        }))
        self._send_frame(WindowUpdateFrame(stream_id=0, window_increment=DEFAULT_WIN_SIZE_INCR))
        self._send_frame(HeadersFrame(stream_id=ROOT_CHANNEL, flags=['END_HEADERS']))

        # send first actual requests
        self.send_request({})
        self._send_frame(DataFrame(stream_id=ROOT_CHANNEL,
                                   data=XpcWrapper.build({'size': 0, 'flags': 0x0201, 'payload': None})))
        self.next_message_id[ROOT_CHANNEL] += 1
        self._open_channel(REPLY_CHANNEL, XpcFlags.INIT_HANDSHAKE)
        self.next_message_id[REPLY_CHANNEL] += 1

        assert isinstance(self._receive_frame(), SettingsFrame)

        self._send_frame(SettingsFrame(flags=['ACK']))

    def _open_channel(self, stream_id: int, flags: int):
        flags |= XpcFlags.ALWAYS_SET
        self._send_frame(HeadersFrame(stream_id=stream_id, flags=['END_HEADERS']))
        self._send_frame(
            DataFrame(stream_id=stream_id, data=XpcWrapper.build({'size': 0, 'flags': flags, 'payload': None})))

    def _send_frame(self, frame: Frame) -> None:
        self.sock.sendall(frame.serialize())

    def _receive_next_data_frame(self) -> DataFrame:
        while True:
            frame = self._receive_frame()

            if isinstance(frame, GoAwayFrame):
                raise StreamClosedError(f'Got {frame}')
            if isinstance(frame, RstStreamFrame):
                raise StreamClosedError(f'Got {frame}')
            if not isinstance(frame, DataFrame):
                continue

            if frame.stream_id % 2 == 0 and frame.body_len > 0:
                self._send_frame(WindowUpdateFrame(stream_id=0, window_increment=frame.body_len))
                self._send_frame(WindowUpdateFrame(stream_id=frame.stream_id, window_increment=frame.body_len))

            return frame

    def _receive_frame(self) -> Frame:
        buf = self._recvall(FRAME_HEADER_SIZE)
        frame, additional_size = Frame.parse_frame_header(memoryview(buf))
        frame.parse_body(memoryview(self._recvall(additional_size)))
        return frame

    def _recvall(self, size: int) -> bytes:
        data = b''
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if chunk is None or len(chunk) == 0:
                raise ConnectionAbortedError()
            data += chunk
        return data
