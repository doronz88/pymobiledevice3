import socket
from socket import create_connection
from typing import Mapping, Optional, Tuple

from hyperframe.frame import DataFrame, Frame, GoAwayFrame, HeadersFrame, SettingsFrame, WindowUpdateFrame

from pymobiledevice3.exceptions import StreamClosedError
from pymobiledevice3.remote.xpc_message import XpcWrapper, create_xpc_wrapper, get_object_from_xpc_wrapper

# Extracted by sniffing `remoted` traffic via Wireshark
DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS = 100
DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE = 1048576
DEFAULT_WIN_SIZE_INCR = 983041

FRAME_HEADER_SIZE = 9
HTTP2_MAGIC = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


class RemoteXPCConnection:
    def __init__(self, address: Tuple[str, int]):
        self.address = address
        self.sock: Optional[socket.socket] = None
        self.next_message_id: Mapping[int: int] = {1: 0, 3: 0}
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

    def send_request(self, data: Mapping) -> None:
        self.sock.sendall(
            DataFrame(stream_id=1, data=create_xpc_wrapper(data, message_id=self.next_message_id[1])).serialize())
        self.next_message_id[1] += 1

    def receive_response(self):
        while True:
            frame = self._receive_frame()
            if isinstance(frame, GoAwayFrame):
                raise StreamClosedError()
            if not isinstance(frame, DataFrame):
                continue
            xpc_message = XpcWrapper.parse(frame.data).message
            if xpc_message.payload is None:
                continue
            if xpc_message.payload.obj.data.entries is None:
                continue

            self.next_message_id[frame.stream_id] = xpc_message.message_id + 1
            return get_object_from_xpc_wrapper(frame.data)

    def send_receive_request(self, data: Mapping):
        self.send_request(data)
        return self.receive_response()

    def _do_handshake(self) -> None:
        self.sock.sendall(HTTP2_MAGIC)

        # send h2 headers
        self._send_frame(SettingsFrame(settings={
            SettingsFrame.MAX_CONCURRENT_STREAMS: DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS,
            SettingsFrame.INITIAL_WINDOW_SIZE: DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
        }))
        self._send_frame(WindowUpdateFrame(stream_id=0, window_increment=DEFAULT_WIN_SIZE_INCR))
        self._send_frame(HeadersFrame(stream_id=1, flags=['END_HEADERS']))

        # send first actual requests
        self.send_request({})
        self._send_frame(DataFrame(stream_id=1, data=XpcWrapper.build({'size': 0, 'flags': 0x0201, 'payload': None})))
        self.next_message_id[1] += 1
        self._send_frame(HeadersFrame(stream_id=3, flags=['END_HEADERS']))
        self._send_frame(
            DataFrame(stream_id=3, data=XpcWrapper.build({'size': 0, 'flags': 0x00400001, 'payload': None})))
        self.next_message_id[3] += 1

        assert isinstance(self._receive_frame(), SettingsFrame)

        self._send_frame(SettingsFrame(flags=['ACK']))

    def _send_frame(self, frame: Frame) -> None:
        self.sock.sendall(frame.serialize())

    def _receive_frame(self) -> Frame:
        buf = self._recvall(FRAME_HEADER_SIZE)
        frame, additional_size = Frame.parse_frame_header(memoryview(buf))
        frame.parse_body(memoryview(self._recvall(additional_size)))
        return frame

    def _recvall(self, size: int) -> bytes:
        buf = b''
        while len(buf) < size:
            buf += self.sock.recv(size - len(buf))
        return buf
