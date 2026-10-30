import asyncio
import platform
import socket
import struct
import time
import uuid
from datetime import datetime, timedelta
from types import MethodType
from typing import Any, Optional, cast

import pytest
from bytestruct import BinaryBuildError, BinaryParseError, TruncatedDataError, UnexpectedConstantError
from hyperframe.frame import DataFrame, Frame, HeadersFrame, RstStreamFrame, SettingsFrame, WindowUpdateFrame

from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    ProtocolError,
    RemoteXPCHandshakeTimeoutError,
    StreamClosedError,
)
from pymobiledevice3.pair_records import generate_host_id
from pymobiledevice3.remote import remotexpc, xpc_message
from pymobiledevice3.remote.remotexpc import (
    DEFAULT_PEER_WINDOW_SIZE,
    DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
    DEFAULT_WIN_SIZE_INCR,
    FRAME_HEADER_SIZE,
    MAX_OUTBOUND_FRAME_SIZE,
    WINDOW_UPDATE_THRESHOLD,
    RemoteXPCConnection,
)
from pymobiledevice3.remote.xpc_message import (
    FileTransferType,
    XpcFlags,
    XpcInt64Type,
    XpcMessageType,
    XpcObject,
    XpcUInt64Type,
    XpcWrapper,
    create_xpc_wrapper,
    decode_xpc_object,
)


class FakeWriter:
    def __init__(self):
        self.writes = []
        self.drain_calls = 0

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        self.drain_calls += 1


class ResettingWriter:
    def close(self):
        pass

    async def wait_closed(self):
        raise ConnectionResetError


@pytest.mark.asyncio
async def test_receive_data_frame_batches_window_updates():
    frame = DataFrame(stream_id=2, data=b"x" * WINDOW_UPDATE_THRESHOLD)
    frame.serialize()

    async def receive_frame():
        return frame

    connection = RemoteXPCConnection(("localhost", 0))
    writer = FakeWriter()
    connection._writer = cast(asyncio.StreamWriter, writer)
    connection._receive_frame = receive_frame

    assert await connection._receive_next_data_frame() is frame
    assert len(writer.writes) == 2
    assert writer.drain_calls == 1


@pytest.mark.asyncio
async def test_force_replenish_receive_window_flushes_partial_batch():
    connection = RemoteXPCConnection(("localhost", 0))
    writer = FakeWriter()
    connection._writer = cast(asyncio.StreamWriter, writer)

    await connection._replenish_receive_window(stream_id=2, increment=1)
    assert writer.writes == []

    await connection._replenish_receive_window(stream_id=2, force=True)
    assert len(writer.writes) == 2
    assert writer.drain_calls == 1


def test_connection_window_matches_stream_window():
    assert DEFAULT_WIN_SIZE_INCR == DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE - 65535


@pytest.mark.asyncio
async def test_close_ignores_connection_reset():
    connection = RemoteXPCConnection(("localhost", 0))
    connection._writer = cast(asyncio.StreamWriter, ResettingWriter())

    await connection.close()


@pytest.mark.asyncio
async def test_iter_file_chunks_routes_interleaved_streams():
    frames = asyncio.Queue()
    for stream_id, data in ((2, b"a"), (4, b"b"), (2, b"c"), (4, b"d")):
        frames.put_nowait(DataFrame(stream_id=stream_id, data=data))

    async def open_channel(self, stream_id, flags):
        await asyncio.sleep(0)

    async def receive_next_data_frame(self):
        return await frames.get()

    async def receive_file(connection, file_idx):
        return [chunk async for chunk in connection.iter_file_chunks(2, file_idx=file_idx)]

    connection = RemoteXPCConnection(("localhost", 0))
    connection._open_channel = MethodType(open_channel, connection)
    connection._receive_next_data_frame = MethodType(receive_next_data_frame, connection)

    assert await asyncio.gather(receive_file(connection, 0), receive_file(connection, 1)) == [
        [b"a", b"c"],
        [b"b", b"d"],
    ]


def _parse_written_frames(writer: FakeWriter) -> list[Any]:
    """Re-parse everything a FakeWriter captured back into frames.

    Typed as Any because hyperframe's base ``Frame`` has no ``data``/``flags``; every caller here
    inspects concrete DataFrame/HeadersFrame instances.
    """
    buf = b"".join(writer.writes)
    frames: list[Any] = []
    while buf:
        frame, length = Frame.parse_frame_header(memoryview(buf[:FRAME_HEADER_SIZE]))
        frame.parse_body(memoryview(buf[FRAME_HEADER_SIZE : FRAME_HEADER_SIZE + length]))
        frames.append(frame)
        buf = buf[FRAME_HEADER_SIZE + length :]
    return frames


def _sending_connection(window: int = DEFAULT_PEER_WINDOW_SIZE) -> tuple[RemoteXPCConnection, FakeWriter]:
    connection = RemoteXPCConnection(("localhost", 0))
    writer = FakeWriter()
    connection._writer = cast(asyncio.StreamWriter, writer)
    connection._outbound_connection_window = window
    connection._peer_initial_window_size = window
    return connection, writer


@pytest.mark.asyncio
async def test_send_file_transfer_uses_odd_stream_and_carries_transfer_id():
    # The device rejects HEADERS on an even stream with GOAWAY "invalid stream_id", and rejects a
    # preamble whose msg_id is 0 with "Got HEADER with invalid msg_id 0".
    connection, writer = _sending_connection()

    await connection.send_file_transfer(transfer_id=7, data=b"payload")

    frames = _parse_written_frames(writer)
    stream_ids = {f.stream_id for f in frames}
    assert stream_ids == {5}
    assert all(stream_id % 2 == 1 for stream_id in stream_ids)
    assert isinstance(frames[0], HeadersFrame)
    preamble = XpcWrapper.parse(frames[1].data)
    assert preamble.message_id == 7
    assert XpcFlags.FILE_TX_STREAM_REQUEST in XpcFlags(preamble.flags)


@pytest.mark.asyncio
async def test_send_file_transfer_sends_payload_then_end_stream():
    connection, writer = _sending_connection()

    await connection.send_file_transfer(transfer_id=1, data=b"abcdef")

    frames = _parse_written_frames(writer)
    assert frames[2].data == b"abcdef"
    assert "END_STREAM" not in frames[2].flags
    assert frames[-1].data == b""
    assert "END_STREAM" in frames[-1].flags


@pytest.mark.asyncio
async def test_send_file_transfer_allocates_a_fresh_stream_each_time():
    connection, writer = _sending_connection()

    await connection.send_file_transfer(transfer_id=1, data=b"a")
    await connection.send_file_transfer(transfer_id=2, data=b"b")

    assert sorted({f.stream_id for f in _parse_written_frames(writer)}) == [5, 7]


@pytest.mark.asyncio
async def test_send_file_transfer_splits_payload_into_max_sized_frames():
    connection, writer = _sending_connection(window=10 * MAX_OUTBOUND_FRAME_SIZE)

    await connection.send_file_transfer(transfer_id=1, data=b"z" * (MAX_OUTBOUND_FRAME_SIZE * 2 + 5))

    payload_frames = [f for f in _parse_written_frames(writer)[2:] if f.data]
    assert [len(f.data) for f in payload_frames] == [MAX_OUTBOUND_FRAME_SIZE, MAX_OUTBOUND_FRAME_SIZE, 5]


@pytest.mark.asyncio
async def test_send_file_transfer_waits_for_window_then_resumes():
    """A payload larger than the peer's window must block until it grants more."""
    connection, writer = _sending_connection(window=MAX_OUTBOUND_FRAME_SIZE)
    # A real peer replenishes both the connection window and the stream's; either one left at zero
    # is enough to block the sender, so the fake must grant both.
    grants = iter([
        WindowUpdateFrame(stream_id=0, window_increment=MAX_OUTBOUND_FRAME_SIZE),
        WindowUpdateFrame(stream_id=5, window_increment=MAX_OUTBOUND_FRAME_SIZE),
    ])
    granted = 0

    async def receive_frame():
        nonlocal granted
        granted += 1
        return next(grants)

    connection._receive_frame = receive_frame

    await connection.send_file_transfer(transfer_id=1, data=b"z" * (MAX_OUTBOUND_FRAME_SIZE + 1))

    assert granted == 2, "expected to block until the peer replenished both windows"
    frames = _parse_written_frames(writer)
    preamble_len = len(frames[1].data)
    payload_frames = [f for f in frames[2:] if f.data]
    # The preamble is flow controlled too, so the first chunk is short by its length.
    assert [len(f.data) for f in payload_frames] == [
        MAX_OUTBOUND_FRAME_SIZE - preamble_len,
        MAX_OUTBOUND_FRAME_SIZE + 1 - (MAX_OUTBOUND_FRAME_SIZE - preamble_len),
    ]
    assert sum(len(f.data) for f in payload_frames) == MAX_OUTBOUND_FRAME_SIZE + 1


@pytest.mark.asyncio
async def test_preamble_consumes_flow_control_window():
    """The opening frame is DATA; not charging it overruns the window (GOAWAY error 3)."""
    connection, writer = _sending_connection()
    before = connection._outbound_connection_window

    await connection.send_file_transfer(transfer_id=1, data=b"")

    preamble_len = len(_parse_written_frames(writer)[1].data)
    assert connection._outbound_connection_window == before - preamble_len


@pytest.mark.asyncio
async def test_requests_consume_flow_control_window():
    """A request is DATA too; uncharged, a later file transfer overruns the window by its size."""
    connection, writer = _sending_connection()
    before = connection._outbound_connection_window

    await connection.send_request({"routine": "install"})

    request_len = len(_parse_written_frames(writer)[0].data)
    assert connection._outbound_connection_window == before - request_len
    assert connection._outbound_stream_windows[1] == before - request_len


@pytest.mark.asyncio
async def test_every_data_frame_sent_is_charged_to_the_connection_window():
    """The window left must be the window granted minus every DATA byte on the wire."""
    connection, writer = _sending_connection(window=10 * MAX_OUTBOUND_FRAME_SIZE)
    before = connection._outbound_connection_window

    await connection.send_request({"routine": "install"})
    await connection._open_channel(3, XpcFlags.FILE_TX_STREAM_RESPONSE)
    await connection.send_file_transfer(transfer_id=1, data=b"z" * (MAX_OUTBOUND_FRAME_SIZE + 5))

    sent = sum(len(f.data) for f in _parse_written_frames(writer) if isinstance(f, DataFrame))
    assert connection._outbound_connection_window == before - sent


def test_window_update_frames_grow_the_outbound_windows():
    connection, _ = _sending_connection()
    before = connection._outbound_connection_window

    assert connection._apply_flow_control_frame(WindowUpdateFrame(stream_id=0, window_increment=100))
    assert connection._outbound_connection_window == before + 100

    assert connection._apply_flow_control_frame(WindowUpdateFrame(stream_id=5, window_increment=50))
    assert connection._outbound_stream_windows[5] == DEFAULT_PEER_WINDOW_SIZE + 50


def test_settings_initial_window_size_shifts_open_stream_windows():
    connection, _ = _sending_connection()
    connection._outbound_stream_windows[5] = DEFAULT_PEER_WINDOW_SIZE

    connection._apply_flow_control_frame(
        SettingsFrame(settings={SettingsFrame.INITIAL_WINDOW_SIZE: DEFAULT_PEER_WINDOW_SIZE + 1000})
    )

    assert connection._peer_initial_window_size == DEFAULT_PEER_WINDOW_SIZE + 1000
    assert connection._outbound_stream_windows[5] == DEFAULT_PEER_WINDOW_SIZE + 1000


@pytest.mark.asyncio
async def test_reset_of_a_finished_transfer_stream_is_not_an_error():
    """The device resets a transfer stream once it has the payload; that is normal completion."""
    connection, _ = _sending_connection()
    connection._finished_file_transfer_streams.add(5)
    data_frame = DataFrame(stream_id=1, data=b"later")
    frames = iter([RstStreamFrame(stream_id=5), data_frame])

    async def receive_frame():
        return next(frames)

    connection._receive_frame = receive_frame

    assert await connection._pump_one_frame() is data_frame


@pytest.mark.asyncio
async def test_reset_of_an_unrelated_stream_still_raises():
    connection, _ = _sending_connection()

    async def receive_frame():
        return RstStreamFrame(stream_id=9)

    connection._receive_frame = receive_frame

    with pytest.raises(StreamClosedError):
        await connection._pump_one_frame()


@pytest.mark.asyncio
async def test_send_request_splits_a_large_message_into_max_sized_frames():
    connection = RemoteXPCConnection(("localhost", 0))
    writer = FakeWriter()
    connection._writer = cast(asyncio.StreamWriter, writer)
    connection._outbound_connection_window = 10 * MAX_OUTBOUND_FRAME_SIZE
    connection._outbound_stream_windows[1] = 10 * MAX_OUTBOUND_FRAME_SIZE

    await connection.send_request({"command": "x", "payload": {"blob": b"\x00" * (3 * MAX_OUTBOUND_FRAME_SIZE)}})

    frames = [Frame.parse_frame_header(w[:FRAME_HEADER_SIZE])[0] for w in writer.writes]
    assert all(isinstance(f, DataFrame) and f.stream_id == 1 for f in frames)
    assert len(frames) > 1 and all(len(w) - FRAME_HEADER_SIZE <= MAX_OUTBOUND_FRAME_SIZE for w in writer.writes)
    reassembled = b"".join(w[FRAME_HEADER_SIZE:] for w in writer.writes)
    assert XpcWrapper.parse(reassembled).message_id == 0
    assert connection.next_message_id[1] == 1


@pytest.mark.asyncio
async def test_send_request_keeps_small_messages_in_one_frame():
    connection = RemoteXPCConnection(("localhost", 0))
    writer = FakeWriter()
    connection._writer = cast(asyncio.StreamWriter, writer)

    await connection.send_request({"command": "getpreflightinfo"})

    assert len(writer.writes) == 1 and writer.drain_calls == 1


@pytest.mark.asyncio
async def test_send_request_uses_odd_message_ids_after_the_handshake_message():
    connection = RemoteXPCConnection(("localhost", 0))
    writer = FakeWriter()
    connection._writer = cast(asyncio.StreamWriter, writer)

    for wanting_reply in (False, True, False, True):
        await connection.send_request({"command": "x"}, wanting_reply=wanting_reply)

    message_ids = [XpcWrapper.parse(w[FRAME_HEADER_SIZE:]).message_id for w in writer.writes]
    assert message_ids == [0, 1, 3, 5]


@pytest.mark.asyncio
async def test_connect_reports_an_unanswered_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    class SilentReader:
        async def readexactly(self, size: int) -> bytes:
            await asyncio.sleep(3600)
            return b""

    class ClosableWriter(FakeWriter):
        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def open_connection(host: str, port: int) -> tuple[Any, Any]:
        return SilentReader(), ClosableWriter()

    monkeypatch.setattr(remotexpc, "FIRST_REPLY_TIMEOUT", 0.05)
    connection = RemoteXPCConnection(("fd00::1", 1234), open_connection=open_connection)

    # Still a timeout error for callers that probe services by catching one.
    with pytest.raises(asyncio.TimeoutError) as error:
        await connection.connect()

    assert isinstance(error.value, RemoteXPCHandshakeTimeoutError)
    assert "fd00::1:1234 did not answer the RemoteXPC handshake" in str(error.value)


def _handshake_uuids(writer: FakeWriter) -> list[uuid.UUID]:
    return [
        decode_xpc_object(cast(XpcObject, XpcWrapper.parse(frame.data).payload))["UUID"]
        for frame in _parse_written_frames(writer)
    ]


@pytest.mark.asyncio
async def test_device_handshake_identifies_as_the_given_peer():
    connection, writer = _sending_connection()
    peer_uuid = uuid.UUID("c9a6e86b-beea-45ea-9332-86f295536960")

    await connection.send_device_handshake(peer_uuid)

    assert _handshake_uuids(writer) == [peer_uuid]


@pytest.fixture(autouse=True)
def _fresh_handshake_uuids():
    remotexpc.default_handshake_uuid.cache_clear()
    remotexpc.remoted_handshake_uuid.cache_clear()
    yield
    remotexpc.default_handshake_uuid.cache_clear()
    remotexpc.remoted_handshake_uuid.cache_clear()


@pytest.mark.asyncio
async def test_device_handshake_defaults_to_one_stable_host_identity():
    # iOS 27.2+ remembers the last RSD peer's UUID per tunnel and drops every advertised service
    # listener when the next peer's differs, so separate connections (and separate processes) must
    # all present the same one (#1966).
    first, first_writer = _sending_connection()
    second, second_writer = _sending_connection()

    await first.send_device_handshake()
    await second.send_device_handshake()

    assert _handshake_uuids(first_writer) == _handshake_uuids(second_writer) == [uuid.UUID(generate_host_id())]


@pytest.mark.asyncio
async def test_device_handshake_never_identifies_as_the_host_remoted(monkeypatch: pytest.MonkeyPatch):
    # From iOS 26.2 a handshake presenting remoted's UUID evicts remoted's own RSD connection, and
    # remoted's redial then resets ours (#1994). Only the native tunnel passes remoted's explicitly.
    def host_remoted_uuid() -> uuid.UUID:
        raise AssertionError("the default handshake must not ask for remoted's UUID")

    monkeypatch.setattr(remotexpc, "host_remoted_uuid", host_remoted_uuid)
    connection, writer = _sending_connection()

    await connection.send_device_handshake()

    assert _handshake_uuids(writer) == [uuid.UUID(generate_host_id())]


_HOST_REMOTED_UUID = uuid.UUID("c9a6e86b-beea-45ea-9332-86f295536960")

# Head of a real ``remotectl dumpstate``: the host's own identity, then each attached device.
_REMOTECTL_DUMPSTATE = """Local device
\tUUID: C9A6E86B-BEEA-45EA-9332-86F295536960
\tMessaging Protocol Version: 7
\tProduct Type: Mac16,11
\tServices:
\t\tcom.apple.osanalytics.logRelay
Found ncm-1 (ncm-device)
\tState: connected (connectable)
\tUUID: 687A4CFC-3E83-4CCD-B7E2-C9223A3782DD
\tProduct Type: iPhone18,4
"""


def test_parse_remotectl_local_uuid_takes_the_host_not_an_attached_device() -> None:
    assert remotexpc.parse_remotectl_local_uuid(_REMOTECTL_DUMPSTATE) == _HOST_REMOTED_UUID


@pytest.mark.parametrize("text", ["", "Found ncm-1 (ncm-device)\n\tUUID: 687A4CFC-3E83-4CCD-B7E2-C9223A3782DD\n"])
def test_parse_remotectl_local_uuid_is_none_without_a_local_device(text: str) -> None:
    assert remotexpc.parse_remotectl_local_uuid(text) is None


def test_remoted_handshake_uuid_asks_remotectl_once(monkeypatch: pytest.MonkeyPatch) -> None:
    # remotectl cannot answer while remoted is suspended (get_rsds, tunneld), so the identity is
    # resolved once and later handshakes must not ask again.
    calls: list[None] = []

    def host_remoted_uuid() -> uuid.UUID:
        calls.append(None)
        return _HOST_REMOTED_UUID

    monkeypatch.setattr(remotexpc, "_IS_DARWIN", True)
    monkeypatch.setattr(remotexpc, "host_remoted_uuid", host_remoted_uuid)

    assert remotexpc.remoted_handshake_uuid() == remotexpc.remoted_handshake_uuid() == _HOST_REMOTED_UUID
    assert len(calls) == 1


def test_remoted_handshake_uuid_is_none_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    def host_remoted_uuid() -> uuid.UUID:
        raise AssertionError("remotectl only exists on macOS")

    monkeypatch.setattr(remotexpc, "_IS_DARWIN", False)
    monkeypatch.setattr(remotexpc, "host_remoted_uuid", host_remoted_uuid)

    assert remotexpc.remoted_handshake_uuid() is None


def test_host_remoted_uuid_is_none_when_remotectl_is_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remotexpc, "_REMOTECTL_PATH", "/nonexistent/remotectl")
    assert remotexpc.host_remoted_uuid() is None


def test_host_remoted_uuid_reads_this_hosts_remoted() -> None:
    if platform.system() != "Darwin":
        pytest.skip("remotectl is macOS-only")
    assert isinstance(remotexpc.host_remoted_uuid(), uuid.UUID)


@pytest.mark.asyncio
@pytest.mark.parametrize("received", [b"", b"\x00\x00\x01"], ids=["between-frames", "mid-header"])
async def test_peer_closing_the_connection_is_a_terminated_connection(received: bytes):
    # Regression (#1991): EOF while reading a frame header escaped as a bare IncompleteReadError --
    # an EOFError, which the CLI reports as nothing but "Aborted." -- unlike EOF in a frame body
    connection = RemoteXPCConnection(("localhost", 0))
    reader = asyncio.StreamReader()
    reader.feed_data(received)
    reader.feed_eof()
    connection._reader = reader

    with pytest.raises(ConnectionTerminatedError):
        await connection.receive_response()


async def _loopback_connection() -> tuple[RemoteXPCConnection, socket.socket]:
    with socket.create_server(("127.0.0.1", 0)) as server:
        host = socket.create_connection(server.getsockname())
        device, _ = server.accept()
    connection = RemoteXPCConnection(("127.0.0.1", 0))
    connection._reader, connection._writer = await asyncio.open_connection(sock=host)
    return connection, device


@pytest.mark.asyncio
@pytest.mark.parametrize("reset", [True, False], ids=["reset", "close"])
async def test_receive_after_peer_dropped_raises_connection_terminated(reset: bool):
    connection, device = await _loopback_connection()
    try:
        if reset:
            # Linger 0 makes close() send RST instead of FIN, like a device dropping off the bus.
            device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        device.close()
        with pytest.raises(ConnectionTerminatedError):
            await connection.receive_response()
    finally:
        device.close()
        await connection.close()


@pytest.mark.asyncio
async def test_send_after_peer_reset_raises_connection_terminated():
    # asyncio only notices the RST once it reads it, so the first sends may still be accepted; keep
    # sending until one fails.
    connection, device = await _loopback_connection()
    try:
        device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        device.close()
        with pytest.raises(ConnectionTerminatedError):
            for _ in range(200):
                await connection.send_request({"Command": "Ping"})
                await asyncio.sleep(0.01)
    finally:
        device.close()
        await connection.close()


# Golden frame pinning the RemoteXPC wire encoding.
_GOLDEN_XPC_WRAPPER = bytes.fromhex(
    "920bb02901010100f0000000000000000500000000000000423713420500000000f00000e00000000a000000"
    "73000000009000000700000068c3a96c6c6f00006200000000200000010000006e0000000010000069000000"
    "00300000feffffffffffffff750000000040000003000000000000006400000000500000000000000000f83f"
    "6461746100000000008000000300000001020300757569640000000000a00000000000000000000000000000"
    "000000016c00000000e000001c0000000200000000f00000040000000000000000e000000400000000000000"
    "6674000000a00100040000000000000000f00000140000000100000073000000004000000900000000000000"
)
_GOLDEN_XPC_VALUE = {
    "s": "héllo",
    "b": True,
    "n": None,
    "i": XpcInt64Type(-2),
    "u": XpcUInt64Type(3),
    "d": 1.5,
    "data": b"\x01\x02\x03",
    "uuid": uuid.UUID(int=1),
    "l": [{}, []],
    "ft": FileTransferType(transfer_size=9, transfer_id=4),
}


def test_xpc_wrapper_wire_format():
    assert create_xpc_wrapper(_GOLDEN_XPC_VALUE, message_id=5, wanting_reply=True) == _GOLDEN_XPC_WRAPPER

    wrapper = XpcWrapper.parse(_GOLDEN_XPC_WRAPPER)
    assert wrapper.flags == XpcFlags.ALWAYS_SET | XpcFlags.DATA_PRESENT | XpcFlags.WANTING_REPLY
    assert wrapper.message_id == 5
    assert wrapper.payload is not None
    assert wrapper.build() == _GOLDEN_XPC_WRAPPER
    decoded = decode_xpc_object(wrapper.payload)
    # a decoded file transfer carries no transfer_id; its stream is derived positionally
    assert decoded == {**_GOLDEN_XPC_VALUE, "ft": FileTransferType(transfer_size=9)}
    assert type(decoded["i"]) is XpcInt64Type and type(decoded["u"]) is XpcUInt64Type


def test_xpc_wrapper_keeps_unnamed_flag_bits():
    frame = XpcWrapper(flags=0x80000201, message_id=9).build()
    wrapper = XpcWrapper.parse(frame)
    assert wrapper.flags == 0x80000201 and isinstance(wrapper.flags, XpcFlags)
    assert wrapper.message_id == 9 and wrapper.payload is None
    assert wrapper.build() == frame


def test_xpc_wrapper_parse_errors():
    for cut in range(len(_GOLDEN_XPC_WRAPPER)):
        with pytest.raises(TruncatedDataError):
            XpcWrapper.parse(_GOLDEN_XPC_WRAPPER[:cut])
    with pytest.raises(UnexpectedConstantError):
        XpcWrapper.parse(b"\x00\x00\x00\x00")
    # an unparsable payload is dropped, not raised
    corrupt = bytearray(_GOLDEN_XPC_WRAPPER)
    corrupt[24] ^= 0xFF
    assert XpcWrapper.parse(bytes(corrupt)).payload is None


def test_xpc_object_parses_uncommon_types():
    def obj(type_: int, body: bytes = b"") -> bytes:
        return struct.pack("<I", type_) + body

    assert XpcObject.parse(obj(XpcMessageType.DATE, struct.pack("<Q", 7))) == XpcObject(XpcMessageType.DATE, 7)
    assert XpcObject.parse(obj(XpcMessageType.FD, struct.pack("<I", 3))) == XpcObject(XpcMessageType.FD, 3)
    shmem = XpcObject.parse(obj(XpcMessageType.SHMEM, struct.pack("<II", 4096, 0)))
    assert shmem == XpcObject(XpcMessageType.SHMEM, 4096)
    assert XpcObject.parse(obj(0x1234)) == XpcObject(0x1234, None)  # unknown types carry no body
    with pytest.raises(BinaryParseError):
        XpcObject.parse(obj(XpcMessageType.POINTER))
    with pytest.raises(BinaryParseError):  # non-UTF-8 dictionary key
        XpcObject.parse(obj(XpcMessageType.DICTIONARY, struct.pack("<II", 8, 1) + b"\xff\0\0\0"))


def test_xpc_object_build_errors():
    with pytest.raises(BinaryBuildError):
        XpcObject(XpcMessageType.UUID, b"abc").build()
    with pytest.raises(BinaryBuildError):
        XpcObject(XpcMessageType.INT64, 2**64).build()
    with pytest.raises(BinaryBuildError):  # nested failures surface the same way
        XpcObject(XpcMessageType.ARRAY, [XpcObject(XpcMessageType.UINT64, -1)]).build()


def test_deeply_nested_payload_is_dropped_not_a_recursion_error():
    # 5000 nested single-element arrays: a corrupt or hostile peer, not a real message.
    payload = struct.pack("<I", XpcMessageType.NULL)
    for _ in range(5000):
        body = struct.pack("<I", 1) + payload
        payload = struct.pack("<II", XpcMessageType.ARRAY, len(body)) + body
    frame = XpcWrapper(payload=XpcObject(XpcMessageType.NULL)).build()
    frame = frame[:-4] + payload  # replace the NULL payload object with the nested one
    frame = frame[:8] + struct.pack("<Q", len(frame) - 24) + frame[16:]
    assert XpcWrapper.parse(frame).payload is None


def _replaying_connection(chunks: list[bytes]) -> RemoteXPCConnection:
    frames = iter(chunks)

    async def receive_next_data_frame(self):
        return DataFrame(1, data=next(frames))

    connection = RemoteXPCConnection(("localhost", 0))
    connection._receive_next_data_frame = MethodType(receive_next_data_frame, connection)
    return connection


@pytest.mark.asyncio
async def test_receive_response_reassembles_split_frames_and_skips_empty_replies():
    reply = create_xpc_wrapper({"answer": "yes"})
    chunks = [create_xpc_wrapper({}), XpcWrapper().build()] + [reply[i : i + 7] for i in range(0, len(reply), 7)]
    assert await _replaying_connection(chunks).receive_response() == {"answer": "yes"}


@pytest.mark.asyncio
async def test_receive_response_rejects_a_non_dictionary_reply():
    with pytest.raises(ProtocolError):
        frame = XpcWrapper(payload=XpcObject(XpcMessageType.STRING, "not a dict")).build()
        await _replaying_connection([frame]).receive_response()


@pytest.mark.parametrize("value", [{"key": "a\0b"}, {"a\0b": "value"}])
def test_xpc_rejects_embedded_nul(value: dict[str, Any]):
    with pytest.raises(BinaryBuildError):
        create_xpc_wrapper(value)


def test_xpc_dates_are_signed():
    before_1970 = XpcObject(XpcMessageType.DATE, -1_000_000_000)  # one second before the epoch
    assert XpcObject.parse(before_1970.build()) == before_1970
    assert decode_xpc_object(before_1970) == datetime.fromtimestamp(0) - timedelta(seconds=1)


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="needs time.tzset to pin the local time zone")
def test_xpc_dates_before_1970_without_platform_support(monkeypatch: pytest.MonkeyPatch) -> None:
    # Windows' fromtimestamp() rejects negative timestamps; the fallback must still apply daylight saving.
    real_datetime = xpc_message.datetime

    class WindowsDatetime(real_datetime):
        @classmethod
        def fromtimestamp(cls, t: float, tz: Any = None) -> Any:
            if t < 0:
                raise OSError(22, "Invalid argument")
            return real_datetime.fromtimestamp(t, tz)

    def xpc_date(utc: datetime) -> XpcObject:
        return XpcObject(XpcMessageType.DATE, int((utc - datetime(1970, 1, 1)).total_seconds()) * 1_000_000_000)

    monkeypatch.setattr(xpc_message, "datetime", WindowsDatetime)
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    try:
        assert decode_xpc_object(xpc_date(datetime(1960, 1, 1, 12))) == datetime(1960, 1, 1, 7)  # EST
        assert decode_xpc_object(xpc_date(datetime(1960, 7, 1, 12))) == datetime(1960, 7, 1, 8)  # EDT
        assert decode_xpc_object(XpcObject(XpcMessageType.DATE, -(2**63))).year == 1677  # the earliest int64 date
    finally:
        monkeypatch.undo()
        time.tzset()


def test_padding_is_relative_to_each_object_not_the_container() -> None:
    # A dictionary whose declared length (5) is not a multiple of 4 leaves the next object unaligned in the array.
    items = (
        struct.pack("<III", XpcMessageType.DICTIONARY, 5, 0)
        + b"\0"
        + struct.pack("<II", XpcMessageType.STRING, 2)
        + b"a\0\0\0"
        + struct.pack("<I", XpcMessageType.NULL)
    )
    raw = struct.pack("<III", XpcMessageType.ARRAY, 4 + len(items), 3) + items
    parsed = XpcObject.parse(raw)
    assert [item.type for item in parsed.data] == [
        XpcMessageType.DICTIONARY,
        XpcMessageType.STRING,
        XpcMessageType.NULL,
    ]
    assert parsed.data[1].data == "a"


_REMOTECTL_DUMPSTATE_WITH_LINKS = (
    _REMOTECTL_DUMPSTATE
    + """\tProperties: {
\t\tInterfaceName => anpi0
\t}
Found coredevice-9 (coredevice-device)
\tState: connected (connectable)
\tProperties: {
\t\tHWModel => N104AP
\t\tInterfaceName => utun4
\t}
"""
)


def test_parse_remotectl_interfaces_lists_every_link() -> None:
    assert remotexpc.parse_remotectl_interfaces(_REMOTECTL_DUMPSTATE_WITH_LINKS) == {"anpi0", "utun4"}
    assert remotexpc.parse_remotectl_interfaces(_REMOTECTL_DUMPSTATE) == set()


def _fake_links(monkeypatch: pytest.MonkeyPatch, routed_interface: Optional[str]) -> list[str]:
    routed: list[str] = []

    def route_interface(host: str) -> Optional[str]:
        routed.append(host)
        return routed_interface

    monkeypatch.setattr(remotexpc, "_IS_DARWIN", True)
    monkeypatch.setattr(remotexpc, "route_interface", route_interface)
    monkeypatch.setattr(remotexpc, "_remotectl_dumpstate", lambda: _REMOTECTL_DUMPSTATE_WITH_LINKS)
    monkeypatch.setattr(remotexpc, "host_remoted_uuid", lambda: _HOST_REMOTED_UUID)
    return routed


def test_rsd_handshake_uuid_is_remoteds_on_remoteds_tunnel(monkeypatch: pytest.MonkeyPatch) -> None:
    # `remote start-tunnel --native` prints an address on remoted's tunnel; the host id there makes
    # iOS 27.2+ close every service listener.
    routed = _fake_links(monkeypatch, "utun4")

    assert remotexpc.rsd_handshake_uuid("fdd4:4e11:4789::1") == _HOST_REMOTED_UUID
    assert routed == ["fdd4:4e11:4789::1"]


@pytest.mark.parametrize("routed_interface", ["utun7", None], ids=["own-tunnel", "no-route"])
def test_rsd_handshake_uuid_is_the_default_off_remoteds_links(
    monkeypatch: pytest.MonkeyPatch, routed_interface: Optional[str]
) -> None:
    _fake_links(monkeypatch, routed_interface)
    assert remotexpc.rsd_handshake_uuid("fd7b:e5b:6f53::1") is None


def test_rsd_handshake_uuid_is_the_default_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    def route_interface(host: str) -> Optional[str]:
        raise AssertionError("route lookup is macOS-only")

    monkeypatch.setattr(remotexpc, "_IS_DARWIN", False)
    monkeypatch.setattr(remotexpc, "route_interface", route_interface)

    assert remotexpc.rsd_handshake_uuid("fd7b:e5b:6f53::1") is None


def test_route_interface_is_none_when_route_is_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remotexpc, "_ROUTE_PATH", "/nonexistent/route")
    assert remotexpc.route_interface("fd7b:e5b:6f53::1") is None
