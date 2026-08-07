import asyncio
from types import MethodType
from typing import Any, cast

import pytest
from hyperframe.frame import DataFrame, Frame, HeadersFrame, RstStreamFrame, SettingsFrame, WindowUpdateFrame

from pymobiledevice3.exceptions import StreamClosedError
from pymobiledevice3.remote.remotexpc import (
    DEFAULT_PEER_WINDOW_SIZE,
    DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
    DEFAULT_WIN_SIZE_INCR,
    FRAME_HEADER_SIZE,
    MAX_OUTBOUND_FRAME_SIZE,
    WINDOW_UPDATE_THRESHOLD,
    RemoteXPCConnection,
)
from pymobiledevice3.remote.xpc_message import XpcWrapper


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
    assert preamble.message.message_id == 7
    assert preamble.flags.FILE_TX_STREAM_REQUEST


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
