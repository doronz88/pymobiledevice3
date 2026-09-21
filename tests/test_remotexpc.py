import asyncio
import platform
import uuid
from types import MethodType
from typing import Any, cast

import pytest
from hyperframe.frame import DataFrame, Frame, HeadersFrame, RstStreamFrame, SettingsFrame, WindowUpdateFrame

from pymobiledevice3.exceptions import StreamClosedError
from pymobiledevice3.pair_records import generate_host_id
from pymobiledevice3.remote import remotexpc
from pymobiledevice3.remote.remotexpc import (
    DEFAULT_PEER_WINDOW_SIZE,
    DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
    DEFAULT_WIN_SIZE_INCR,
    FRAME_HEADER_SIZE,
    MAX_OUTBOUND_FRAME_SIZE,
    WINDOW_UPDATE_THRESHOLD,
    RemoteXPCConnection,
)
from pymobiledevice3.remote.xpc_message import XpcWrapper, decode_xpc_object


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
    assert XpcWrapper.parse(reassembled).message.message_id == 0
    assert connection.next_message_id[1] == 1


@pytest.mark.asyncio
async def test_send_request_keeps_small_messages_in_one_frame():
    connection = RemoteXPCConnection(("localhost", 0))
    writer = FakeWriter()
    connection._writer = cast(asyncio.StreamWriter, writer)

    await connection.send_request({"command": "getpreflightinfo"})

    assert len(writer.writes) == 1 and writer.drain_calls == 1


def _handshake_uuids(writer: FakeWriter) -> list[uuid.UUID]:
    return [
        decode_xpc_object(XpcWrapper.parse(frame.data).message.payload.obj)["UUID"]
        for frame in _parse_written_frames(writer)
    ]


@pytest.mark.asyncio
async def test_device_handshake_identifies_as_the_given_peer():
    connection, writer = _sending_connection()
    peer_uuid = uuid.UUID("c9a6e86b-beea-45ea-9332-86f295536960")

    await connection.send_device_handshake(peer_uuid)

    assert _handshake_uuids(writer) == [peer_uuid]


@pytest.fixture(autouse=True)
def _fresh_default_handshake_uuid():
    remotexpc.default_handshake_uuid.cache_clear()
    yield
    remotexpc.default_handshake_uuid.cache_clear()


@pytest.mark.asyncio
async def test_device_handshake_defaults_to_one_stable_host_identity(monkeypatch: pytest.MonkeyPatch):
    # iOS 27.2+ remembers the last RSD peer's UUID per tunnel and drops every advertised service
    # listener when the next peer's differs, so separate connections (and separate processes) must
    # all present the same one (#1966).
    monkeypatch.setattr(remotexpc, "_IS_DARWIN", False)
    first, first_writer = _sending_connection()
    second, second_writer = _sending_connection()

    await first.send_device_handshake()
    await second.send_device_handshake()

    assert _handshake_uuids(first_writer) == _handshake_uuids(second_writer) == [uuid.UUID(generate_host_id())]


@pytest.mark.asyncio
async def test_device_handshake_defaults_to_the_host_remoted_on_macos(monkeypatch: pytest.MonkeyPatch):
    # On macOS the endpoint may be shared with remoted (the native tunnel, the NCM interface), and
    # remoted keeps reconnecting with its own UUID -- so that is the only identity that holds.
    monkeypatch.setattr(remotexpc, "_IS_DARWIN", True)
    monkeypatch.setattr(remotexpc, "host_remoted_uuid", lambda: _HOST_REMOTED_UUID)
    connection, writer = _sending_connection()

    await connection.send_device_handshake()

    assert _handshake_uuids(writer) == [_HOST_REMOTED_UUID]


@pytest.mark.asyncio
async def test_device_handshake_falls_back_to_the_host_id_without_remotectl(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(remotexpc, "_IS_DARWIN", True)
    monkeypatch.setattr(remotexpc, "host_remoted_uuid", lambda: None)
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


def test_default_handshake_uuid_asks_remotectl_once(monkeypatch: pytest.MonkeyPatch) -> None:
    # remotectl cannot answer while remoted is suspended (get_rsds, tunneld), so the identity is
    # resolved once and later handshakes must not ask again.
    calls: list[None] = []

    def host_remoted_uuid() -> uuid.UUID:
        calls.append(None)
        return _HOST_REMOTED_UUID

    monkeypatch.setattr(remotexpc, "_IS_DARWIN", True)
    monkeypatch.setattr(remotexpc, "host_remoted_uuid", host_remoted_uuid)

    assert remotexpc.default_handshake_uuid() == remotexpc.default_handshake_uuid() == _HOST_REMOTED_UUID
    assert len(calls) == 1


def test_host_remoted_uuid_is_none_when_remotectl_is_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remotexpc, "_REMOTECTL_PATH", "/nonexistent/remotectl")
    assert remotexpc.host_remoted_uuid() is None


def test_host_remoted_uuid_reads_this_hosts_remoted() -> None:
    if platform.system() != "Darwin":
        pytest.skip("remotectl is macOS-only")
    assert isinstance(remotexpc.host_remoted_uuid(), uuid.UUID)
