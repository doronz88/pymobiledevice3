import asyncio
from types import MethodType
from typing import cast

import pytest
from hyperframe.frame import DataFrame

from pymobiledevice3.remote.remotexpc import (
    DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE,
    DEFAULT_WIN_SIZE_INCR,
    WINDOW_UPDATE_THRESHOLD,
    RemoteXPCConnection,
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
