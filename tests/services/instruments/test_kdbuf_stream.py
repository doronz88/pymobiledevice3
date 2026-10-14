import queue
import struct
from typing import Any

from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import STACKSHOT_HEADER, KdBufStream

KD_BUF_SIZE = 64


def kd_buf(timestamp: int) -> bytes:
    return struct.pack("<Q", timestamp).ljust(KD_BUF_SIZE, b"\x00")


def make_stream(*chunks: Any) -> KdBufStream:
    chunk_queue: queue.Queue[Any] = queue.Queue()
    for chunk in chunks:
        chunk_queue.put(chunk)
    chunk_queue.put(None)
    return KdBufStream(chunk_queue)


def read_timestamps(stream: KdBufStream) -> list[int]:
    timestamps = []
    while buf := stream.read(KD_BUF_SIZE):
        timestamps.append(struct.unpack_from("<Q", buf)[0])
    return timestamps


def test_read_skips_bplist_and_stackshot_chunks() -> None:
    stream = make_stream(b"bplist00...", STACKSHOT_HEADER + b"\x00" * 60, kd_buf(1) + kd_buf(2))
    assert read_timestamps(stream) == [1, 2]


def test_read_restarts_at_next_chunk_boundary() -> None:
    # The header chunk ends in slack that is not a whole record; the next chunk must start a fresh record.
    stream = make_stream(kd_buf(1) + b"\xff" * 32, kd_buf(2) + kd_buf(3))
    assert read_timestamps(stream) == [1, 2, 3]
