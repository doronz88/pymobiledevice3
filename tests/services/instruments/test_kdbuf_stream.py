import queue
import struct
import time
from datetime import timezone
from typing import Any

import pytest
from pykdebugparser.kd_buf_parser import RAW_VERSION2_BYTES, V2_EVENTS_ALIGNMENT
from pykdebugparser.pykdebugparser import PyKdebugParser

from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import (
    KD_BUF_SIZE,
    STACKSHOT_HEADER,
    KdBufStream,
)

BSC_GETPID = 0x040C0050
DBG_FUNC_START = 1
DBG_FUNC_END = 2
# kd_header_v2 with an empty threadmap, padded to 4 KiB with stale non-zero bytes, like the device's header chunk.
HEADER_CHUNK = (RAW_VERSION2_BYTES + struct.pack("<I8x4xIQ256x", 0, 1, 1)).ljust(V2_EVENTS_ALIGNMENT, b"\xff")


# Event clock = host monotonic clock + a day: a constant offset the stream must absorb anyway, which keeps
# timestamps positive on a freshly booted host.
CLOCK_OFFSET = 86400


def ms_ago(seconds: float) -> int:
    """A kd_buf timestamp (in ms, see `event_seconds`) for an event that happened `seconds` ago."""
    return int((time.monotonic() + CLOCK_OFFSET - seconds) * 1000)


def event_seconds(timestamp: int) -> float:
    return timestamp / 1000


def kd_buf(timestamp: int, tid: int = 0, debugid: int = 0) -> bytes:
    return struct.pack("<Q32sQIIQ", timestamp, b"\x00" * 32, tid, debugid, 0, 0)


def make_stream(*chunks: Any, **kwargs: Any) -> KdBufStream:
    chunk_queue: queue.Queue[Any] = queue.Queue()
    for chunk in chunks:
        chunk_queue.put(chunk)
    if chunks[-1:] != (None,) and not isinstance(chunks[-1], Exception):
        chunk_queue.put(None)
    if "max_lag" in kwargs:
        kwargs.setdefault("event_seconds", event_seconds)
    return KdBufStream(chunk_queue, **kwargs)


def read_timestamps(stream: KdBufStream) -> list[int]:
    timestamps = []
    while buf := stream.read(KD_BUF_SIZE):
        timestamps.append(struct.unpack_from("<Q", buf)[0])
    return timestamps


def test_read_skips_bplist_and_stackshot_chunks() -> None:
    stream = make_stream(b"bplist00...", STACKSHOT_HEADER + b"\x00" * 60, b"", kd_buf(1) + kd_buf(2))
    assert read_timestamps(stream) == [1, 2]


def test_read_restarts_at_next_chunk_boundary() -> None:
    # A chunk that ends in a partial record must not misalign the next chunk's records.
    stream = make_stream(kd_buf(1) + b"\xff" * 32, kd_buf(2) + kd_buf(3))
    assert read_timestamps(stream) == [1, 2, 3]


def test_without_max_lag_nothing_is_skipped() -> None:
    old = [ms_ago(60 - i) for i in range(3)]
    stream = make_stream(kd_buf(0), kd_buf(ms_ago(0)), *(kd_buf(ts) for ts in old))
    assert read_timestamps(stream)[2:] == old
    assert stream.skipped_events == 0


def test_skips_chunks_that_fell_behind_and_reports_once_per_catch_up() -> None:
    skips: list[tuple[int, float]] = []
    fresh, stale = ms_ago(0), ms_ago(10)
    stream = make_stream(
        kd_buf(ms_ago(60)),  # the header chunk is never checked, however old it looks
        kd_buf(fresh),
        kd_buf(stale) + kd_buf(stale),
        b"bplist00...",
        kd_buf(stale),
        kd_buf(fresh + 1),
        max_lag=2.0,
        on_skip=lambda events, lag: skips.append((events, lag)),
    )
    assert read_timestamps(stream)[1:] == [fresh, fresh + 1]
    assert stream.skipped_events == 3
    assert len(skips) == 1
    assert skips[0][0] == 3 and skips[0][1] > 2.0


def test_a_constant_clock_offset_is_not_lag() -> None:
    # Every event looks an hour old (device clock behind the host's): only growth in lag counts.
    # (ms_ago adds CLOCK_OFFSET, so these timestamps stay positive however long the host has been up.)
    hour = 3600
    stamps = [ms_ago(hour), ms_ago(hour) + 1, ms_ago(hour) + 2]
    stream = make_stream(kd_buf(0), *(kd_buf(ts) for ts in stamps), max_lag=2.0)
    assert read_timestamps(stream)[1:] == stamps
    assert stream.skipped_events == 0


def test_end_of_stream_and_errors_still_arrive_while_skipping() -> None:
    stream = make_stream(kd_buf(0), kd_buf(ms_ago(0)), kd_buf(ms_ago(10)), None, max_lag=2.0)
    assert len(read_timestamps(stream)) == 2

    stream = make_stream(kd_buf(0), kd_buf(ms_ago(0)), kd_buf(ms_ago(10)), ConnectionError("gone"), max_lag=2.0)
    read_timestamps_until_error = [stream.read(KD_BUF_SIZE), stream.read(KD_BUF_SIZE)]
    assert all(read_timestamps_until_error)
    with pytest.raises(ConnectionError):
        stream.read(KD_BUF_SIZE)


def test_reads_after_the_end_of_stream_do_not_wait_for_more_chunks() -> None:
    stream = make_stream(kd_buf(1))
    assert read_timestamps(stream) == [1]
    # A chunk queued after the end must be neither read nor waited for (an empty queue would block forever).
    stream.chunk_queue.put(kd_buf(2))
    assert stream.read(KD_BUF_SIZE) == b""
    assert stream.chunk_queue.qsize() == 1


def test_max_lag_needs_a_clock() -> None:
    with pytest.raises(ValueError):
        KdBufStream(queue.Queue(), max_lag=2.0)


def test_traces_survive_skipping_unmatched_start_and_end() -> None:
    now, stale = ms_ago(0), ms_ago(10)
    stream = make_stream(
        HEADER_CHUNK,
        kd_buf(now, tid=1, debugid=BSC_GETPID | DBG_FUNC_START)
        + kd_buf(now, tid=2, debugid=BSC_GETPID | DBG_FUNC_START),
        kd_buf(stale, tid=1, debugid=BSC_GETPID | DBG_FUNC_END),
        # END whose START was skipped, a whole syscall, then a START whose END never comes.
        kd_buf(now, tid=2, debugid=BSC_GETPID | DBG_FUNC_END)
        + kd_buf(now, tid=3, debugid=BSC_GETPID | DBG_FUNC_START)
        + kd_buf(now, tid=3, debugid=BSC_GETPID | DBG_FUNC_END)
        + kd_buf(now, tid=4, debugid=BSC_GETPID | DBG_FUNC_START),
        max_lag=2.0,
    )
    parser: Any = PyKdebugParser()
    parser.numer = 1
    parser.denom = 1
    parser.mach_absolute_time = 0
    parser.usecs_since_epoch = 0
    parser.timezone = timezone.utc
    parser.show_tid = True
    parser.color = False

    traces = list(parser.formatted_traces(stream, {BSC_GETPID: "BSC_getpid"}))

    assert stream.skipped_events == 1
    # tid 1's END was skipped; tid 2 and tid 3 complete (the process column reads "Error: tid N" without a threadmap).
    assert [trace.split("tid ")[1][0] for trace in traces] == ["2", "3"]
    assert all("getpid()" in trace for trace in traces)
