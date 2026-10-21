import struct
import uuid
from typing import Any, cast

import pytest
from bpylist2 import archiver

from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.exceptions import DvtException, ExtractingStackshotError
from pymobiledevice3.services.dvt.instruments import core_profile_session_tap
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import (
    CoreProfileSessionTap,
)
from pymobiledevice3.services.dvt.instruments.tap import TapMessageChannel


@pytest.mark.asyncio
async def test_stackshot(dvt) -> None:
    """
    Test getting stackshot.
    """
    time_config = await CoreProfileSessionTap.get_time_config(dvt)
    async with CoreProfileSessionTap(dvt, time_config) as tap:
        data = await tap.get_stackshot()

    assert "Darwin Kernel" in data["osversion"]
    # Constant kernel task data.
    assert data["task_snapshots"][0]["task_snapshot"]["ts_pid"] == 0
    assert data["task_snapshots"][0]["task_snapshot"]["ts_p_comm"] == "kernel_task"


@pytest.mark.asyncio
async def test_stackshot_raises_on_start_failure_notice() -> None:
    class FakeChannel:
        async def receive_message(self):
            return archiver.archive({
                "k": 8,
                "status": 2147483648,
                "notice": "Failed to start the recording: _lockKPerf: could not lock kperf.",
            })

    tap = CoreProfileSessionTap(cast(DtxServiceProvider, None), {})
    tap.channel = cast(TapMessageChannel, FakeChannel())

    with pytest.raises(DvtException, match="Failed to start the recording"):
        await tap.get_stackshot(timeout=0.1)


@pytest.mark.asyncio
async def test_stackshot_times_out_without_stackshot_data() -> None:
    class FakeChannel:
        async def receive_message(self):
            return archiver.archive({"k": 7, "sm": {}})

    tap = CoreProfileSessionTap(cast(DtxServiceProvider, None), {})
    tap.channel = cast(TapMessageChannel, FakeChannel())

    with pytest.raises(ExtractingStackshotError, match="Timed out waiting for the device to send a stackshot"):
        await tap.get_stackshot(timeout=0.01)


def test_tap_samples_callstacks_only_when_asked() -> None:
    def trigger(**kwargs: Any) -> dict[str, Any]:
        tap = CoreProfileSessionTap(cast(DtxServiceProvider, None), {}, {0x040C0000}, **kwargs)
        assert tap._config["ur"] == 100
        return tap._config["tc"][0]

    sampling = trigger()
    assert sampling["ta"] == [[3], [0], [2], [1, 1, 0]] and sampling["csd"] == 128
    plain = trigger(sample_callstacks=False)
    assert plain["ta"] == [[0], [2]] and "csd" not in plain
    assert plain["kdf2"] == {0x040C0000}


def _kcdata_item(type_: int, payload: bytes = b"", flags: int = 0) -> bytes:
    return struct.pack("<IIQ", type_, len(payload), flags) + payload


def _synthetic_stackshot() -> bytes:
    image_uuid = uuid.UUID("11111111-2222-3333-4444-555555555555")
    task = struct.pack("<7Q8I", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0) + b"kernel_task".ljust(32, b"\0")
    thread_groups = struct.pack("<Q16sQ", 5, b"tg-v2", 6) * 2
    return b"".join([
        _kcdata_item(0x59A25807),  # KCDATA_BUFFER_BEGIN_STACKSHOT
        _kcdata_item(0x3, b"stackshot_flags".ljust(32, b"\0") + struct.pack("<Q", 0x1234)),  # UINT64_DESC
        _kcdata_item(0x90F, b"Darwin Kernel\0"),  # OSVERSION
        _kcdata_item(0x32, struct.pack("<II", 125, 3)),  # TIMEBASE
        _kcdata_item(0x908, struct.pack("<Q", 0x180000000) + image_uuid.bytes + struct.pack("<Q", 0x190000000)),
        _kcdata_item(0x20, thread_groups, flags=(0x91E << 32) | 2),  # ARRAY_PAD0 of THREAD_GROUP_SNAPSHOT (v2)
        _kcdata_item(0x13, struct.pack("<I", 0x903), flags=0),  # CONTAINER_BEGIN task 0
        _kcdata_item(0x905, task),  # TASK_SNAPSHOT
        _kcdata_item(0x24, struct.pack("<QQ", 0x1000, 0x2000) + bytes(4), flags=(0x916 << 32) | 2),  # ARRAY_PAD4 LR64
        _kcdata_item(0x7777, b"opaque"),  # unknown type: skipped
        _kcdata_item(0x14),  # CONTAINER_END
        _kcdata_item(0xF19158ED),  # BUFFER_END
    ])


def test_parse_stackshot_of_synthetic_kcdata() -> None:
    assert CoreProfileSessionTap.parse_stackshot(_synthetic_stackshot()) == {
        "stackshot_flags": 0x1234,
        "osversion": "Darwin Kernel",
        "mach_timebase_info": {"numer": 125, "denom": 3},
        "shared_cache_dyld_load_info": {
            "imageLoadAddress": 0x180000000,
            "imageUUID": uuid.UUID("11111111-2222-3333-4444-555555555555"),
            "imageSlidBaseAddress": 0x190000000,
        },
        "thread_group_snapshot": [{"tgs_id": 5, "tgs_name": "tg-v2", "tgs_flags": 6}] * 2,
        "task_snapshots": {
            0: {
                "task_snapshot": {
                    "ts_unique_pid": 1,
                    "ts_ss_flags": 2,
                    "ts_user_time_in_terminated_thre": 3,
                    "ts_system_time_in_terminated_th": 4,
                    "ts_p_start_sec": 5,
                    "ts_task_size": 6,
                    "ts_max_resident_size": 7,
                    "ts_suspend_count": 8,
                    "ts_faults": 9,
                    "ts_pageins": 10,
                    "ts_cow_faults": 11,
                    "ts_was_throttled": 12,
                    "ts_did_throttle": 13,
                    "ts_latency_qos": 14,
                    "ts_pid": 0,
                    "ts_p_comm": "kernel_task",
                },
                "user_stack_frames": [{"lr": 0x1000}, {"lr": 0x2000}],
            }
        },
    }


def test_parse_stackshot_stops_at_an_undecodable_item() -> None:
    data = _synthetic_stackshot()
    # An OSVERSION without its NUL terminator ends the item list, so the buffer end is never reached.
    broken = data.replace(b"Darwin Kernel\0", b"Darwin Kernel!")
    with pytest.raises(ExtractingStackshotError):
        CoreProfileSessionTap.parse_stackshot(broken)


def _stackshot_with(*items: bytes) -> bytes:
    return b"".join([_kcdata_item(0x59A25807), *items, _kcdata_item(0xF19158ED)])


def test_parse_stackshot_array_with_any_padding() -> None:
    # ARRAY_PAD3: two LR64 elements followed by three bytes of padding
    lrs = _kcdata_item(0x23, struct.pack("<QQ", 0x1000, 0x2000) + bytes(3), flags=(0x916 << 32) | 2)
    assert CoreProfileSessionTap.parse_stackshot(_stackshot_with(lrs)) == {
        "user_stack_frames": [{"lr": 0x1000}, {"lr": 0x2000}]
    }


def test_parse_stackshot_skips_arrays_of_unknown_elements() -> None:
    unknown = _kcdata_item(0x20, b"\x01" * 8, flags=(0x7777 << 32) | 2)
    assert CoreProfileSessionTap.parse_stackshot(_stackshot_with(unknown)) == {}


def test_parse_stackshot_rejects_an_impossible_element_count() -> None:
    # CONTAINER_END elements read nothing; a huge count must not spin through 2**32 of them
    huge = _kcdata_item(0x20, b"", flags=(0x14 << 32) | 0xFFFFFFFF)
    with pytest.raises(ExtractingStackshotError):
        CoreProfileSessionTap.parse_stackshot(_stackshot_with(huge))


@pytest.mark.parametrize(
    ("record", "fields", "fmt"),
    [
        ("_TaskSnapshot", ["ts_pid"], "<i"),
        ("_ThreadSnapshot", ["ths_base_priority", "ths_sched_priority"], "<h"),
        ("_CpuArchitecture", ["cputype", "cpusubtype"], "<i"),
    ],
)
def test_signed_kcdata_fields_parse_as_signed(record: str, fields: list[str], fmt: str) -> None:
    record_type = getattr(core_profile_session_tap, record)
    raw = bytearray(record_type.SIZE)
    offsets = {field.name: field.offset for field in record_type._fields}
    for name in fields:
        struct.pack_into(fmt, raw, offsets[name], -1)
    parsed = record_type.parse(bytes(raw))
    assert [getattr(parsed, name) for name in fields] == [-1] * len(fields)


def test_donating_pids_parse_as_signed() -> None:
    donating = _kcdata_item(0x907, struct.pack("<i", -1))  # STACKSHOT_KCTYPE_DONATING_PIDS
    assert CoreProfileSessionTap.parse_stackshot(_stackshot_with(donating)) == {"donating_pids": -1}


def test_io_statistics_follow_the_xnu_layout() -> None:
    # struct io_stats_snapshot: 14 uint64_t (8 of them in two 4-entry priority arrays) = 160 bytes, as devices send.
    values = list(range(1, 21))
    record = core_profile_session_tap._IoStatistics.parse(struct.pack("<20Q", *values))
    assert core_profile_session_tap._IoStatistics.SIZE == 160
    assert (record.ss_non_paging_count, record.ss_metadata_size) == (15, 20)


def test_names_truncated_mid_character_do_not_end_the_stackshot() -> None:
    truncated = ("中" * 11).encode()[:31]  # the kernel cuts names at a byte count
    data = _synthetic_stackshot().replace(b"kernel_task".ljust(32, b"\0"), truncated + b"\0")
    task = CoreProfileSessionTap.parse_stackshot(data)["task_snapshots"][0]["task_snapshot"]
    assert task["ts_p_comm"] == "中" * 10 + "�"


def test_thread_queue_and_group_names_cut_mid_character_decode() -> None:
    cut = ("中" * 11).encode()[:31]  # ends inside the 11th character
    items = core_profile_session_tap.parse_kcdata(
        b"".join([
            _kcdata_item(0x909, cut.ljust(64, b"\0")),  # THREAD_NAME (64-byte field)
            _kcdata_item(0x928, cut + b"\0"),  # THREAD_DISPATCH_QUEUE_LABEL
            # ARRAY_PAD0 of one THREAD_GROUP_SNAPSHOT v2 whose 16-byte name ends mid-character
            _kcdata_item(0x20, struct.pack("<Q16sQ", 1, cut[:16], 0), flags=(0x91E << 32) | 1),
        ])
    )
    expected = "中" * 10 + "�"
    assert [item["data"]["obj"] for item in items[:2]] == [expected, expected]
    assert items[2]["data"]["obj"][0]["obj"]["tgs_name"] == "中" * 5 + "�"
