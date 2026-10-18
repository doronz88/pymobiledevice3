import asyncio
import queue
import struct
import time
import typing
import uuid
from dataclasses import dataclass
from datetime import timedelta, timezone
from io import BytesIO
from typing import Annotated

from bpylist2 import archiver
from bytestruct import (
    I32_LE,
    U32_LE,
    U64_LE,
    Array,
    BinaryParseError,
    BinaryStruct,
    ByteReader,
    BytesLike,
    CString,
    PaddedString,
    i16,
    i32,
    u8,
    u32,
    u64,
    uuid_t,
)
from pykdebugparser.kd_buf_parser import RAW_VERSION2_BYTES

from pymobiledevice3.dtx import DTXContext, DTXQueue, DTXService, dtx_method, dtx_on_data, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.exceptions import ConnectionTerminatedError, DvtException, ExtractingStackshotError
from pymobiledevice3.resources.dsc_uuid_map import get_dsc_map
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.tap import TapMessageChannel

kcdata_types = {
    "KCDATA_TYPE_INVALID": 0x0,
    "KCDATA_TYPE_STRING_DESC": 0x1,
    "KCDATA_TYPE_UINT32_DESC": 0x2,
    "KCDATA_TYPE_UINT64_DESC": 0x3,
    "KCDATA_TYPE_INT32_DESC": 0x4,
    "KCDATA_TYPE_INT64_DESC": 0x5,
    "KCDATA_TYPE_BINDATA_DESC": 0x6,
    "KCDATA_TYPE_ARRAY": 0x11,
    "KCDATA_TYPE_TYPEDEFINITION": 0x12,
    "KCDATA_TYPE_CONTAINER_BEGIN": 0x13,
    "KCDATA_TYPE_CONTAINER_END": 0x14,
    "KCDATA_TYPE_ARRAY_PAD0": 0x20,
    "KCDATA_TYPE_ARRAY_PAD1": 0x21,
    "KCDATA_TYPE_ARRAY_PAD2": 0x22,
    "KCDATA_TYPE_ARRAY_PAD3": 0x23,
    "KCDATA_TYPE_ARRAY_PAD4": 0x24,
    "KCDATA_TYPE_ARRAY_PAD5": 0x25,
    "KCDATA_TYPE_ARRAY_PAD6": 0x26,
    "KCDATA_TYPE_ARRAY_PAD7": 0x27,
    "KCDATA_TYPE_ARRAY_PAD8": 0x28,
    "KCDATA_TYPE_ARRAY_PAD9": 0x29,
    "KCDATA_TYPE_ARRAY_PADa": 0x2A,
    "KCDATA_TYPE_ARRAY_PADb": 0x2B,
    "KCDATA_TYPE_ARRAY_PADc": 0x2C,
    "KCDATA_TYPE_ARRAY_PADd": 0x2D,
    "KCDATA_TYPE_ARRAY_PADe": 0x2E,
    "KCDATA_TYPE_ARRAY_PADf": 0x2F,
    "KCDATA_TYPE_LIBRARY_LOADINFO": 0x30,
    "KCDATA_TYPE_LIBRARY_LOADINFO64": 0x31,
    "KCDATA_TYPE_TIMEBASE": 0x32,
    "KCDATA_TYPE_MACH_ABSOLUTE_TIME": 0x33,
    "KCDATA_TYPE_TIMEVAL": 0x34,
    "KCDATA_TYPE_USECS_SINCE_EPOCH": 0x35,
    "KCDATA_TYPE_PID": 0x36,
    "KCDATA_TYPE_PROCNAME": 0x37,
    "KCDATA_TYPE_NESTED_KCDATA": 0x38,
    "STACKSHOT_KCTYPE_IO_STATISTICS": 0x901,
    "STACKSHOT_KCCONTAINER_TASK": 0x903,
    "STACKSHOT_KCCONTAINER_THREAD": 0x904,
    "STACKSHOT_KCTYPE_TASK_SNAPSHOT": 0x905,
    "STACKSHOT_KCTYPE_THREAD_SNAPSHOT": 0x906,
    "STACKSHOT_KCTYPE_DONATING_PIDS": 0x907,
    "STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO": 0x908,
    "STACKSHOT_KCTYPE_THREAD_NAME": 0x909,
    "STACKSHOT_KCTYPE_KERN_STACKFRAME": 0x90A,
    "STACKSHOT_KCTYPE_KERN_STACKFRAME64": 0x90B,
    "STACKSHOT_KCTYPE_USER_STACKFRAME": 0x90C,
    "STACKSHOT_KCTYPE_USER_STACKFRAME64": 0x90D,
    "STACKSHOT_KCTYPE_BOOTARGS": 0x90E,
    "STACKSHOT_KCTYPE_OSVERSION": 0x90F,
    "STACKSHOT_KCTYPE_KERN_PAGE_SIZE": 0x910,
    "STACKSHOT_KCTYPE_JETSAM_LEVEL": 0x911,
    "STACKSHOT_KCTYPE_DELTA_SINCE_TIMESTAMP": 0x912,
    "STACKSHOT_KCTYPE_KERN_STACKLR": 0x913,
    "STACKSHOT_KCTYPE_KERN_STACKLR64": 0x914,
    "STACKSHOT_KCTYPE_USER_STACKLR": 0x915,
    "STACKSHOT_KCTYPE_USER_STACKLR64": 0x916,
    "STACKSHOT_KCTYPE_NONRUNNABLE_TIDS": 0x917,
    "STACKSHOT_KCTYPE_NONRUNNABLE_TASKS": 0x918,
    "STACKSHOT_KCTYPE_CPU_TIMES": 0x919,
    "STACKSHOT_KCTYPE_STACKSHOT_DURATION": 0x91A,
    "STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS": 0x91B,
    "STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO": 0x91C,
    "STACKSHOT_KCTYPE_THREAD_WAITINFO": 0x91D,
    "STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT": 0x91E,
    "STACKSHOT_KCTYPE_THREAD_GROUP": 0x91F,
    "STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT": 0x920,
    "STACKSHOT_KCTYPE_JETSAM_COALITION": 0x921,
    "STACKSHOT_KCTYPE_THREAD_POLICY_VERSION": 0x922,
    "STACKSHOT_KCTYPE_INSTRS_CYCLES": 0x923,
    "STACKSHOT_KCTYPE_USER_STACKTOP": 0x924,
    "STACKSHOT_KCTYPE_ASID": 0x925,
    "STACKSHOT_KCTYPE_PAGE_TABLES": 0x926,
    "STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT": 0x927,
    "STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL": 0x928,
    "STACKSHOT_KCTYPE_THREAD_TURNSTILEINFO": 0x929,
    "STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE": 0x92A,
    "STACKSHOT_KCTYPE_LATENCY_INFO": 0x92B,
    "STACKSHOT_KCTYPE_LATENCY_INFO_TASK": 0x92C,
    "STACKSHOT_KCTYPE_LATENCY_INFO_THREAD": 0x92D,
    "STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC": 0x92E,
    "STACKSHOT_KCTYPE_USER_ASYNC_START_INDEX": 0x932,
    "STACKSHOT_KCTYPE_USER_ASYNC_STACKLR64": 0x933,
    "STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT": 0x940,
    "STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT": 0x941,
    "STACKSHOT_KCCONTAINER_SHAREDCACHE": 0x942,
    "STACKSHOT_KCTYPE_UNKNOWN_0x943": 0x943,
    "STACKSHOT_KCCONTAINER_EXCLAVES": 0x949,
    "STACKSHOT_KCCONTAINER_EXCLAVE_SCRESULT": 0x94A,
    "STACKSHOT_KCCONTAINER_EXCLAVE_IPCSTACKENTRY": 0x94C,
    "STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_INFO": 0x94D,
    "STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_ECSTACK": 0x94E,
    "STACKSHOT_KCCONTAINER_EXCLAVE_ADDRESSSPACE": 0x94F,
    "STACKSHOT_KCCONTAINER_EXCLAVE_TEXTLAYOUT": 0x952,
    "STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_INFO": 0x953,
    "STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_SEGMENTS": 0x954,
    "KCDATA_TYPE_BUFFER_END": 0xF19158ED,
    "TASK_CRASHINFO_EXTMODINFO": 0x801,
    "TASK_CRASHINFO_BSDINFOWITHUNIQID": 0x802,
    "TASK_CRASHINFO_TASKDYLD_INFO": 0x803,
    "TASK_CRASHINFO_UUID": 0x804,
    "TASK_CRASHINFO_PID": 0x805,
    "TASK_CRASHINFO_PPID": 0x806,
    # Don't want anyone using this.  It's struct rusage from whatever machine generated the data
    # 'TASK_CRASHINFO_RUSAGE':               0x807,
    "Type_0x807": 0x807,
    "TASK_CRASHINFO_RUSAGE_INFO": 0x808,
    "TASK_CRASHINFO_PROC_NAME": 0x809,
    "TASK_CRASHINFO_PROC_STARTTIME": 0x80B,
    "TASK_CRASHINFO_USERSTACK": 0x80C,
    "TASK_CRASHINFO_ARGSLEN": 0x80D,
    "TASK_CRASHINFO_EXCEPTION_CODES": 0x80E,
    "TASK_CRASHINFO_PROC_PATH": 0x80F,
    "TASK_CRASHINFO_PROC_CSFLAGS": 0x810,
    "TASK_CRASHINFO_PROC_STATUS": 0x811,
    "TASK_CRASHINFO_UID": 0x812,
    "TASK_CRASHINFO_GID": 0x813,
    "TASK_CRASHINFO_PROC_ARGC": 0x814,
    "TASK_CRASHINFO_PROC_FLAGS": 0x815,
    "TASK_CRASHINFO_CPUTYPE": 0x816,
    "TASK_CRASHINFO_WORKQUEUEINFO": 0x817,
    "TASK_CRASHINFO_RESPONSIBLE_PID": 0x818,
    "TASK_CRASHINFO_DIRTY_FLAGS": 0x819,
    "TASK_CRASHINFO_CRASHED_THREADID": 0x81A,
    "TASK_CRASHINFO_COALITION_ID": 0x81B,
    "EXIT_REASON_SNAPSHOT": 0x1001,
    "EXIT_REASON_USER_DESC": 0x1002,
    "EXIT_REASON_USER_PAYLOAD": 0x1003,
    "EXIT_REASON_CODESIGNING_INFO": 0x1004,
    "EXIT_REASON_WORKLOOP_ID": 0x1005,
    "EXIT_REASON_DISPATCH_QUEUE_NO": 0x1006,
    "KCDATA_BUFFER_BEGIN_CRASHINFO": 0xDEADF157,
    "KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT": 0xDE17A59A,
    "KCDATA_BUFFER_BEGIN_STACKSHOT": 0x59A25807,
    "KCDATA_BUFFER_BEGIN_COMPRESSED": 0x434F4D50,
    "KCDATA_BUFFER_BEGIN_OS_REASON": 0x53A20900,
    "KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG": 0x1E21C09F,
}

_KCDATA_TYPE_NAMES: dict[int, str] = {value: name for name, value in kcdata_types.items()}

#: A kcdata item type: its name from `kcdata_types` when known, otherwise the raw integer.
KcdataType = typing.Union[str, int]

predefined_names: dict[KcdataType, str] = {
    "STACKSHOT_KCTYPE_JETSAM_LEVEL": "jetsam_level",
    "STACKSHOT_KCTYPE_THREAD_POLICY_VERSION": "thread_policy_version",
    "STACKSHOT_KCTYPE_KERN_PAGE_SIZE": "kernel_page_size",
    "STACKSHOT_KCTYPE_OSVERSION": "osversion",
    "STACKSHOT_KCTYPE_BOOTARGS": "boot_args",
    "KCDATA_TYPE_TIMEBASE": "mach_timebase_info",
    "KCDATA_TYPE_MACH_ABSOLUTE_TIME": "mach_absolute_time",
    "KCDATA_TYPE_USECS_SINCE_EPOCH": "usecs_since_epoch",
    "STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO": "shared_cache_dyld_load_info",
    "STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT": "thread_group_snapshot",
    "STACKSHOT_KCCONTAINER_TASK": "task_snapshots",
    "STACKSHOT_KCCONTAINER_THREAD": "thread_snapshots",
    "STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO": "kernelcache_load_info",
    "STACKSHOT_KCTYPE_TASK_SNAPSHOT": "task_snapshot",
    "STACKSHOT_KCTYPE_JETSAM_COALITION": "jetsam_coalition",
    "STACKSHOT_KCTYPE_IO_STATISTICS": "io_statistics",
    "STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE": "task_cpu_architecture",
    "STACKSHOT_KCTYPE_THREAD_SNAPSHOT": "thread_snapshot",
    "STACKSHOT_KCTYPE_THREAD_NAME": "pth_name",
    "STACKSHOT_KCTYPE_CPU_TIMES": "cpu_times",
    "STACKSHOT_KCTYPE_THREAD_GROUP": "thread_group",
    "STACKSHOT_KCTYPE_KERN_STACKLR64": "kernel_stack_frames",
    "KCDATA_TYPE_LIBRARY_LOADINFO64": "dyld_load_info",
    "STACKSHOT_KCTYPE_USER_STACKLR64": "user_stack_frames",
    "STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT": "jetsam_coalition_snapshot",
    "STACKSHOT_KCTYPE_DONATING_PIDS": "donating_pids",
    "STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL": "dispatch_queue_label",
    "KCDATA_BUFFER_BEGIN_STACKSHOT": "kcdata_stackshot",
    "STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS": "stackshot_fault_stats",
    "STACKSHOT_KCTYPE_STACKSHOT_DURATION": "stackshot_duration",
    "STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC": "dyld_load_info_text_exec",
    "STACKSHOT_KCTYPE_USER_ASYNC_STACKLR64": "user_async_stack_lr",
    "STACKSHOT_KCCONTAINER_SHAREDCACHE": "container_sharedcache",
    "STACKSHOT_KCCONTAINER_EXCLAVES": "container_exclaves",
    "STACKSHOT_KCCONTAINER_EXCLAVE_SCRESULT": "exclave_scresult",
    "STACKSHOT_KCCONTAINER_EXCLAVE_IPCSTACKENTRY": "exclave_ipc_stack_entry",
    "STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_ECSTACK": "exclave_ipc_stack_entry_ecstack",
    "STACKSHOT_KCCONTAINER_EXCLAVE_ADDRESSSPACE": "exclave_address_space",
    "STACKSHOT_KCCONTAINER_EXCLAVE_TEXTLAYOUT": "exclave_text_layout",
    "STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_INFO": "exclave_text_layout_info",
    "STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_SEGMENTS": "exclave_text_layout_segments",
}

_ITEM_HEADER = struct.Struct("<IIQ")

_FieldParser = typing.Callable[[ByteReader], typing.Any]


@dataclass
class _ItemContext:
    """What a kcdata payload parser may consult besides its own bytes."""

    #: Type whose predefined name labels the payload (the item type, or the element type inside an array).
    type: KcdataType
    #: Size of the enclosing kcdata item.
    size: int
    #: Flags of the enclosing kcdata item.
    flags: int
    #: Element count, only while parsing the elements of an array item.
    count: typing.Optional[int] = None


_ItemParser = typing.Callable[[ByteReader, _ItemContext], typing.Any]


def _type_name(value: int) -> KcdataType:
    return _KCDATA_TYPE_NAMES.get(value, value)


def _u32(reader: ByteReader) -> int:
    return reader.unpack_one(U32_LE)


def _i32(reader: ByteReader) -> int:
    return reader.unpack_one(I32_LE)


def _u64(reader: ByteReader) -> int:
    return reader.unpack_one(U64_LE)


# The kernel truncates names (process, thread, queue) at a byte count, which can split a UTF-8 character.
_cstring = CString(errors="replace").read


_THREAD_NAME = PaddedString(64, errors="replace")


def _thread_name(reader: ByteReader) -> str:
    return _THREAD_NAME.decode(reader.read(64))


STACKSHOT_IO_NUM_PRIORITIES = 4


@dataclass
class _Uint32Desc(BinaryStruct):
    name: Annotated[str, PaddedString(32)]
    obj: u32


@dataclass
class _Uint64Desc(BinaryStruct):
    name: Annotated[str, PaddedString(32)]
    obj: u64


@dataclass
class _Timebase(BinaryStruct):
    numer: u32
    denom: u32


@dataclass
class _DyldUuidInfo64(BinaryStruct):
    imageLoadAddress: u64
    imageUUID: uuid_t


@dataclass
class _DyldUuidInfo64V2(BinaryStruct):
    imageLoadAddress: u64
    imageUUID: uuid_t
    imageSlidBaseAddress: u64


@dataclass
class _TaskSnapshot(BinaryStruct):
    ts_unique_pid: u64
    ts_ss_flags: u64
    ts_user_time_in_terminated_thre: u64
    ts_system_time_in_terminated_th: u64
    ts_p_start_sec: u64
    ts_task_size: u64
    ts_max_resident_size: u64
    ts_suspend_count: u32
    ts_faults: u32
    ts_pageins: u32
    ts_cow_faults: u32
    ts_was_throttled: u32
    ts_did_throttle: u32
    ts_latency_qos: u32
    ts_pid: i32  # int32_t in xnu task_snapshot_v2
    ts_p_comm: Annotated[str, PaddedString(32, errors="replace")]  # cut at a byte count, like _cstring


@dataclass
class _IoStatistics(BinaryStruct):
    ss_disk_reads_count: u64
    ss_disk_reads_size: u64
    ss_disk_writes_count: u64
    ss_disk_writes_size: u64
    ss_io_priority_count: Annotated[list[int], Array(u64, STACKSHOT_IO_NUM_PRIORITIES)]
    ss_io_priority_size: Annotated[list[int], Array(u64, STACKSHOT_IO_NUM_PRIORITIES)]
    ss_paging_count: u64
    ss_paging_size: u64
    ss_non_paging_count: u64
    ss_non_paging_size: u64
    ss_data_count: u64
    ss_data_size: u64
    ss_metadata_count: u64
    ss_metadata_size: u64


@dataclass
class _CpuArchitecture(BinaryStruct):
    cputype: i32  # int32_t in xnu stackshot_cpu_architecture
    cpusubtype: i32


@dataclass
class _ThreadSnapshot(BinaryStruct):
    ths_thread_id: u64
    ths_wait_event: u64
    ths_continuation: u64
    ths_total_syscalls: u64
    ths_voucher_identifier: u64
    ths_dqserialnum: u64
    ths_user_time: u64
    ths_sys_time: u64
    ths_ss_flags: u64
    ths_last_run_time: u64
    ths_last_made_runnable_time: u64
    ths_state: u32
    ths_sched_flags: u32
    ths_base_priority: i16  # int16_t in xnu thread_snapshot_v4
    ths_sched_priority: i16
    ths_eqos: u8
    ths_rqos: u8
    ths_rqos_override: u8
    ths_io_tier: u8
    ths_thread_t: u64
    ths_requested_policy: u64
    ths_effective_policy: u64


@dataclass
class _CpuTimes(BinaryStruct):
    user_usec: u64
    system_usec: u64
    runnable_usec: u64


@dataclass
class _StackLr64(BinaryStruct):
    lr: u64


@dataclass
class _JetsamCoalitionSnapshot(BinaryStruct):
    jcs_id: u64
    jcs_flags: u64
    jcs_thread_group: u64
    jcs_leader_task_uniqueid: u64


@dataclass
class _StackshotFaultStats(BinaryStruct):
    sfs_pages_faulted_in: u32
    sfs_time_spent_faulting: u64
    sfs_system_max_fault_time: u64
    sfs_stopped_faulting: u8


@dataclass
class _StackshotDuration(BinaryStruct):
    stackshot_duration: u64
    stackshot_duration_outer: u64


@dataclass
class _ExclaveIpcStackEntryEcStack(BinaryStruct):
    addr: u64


@dataclass
class _ExclaveTextLayoutInfo(BinaryStruct):
    layout_id: u64
    etl_flags: u64
    sharedcache_index: u32


@dataclass
class _ExclaveTextLayoutSegment(BinaryStruct):
    imageUUID: uuid_t
    layoutSegment_loadAddress: u64
    layoutSegment_rawLoadAddress: u64


def _record(cls: type[BinaryStruct]) -> _FieldParser:
    """A packed struct, parsed into a dict of its fields in declaration order."""
    read = cls.read

    def parse(reader: ByteReader) -> dict[str, typing.Any]:
        return vars(read(reader)).copy()

    return parse


def _named(obj: _FieldParser) -> _ItemParser:
    """A payload labelled with the predefined name of its type: ``{"name": ..., "obj": ...}``."""

    def parse(reader: ByteReader, ctx: _ItemContext) -> dict[str, typing.Any]:
        name = predefined_names[ctx.type]
        return {"name": name, "obj": obj(reader)}

    return parse


def _greedy_bytes(reader: ByteReader, ctx: _ItemContext) -> bytes:
    return reader.read_all()


def _empty(reader: ByteReader, ctx: _ItemContext) -> None:
    return None


def _stackshot_begin(reader: ByteReader, ctx: _ItemContext) -> dict[str, typing.Any]:
    return {"name": predefined_names[ctx.type]}


def _container_begin(reader: ByteReader, ctx: _ItemContext) -> dict[str, typing.Any]:
    obj = _type_name(_u32(reader))
    return {"obj": obj, "name": predefined_names.get(obj, "unknown"), "unique_id": ctx.flags}


def _thread_group_snapshot_v2(reader: ByteReader) -> dict[str, typing.Any]:
    tgs_id = _u64(reader)
    tgs_name = reader.read(16).decode("utf-8", "replace").strip("\x00")
    return {"tgs_id": tgs_id, "tgs_name": tgs_name, "tgs_flags": _u64(reader)}


def _thread_group_snapshot_v3(reader: ByteReader) -> dict[str, typing.Any]:
    tgs_id = _u64(reader)
    tgs_name = reader.read(16)
    tgs_flags = _u64(reader)
    tgs_name_cont = reader.read(16)
    return {
        "tgs_id": tgs_id,
        "tgs_flags": tgs_flags,
        "tgs_name": (tgs_name.strip(b"\x00") + tgs_name_cont.strip(b"\x00")).decode("utf-8", "replace"),
    }


# The element layout is told apart by its size: ``thread_group_snapshot_v2`` / ``thread_group_snapshot_v3``.
_THREAD_GROUP_SNAPSHOT_VERSIONS: dict[int, _FieldParser] = {
    32: _thread_group_snapshot_v2,
    48: _thread_group_snapshot_v3,
}


def _thread_group_snapshot(reader: ByteReader, ctx: _ItemContext) -> dict[str, typing.Any]:
    name = predefined_names[ctx.type]
    if ctx.count is None:
        raise BinaryParseError("thread group snapshot outside of an array")
    parser = _THREAD_GROUP_SNAPSHOT_VERSIONS.get(ctx.size // ctx.count)
    # An element size of an unknown snapshot version yields None entries (still valid JSON) and the rest of the
    # stackshot parses; the construct parser stopped at such an array, dropping everything after it.
    return {"name": name, "obj": None if parser is None else parser(reader)}


def _array(padding: int) -> _ItemParser:
    """An array item: the element type and count are packed into the item flags."""

    def parse(reader: ByteReader, ctx: _ItemContext) -> typing.Any:
        flags_type = (ctx.flags >> 32) & 0xFFFFFFFF
        type_ = _type_name(flags_type)
        count = ctx.flags & 0xFFFFFFFF
        parser = _KCDATA_PARSERS.get(type_)
        if parser is None:
            # No layout for the element type: keep the array's raw bytes, like any other unknown item.
            return reader.read_all()
        if count > ctx.size:
            # Every element takes at least a byte; this bounds the loop for elements that read nothing.
            raise BinaryParseError(f"{count} elements cannot fit a {ctx.size}-byte array")
        name = predefined_names[type_]
        element_ctx = _ItemContext(type=type_, size=ctx.size, flags=ctx.flags, count=count)
        obj = [parser(reader, element_ctx) for _ in range(count)]
        reader.read(padding)
        return {"flags_type": flags_type, "type": type_, "count": count, "name": name, "obj": obj}

    return parse


_dyld_uuid_info_64 = _named(_record(_DyldUuidInfo64))
_lr = _named(_record(_StackLr64))

_KCDATA_PARSERS: dict[KcdataType, _ItemParser] = {
    # Self-describing payloads: a 32-byte ``name`` followed by the value, ``obj``.
    "KCDATA_TYPE_UINT32_DESC": lambda reader, ctx: vars(_Uint32Desc.read(reader)).copy(),
    "KCDATA_TYPE_UINT64_DESC": lambda reader, ctx: vars(_Uint64Desc.read(reader)).copy(),
    "STACKSHOT_KCTYPE_JETSAM_LEVEL": _named(_u32),
    "STACKSHOT_KCTYPE_THREAD_POLICY_VERSION": _named(_u32),
    "STACKSHOT_KCTYPE_KERN_PAGE_SIZE": _named(_u32),
    "STACKSHOT_KCTYPE_OSVERSION": _named(_cstring),
    "STACKSHOT_KCTYPE_BOOTARGS": _named(_cstring),
    "KCDATA_TYPE_TIMEBASE": _named(_record(_Timebase)),
    "KCDATA_TYPE_MACH_ABSOLUTE_TIME": _named(_u64),
    "KCDATA_TYPE_USECS_SINCE_EPOCH": _named(_u64),
    "STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO": _named(_record(_DyldUuidInfo64V2)),
    # KCDATA_TYPE_ARRAY_PAD0..PADf: the low nibble of the type is the number of trailing padding bytes.
    **{f"KCDATA_TYPE_ARRAY_PAD{padding:x}": _array(padding) for padding in range(0x10)},
    "STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT": _thread_group_snapshot,
    "KCDATA_TYPE_CONTAINER_BEGIN": _container_begin,
    "STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO": _dyld_uuid_info_64,
    "STACKSHOT_KCTYPE_TASK_SNAPSHOT": _named(_record(_TaskSnapshot)),
    "STACKSHOT_KCTYPE_JETSAM_COALITION": _named(_u64),
    "STACKSHOT_KCTYPE_IO_STATISTICS": _named(_record(_IoStatistics)),
    "STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE": _named(_record(_CpuArchitecture)),
    "STACKSHOT_KCTYPE_THREAD_SNAPSHOT": _named(_record(_ThreadSnapshot)),
    "STACKSHOT_KCTYPE_THREAD_NAME": _named(_thread_name),
    "STACKSHOT_KCTYPE_CPU_TIMES": _named(_record(_CpuTimes)),
    "STACKSHOT_KCTYPE_THREAD_GROUP": _named(_u64),
    "STACKSHOT_KCTYPE_KERN_STACKLR64": _lr,
    "KCDATA_TYPE_LIBRARY_LOADINFO64": _dyld_uuid_info_64,
    "STACKSHOT_KCTYPE_USER_STACKLR64": _lr,
    "STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT": _named(_record(_JetsamCoalitionSnapshot)),
    "STACKSHOT_KCTYPE_DONATING_PIDS": _named(_i32),  # int32_t[] in xnu
    "STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL": _named(_cstring),
    "STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS": _named(_record(_StackshotFaultStats)),
    "KCDATA_BUFFER_BEGIN_STACKSHOT": _stackshot_begin,
    "KCDATA_TYPE_CONTAINER_END": _empty,
    "KCDATA_TYPE_BUFFER_END": _empty,
    "STACKSHOT_KCTYPE_STACKSHOT_DURATION": _named(_record(_StackshotDuration)),
    "STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC": _dyld_uuid_info_64,
    "STACKSHOT_KCTYPE_USER_ASYNC_STACKLR64": _lr,
    "STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_ECSTACK": _named(_record(_ExclaveIpcStackEntryEcStack)),
    "STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_INFO": _named(_record(_ExclaveTextLayoutInfo)),
    "STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_SEGMENTS": _named(_record(_ExclaveTextLayoutSegment)),
}


def parse_kcdata(data: BytesLike) -> list[dict[str, typing.Any]]:
    """
    Parse a kcdata buffer into its flat list of items.

    Each item is ``{"type", "size", "flags", "data"}``, where ``data`` is the decoded payload (a dict for
    known layouts, ``None`` for markers, raw bytes otherwise). Parsing stops silently at the first item
    that cannot be decoded, returning the items before it.
    """
    reader = ByteReader(data)
    items: list[dict[str, typing.Any]] = []
    while True:
        try:
            raw_type, size, flags = reader.unpack(_ITEM_HEADER)
            type_ = _type_name(raw_type)
            payload = reader.sub(size)
            item_data = _KCDATA_PARSERS.get(type_, _greedy_bytes)(payload, _ItemContext(type_, size, flags))
        except Exception:
            # Any undecodable item ends the buffer, as far as the stackshot is concerned.
            break
        items.append({"type": type_, "size": size, "flags": flags, "data": item_data})
    return items


def jsonify_parsed_stackshot(
    stackshot: typing.Any, root: typing.Optional[dict[str, typing.Any]] = None, index: int = 0
) -> typing.Optional[int]:
    assert root is not None
    current_index = index
    while True:
        if current_index >= len(stackshot):
            raise ExtractingStackshotError("stackshot ended before its end marker (an item could not be decoded)")
        item = stackshot[current_index]
        current_index += 1
        if item["type"] == "KCDATA_BUFFER_BEGIN_STACKSHOT":
            # Stackshot root, return no more parsing required after this.
            root[item["data"]["name"]] = {}
            jsonify_parsed_stackshot(stackshot, root[item["data"]["name"]], current_index)
            return
        elif str(item["type"]).startswith("KCDATA_TYPE_ARRAY_PAD") and isinstance(item["data"], dict):
            root[item["data"]["name"]] = [i["obj"] for i in item["data"]["obj"]]
        elif item["type"] == "KCDATA_TYPE_CONTAINER_BEGIN":
            # Each container creates an entry in the container's dictionary with its unique id.
            if item["data"]["name"] not in root:
                root[item["data"]["name"]] = {}
            root[item["data"]["name"]][item["data"]["unique_id"]] = {}
            current_index = jsonify_parsed_stackshot(
                stackshot, root[item["data"]["name"]][item["data"]["unique_id"]], current_index
            )
            # a container is always terminated by KCDATA_TYPE_CONTAINER_END, which returns an index
            assert current_index is not None
        elif item["type"] == "KCDATA_TYPE_CONTAINER_END":
            return current_index
        elif item["type"] == "KCDATA_TYPE_BUFFER_END":
            return
        else:
            if isinstance(item["data"], dict):
                root[item["data"]["name"]] = item["data"]["obj"]


STACKSHOT_HEADER = U32_LE.pack(kcdata_types["KCDATA_BUFFER_BEGIN_STACKSHOT"])


KD_BUF_SIZE = 64


class KdBufStream:
    """
    File-like view over the kd_buf chunks queued by `CoreProfileSessionTap.pump_kdbuf_chunks`.

    :param chunk_queue: Queue being fed by `pump_kdbuf_chunks`.
    :param max_lag: Skip whole chunks whose newest event is more than this many seconds behind real time, so
        a reader slower than the device catches up instead of falling ever further behind. `None` never skips.
        The lag is measured against the smallest lag seen so far, which absorbs the delivery delay and any
        device/host clock offset. The first (header) chunk is never skipped.
    :param event_seconds: Converts a kd_buf timestamp (mach ticks) to seconds; required with `max_lag`.
    :param on_skip: Called with the number of skipped events and how far behind the stream was, once per
        catch-up.
    :param on_wait: Called before a read waits for the next chunk (everything received so far was read), e.g. to
        flush buffered output.
    """

    def __init__(
        self,
        chunk_queue: queue.Queue[typing.Any],
        max_lag: typing.Optional[float] = None,
        event_seconds: typing.Optional[typing.Callable[[int], float]] = None,
        on_skip: typing.Optional[typing.Callable[[int, float], None]] = None,
        on_wait: typing.Optional[typing.Callable[[], None]] = None,
    ):
        if max_lag is not None and event_seconds is None:
            raise ValueError("max_lag requires event_seconds")
        self.chunk_queue = chunk_queue
        self.current_chunk = BytesIO()
        self.max_lag = max_lag
        self.event_seconds = event_seconds
        self.on_skip = on_skip
        self.on_wait = on_wait
        self.skipped_events = 0
        self._started = False
        self._min_offset: typing.Optional[float] = None  # smallest (host clock - event clock) seen
        self._skipping = 0  # events skipped in the current catch-up
        self._skipping_lag = 0.0

    def tell(self):
        return self.current_chunk.tell()

    def seek(self, offset: int, whence: int):
        return self.current_chunk.seek(offset, whence)

    def read(self, size: int):
        # A kd_buf record never spans two chunks: every data chunk holds whole 64-byte records, and the
        # header chunk (a fixed 1 MiB buffer) ends in threadmap slack that is not a multiple of 64 bytes.
        # A read that does not fit in the current chunk therefore drops its short remainder and restarts
        # at the next chunk's first record, which keeps the record stream aligned.
        while size > len(self.current_chunk.getbuffer()) - self.current_chunk.tell():
            if self.on_wait is not None and self.chunk_queue.empty():
                self.on_wait()
            data = self.chunk_queue.get()
            if isinstance(data, Exception):
                raise data
            if data is None:
                return b""
            if data.startswith(b"bplist"):
                continue
            if data.startswith(STACKSHOT_HEADER):
                continue
            if self._started and self._is_behind(data):
                continue
            self._started = True
            self._report_skip()
            self.current_chunk = BytesIO(data)

        return self.current_chunk.read(size)

    def _is_behind(self, data: bytes) -> bool:
        """Whether this data chunk's newest event is more than `max_lag` behind; counts it as skipped if so."""
        if self.max_lag is None or len(data) < KD_BUF_SIZE:
            return False
        assert self.event_seconds is not None
        newest = struct.unpack_from("<Q", data, len(data) - KD_BUF_SIZE)[0]
        offset = time.monotonic() - self.event_seconds(newest)
        if self._min_offset is None or offset < self._min_offset:
            self._min_offset = offset
        lag = offset - self._min_offset
        if lag <= self.max_lag:
            return False
        self._skipping += len(data) // KD_BUF_SIZE
        self._skipping_lag = max(self._skipping_lag, lag)
        return True

    def _report_skip(self) -> None:
        if not self._skipping:
            return
        self.skipped_events += self._skipping
        if self.on_skip is not None:
            self.on_skip(self._skipping, self._skipping_lag)
        self._skipping = 0
        self._skipping_lag = 0.0


class CoreProfileSessionTapService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.coreprofilesessiontap"

    def __init__(self, ctx: DTXContext):
        super().__init__(ctx)
        self.messages: DTXQueue[bytes] = DTXQueue()

    def on_closed(self, reason: str = "") -> None:
        self.shutdown_queue(self.messages)
        super().on_closed(reason)

    @dtx_method("setConfig:", expects_reply=False)
    async def set_config_(self, config: dict[str, typing.Any]) -> None: ...

    @dtx_method("start", expects_reply=False)
    async def start(self) -> None: ...

    @dtx_method("stop", expects_reply=False)
    async def stop(self) -> None: ...

    @dtx_on_data
    async def _on_data(self, payload: bytes) -> None:
        await self.messages.put(payload)

    @dtx_on_notification
    async def _on_notification(self, payload: typing.Any) -> None:
        if payload is None:
            await self.messages.put(b"")
            return
        await self.messages.put(archiver.archive(payload))


class CoreProfileSessionTapChannel(DtxService[CoreProfileSessionTapService]):
    pass


class CoreProfileSessionTap:
    r"""
    Kdebug is a kernel facility for tracing events occurring on a system.
    This header defines reserved debugids, which are 32-bit values that describe
    each event:

    +----------------+----------------+----------------------------+----+
    |   Class (8)    |  Subclass (8)  |          Code (14)         |Func|
    |                |                |                            |(2) |
    +----------------+----------------+----------------------------+----+
    \_________________________________/
            ClassSubclass (CSC)
    \________________________________________________________________00_/
                                    Eventid
    \___________________________________________________________________/
                                    Debugid

    The eventid is a hierarchical ID, indicating which components an event is
    referring to.  The debugid includes an eventid and two function qualifier
    bits, to determine the structural significance of an event (whether it
    starts or ends an interval).

    This tap yields kdebug events.

    Constructed with a `DvtProvider`. Use as an async context manager (``async with``): entering
    configures and starts the session, exiting stops it. While active it can produce a one-time
    stackshot and stream raw kdebug buffer chunks.
    """

    IDENTIFIER = CoreProfileSessionTapService.IDENTIFIER

    def __init__(
        self,
        dvt: DtxServiceProvider,
        time_config: dict[str, typing.Any],
        filters: typing.Optional[set[int]] = None,
        sample_callstacks: bool = True,
    ):
        """
        :param dvt: Instruments service proxy.
        :param time_config: Timing information - numer, denom, mach_absolute_time and matching usecs_since_epoch,
        timezone.
        :param filters: Event filters to include, Include all if empty.
        :param sample_callstacks: Sample a user callstack on the filtered events. This also makes the device add
            MACH scheduler events to the trace and emit kperf sample events, which can outnumber the requested
            events by 10x and make the device drop some of them; pass ``False`` to trace only the filtered events.
        """
        self._provider = dvt
        self.time_config = time_config
        self._channel: typing.Optional[CoreProfileSessionTapChannel] = None
        self.channel: typing.Optional[TapMessageChannel] = None
        self.stack_shot: typing.Optional[dict[str, typing.Any]] = None
        self.uuid = str(uuid.uuid4())

        if filters is None:
            filters = {0xFFFFFFFF}
        trigger: dict[str, typing.Any] = {
            "kdf2": filters,  # Kdebug filter: (class << 24) | (subclass << 16), subclass 0xFF for a whole class.
            # Actions; [0] and [2] are no-ops that Instruments always sends.
            "ta": [[0], [2]],
            "tk": 3,  # Kind: kdebug trigger.
            "uuid": self.uuid,
        }
        if sample_callstacks:
            # [3]: sample on the default backtrace events of the filter (adds MACH scheduler events to the
            # trace), [1, 1, 0]: collect user (not kernel) callstacks of up to 128 frames.
            trigger["ta"] = [[3], [0], [2], [1, 1, 0]]
            trigger["csd"] = 128
        config: dict[str, typing.Any] = {
            "tc": [trigger],  # Triggers configs
            "rp": 100,  # Recording priority
            "bm": 0,  # Buffer mode.
            # Update rate (ms): how often the device flushes buffered events. Without it the device flushes
            # only every few seconds; lower values bottom out at about 200 ms of delivery latency.
            "ur": 100,
        }
        self._config = config

    async def _service_ref(self) -> CoreProfileSessionTapService:
        if self._channel is None:
            self._channel = CoreProfileSessionTapChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def _next_message(self) -> bytes:
        if self.channel is not None:
            return await self.channel.receive_message()
        service = await self._service_ref()
        return await service.messages.get()

    def __enter__(self):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aenter__(self):
        service = await self._service_ref()
        await service.set_config_(self._config)
        await service.start()
        # first message is an ack
        await service.messages.get()
        return self

    async def __aexit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any):
        await (await self._service_ref()).stop()

    @staticmethod
    def _raise_if_tap_start_failed(data: bytes) -> None:
        if not data.startswith(b"bplist"):
            return

        try:
            decoded = archiver.unarchive(data)
        except Exception:
            return

        if not isinstance(decoded, dict):
            return

        decoded = typing.cast(dict[typing.Any, typing.Any], decoded)
        notice = decoded.get("notice")
        status = decoded.get("status")
        if not notice:
            return

        # CoreProfile TAP emits a notice when kperf is already owned by another session.
        if isinstance(status, int) and status != 0:
            raise DvtException(str(notice))

    async def get_stackshot(self, timeout: typing.Optional[float] = 10.0) -> dict[str, typing.Any]:
        """
        Wait for and parse the stackshot the device emits once per tap creation.

        Non-stackshot messages are discarded while waiting. The result is parsed and cached, so
        subsequent calls return the cached value immediately. Loaded images in the parsed
        stackshot are annotated with their shared-cache paths where resolvable.

        :param timeout: Seconds to wait for stackshot data; `None` waits indefinitely.
        :returns: The parsed stackshot dictionary.
        :raises ExtractingStackshotError: If the timeout elapses, or the device sends a raw
            kdebug (version 2) buffer instead of a stackshot.
        :raises DvtException: If the device reports that kperf is already owned by another session.
        """
        if self.stack_shot is not None:
            # The stackshot is sent one per TAP creation, so we cache it.
            return self.stack_shot
        started_at = time.monotonic()
        data = b""

        while not data.startswith(STACKSHOT_HEADER) and not data.startswith(RAW_VERSION2_BYTES):
            if timeout is None:
                data = await self._next_message()
            else:
                remaining = timeout - (time.monotonic() - started_at)
                if remaining <= 0:
                    raise ExtractingStackshotError("timed out waiting for stackshot data")
                data = await asyncio.wait_for(self._next_message(), timeout=remaining)
            self._raise_if_tap_start_failed(data)

        if data.startswith(RAW_VERSION2_BYTES):
            raise ExtractingStackshotError()

        stackshot = self.parse_stackshot(data)

        dsc_map = get_dsc_map(str(stackshot["shared_cache_dyld_load_info"]["imageUUID"]))

        for _pid, snapshot in typing.cast(dict[typing.Any, typing.Any], stackshot["task_snapshots"]).items():
            for loaded_image in typing.cast(list[typing.Any], snapshot.get("dyld_load_info", [])):
                image_uuid = str(loaded_image["imageUUID"])
                if isinstance(dsc_map, dict) and image_uuid in dsc_map:
                    loaded_image["imagePath"] = dsc_map[image_uuid]

        self.stack_shot = stackshot

        return self.stack_shot

    async def dump(self, out: typing.BinaryIO, timeout: typing.Optional[float] = None):
        """
        Stream raw kdebug trace data from the session to a file.

        Stackshot and bplist messages are skipped; only kernel trace chunks are written.

        :param out: Binary file object to write the trace data to.
        :param timeout: Seconds to keep dumping; `None` dumps indefinitely.
        """
        start = time.time()
        while timeout is None or time.time() <= start + timeout:
            data = await self._next_message()
            if data.startswith(STACKSHOT_HEADER) or data.startswith(b"bplist"):
                # Skip not kernel trace data.
                continue
            print(f"Receiving trace data ({len(data)}B)")
            out.write(data)
            out.flush()

    async def pump_kdbuf_chunks(self, chunk_queue: queue.Queue[typing.Any]) -> None:
        """
        Continuously forward received messages into a queue for consumption by a `KdBufStream`.

        Runs until cancelled or the connection ends. On termination or error the offending
        exception is placed on the queue; a `None` sentinel is always enqueued last.

        :param chunk_queue: Queue that receives each raw chunk, then any exception, then a final
            `None` sentinel.
        """
        try:
            while True:
                chunk_queue.put(await self._next_message())
        except asyncio.CancelledError:
            raise
        except ConnectionTerminatedError as e:
            chunk_queue.put(e)
        except Exception as e:
            chunk_queue.put(e)
            raise
        finally:
            chunk_queue.put(None)

    def get_kdbuf_stream(
        self,
        chunk_queue: queue.Queue[typing.Any],
        max_lag: typing.Optional[float] = None,
        on_skip: typing.Optional[typing.Callable[[int, float], None]] = None,
        on_wait: typing.Optional[typing.Callable[[], None]] = None,
    ) -> KdBufStream:
        """
        Wrap a chunk queue in a file-like `KdBufStream` for reading the kd_buf trace.

        :param chunk_queue: Queue being fed by `pump_kdbuf_chunks`.
        :param max_lag: Skip events more than this many seconds behind real time (see `KdBufStream`); needs the
            ``numer``/``denom`` timebase in this tap's ``time_config``. `None` never skips.
        :param on_skip: Called with the number of skipped events and the lag in seconds, once per catch-up.
        :param on_wait: Called before the stream waits for the next chunk (see `KdBufStream`).
        :returns: A seekable, readable stream over the queued kd_buf chunks.
        """
        event_seconds: typing.Optional[typing.Callable[[int], float]] = None
        if max_lag is not None:
            seconds_per_tick = int(self.time_config["numer"]) / int(self.time_config["denom"]) / 1e9

            def ticks_to_seconds(timestamp: int) -> float:
                return timestamp * seconds_per_tick

            event_seconds = ticks_to_seconds
        return KdBufStream(chunk_queue, max_lag=max_lag, event_seconds=event_seconds, on_skip=on_skip, on_wait=on_wait)

    @staticmethod
    def parse_stackshot(data: bytes) -> dict[str, typing.Any]:
        """
        Parse raw KCDATA stackshot bytes into a nested dictionary.

        :param data: Raw stackshot buffer beginning with the stackshot KCDATA header.
        :returns: The stackshot contents as a dictionary.
        """
        parsed_stack_shot: dict[str, typing.Any] = {}
        jsonify_parsed_stackshot(parse_kcdata(data), parsed_stack_shot)
        return parsed_stack_shot[predefined_names["KCDATA_BUFFER_BEGIN_STACKSHOT"]]

    @staticmethod
    async def get_time_config(dvt: DtxServiceProvider) -> dict[str, typing.Any]:
        """
        Build the `time_config` mapping required to construct a `CoreProfileSessionTap`.

        Combines the device's mach timebase and absolute time with the host-visible wall-clock
        epoch and timezone offset taken from lockdown values.

        :param dvt: The `DvtProvider` used to query device info.
        :returns: A dict with `numer`, `denom`, `mach_absolute_time`, `usecs_since_epoch` and
            `timezone`.
        """
        async with DeviceInfo(dvt) as device_info:
            time_info = typing.cast(list[typing.Any], await device_info.mach_time_info())
        mach_absolute_time = time_info[0]
        numer = time_info[1]
        denom = time_info[2]

        usecs_since_epoch = dvt.lockdown.all_values.get("TimeIntervalSince1970", 0) * 1000000
        timezone_ = timezone(timedelta(seconds=dvt.lockdown.all_values.get("TimeZoneOffsetFromUTC", 0)))

        return {
            "numer": numer,
            "denom": denom,
            "mach_absolute_time": mach_absolute_time,
            "usecs_since_epoch": usecs_since_epoch,
            "timezone": timezone_,
        }

    @staticmethod
    async def get_trace_codes(dvt: DtxServiceProvider) -> dict[int, str]:
        """
        Fetch the device's kdebug trace-code table, mapping numeric debugids to symbol names.

        :param dvt: The `DvtProvider` used to query device info.
        :returns: A mapping of debugid code to its trace-code name.
        """
        async with DeviceInfo(dvt) as device_info:
            return await device_info.trace_codes()
