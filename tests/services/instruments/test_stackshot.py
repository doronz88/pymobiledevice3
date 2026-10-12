import struct
import uuid
from pathlib import Path
from typing import Any

import pytest

from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap
from pymobiledevice3.services.dvt.instruments.device_support_symbols import DeviceSupportSymbols
from pymobiledevice3.services.dvt.instruments.stackshot import SHARED_CACHE_IMAGE_NAME, resolve_stackshot

SHARED_CACHE_BASE = 0x180000000
LIBFOO_UUID = "11111111-2222-3333-4444-555555555555"
LIBFOO_VMADDR = SHARED_CACHE_BASE + 0x10000
DYLD_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
APP_UUID = "99999999-8888-7777-6666-555555555555"


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _macho(image_uuid: str, vmaddr: int, vmsize: int, symbols: dict[str, int], functions: list[int]) -> bytes:
    """Build a Mach-O holding just the load commands and tables which symbolication reads."""
    strings = b"\x00"
    nlists = b""
    for name, offset in symbols.items():
        nlists += struct.pack("<IBBHQ", len(strings), 0x0F, 1, 0, vmaddr + offset)
        strings += name.encode() + b"\x00"
    # A debugging (stab) entry, which is not a symbol of the image
    nlists += struct.pack("<IBBHQ", 0, 0x24, 1, 0, vmaddr + 0x30)
    function_starts = b"".join(_uleb128(function - previous) for previous, function in zip([0, *functions], functions))
    function_starts += b"\x00"

    sizeofcmds = 72 + 24 + 24 + 16
    symoff = 32 + sizeofcmds
    stroff = symoff + len(nlists)
    function_starts_offset = stroff + len(strings)
    commands = struct.pack("<2I16s4Q4I", 0x19, 72, b"__TEXT", vmaddr, vmsize, 0, 0, 5, 5, 0, 0)
    commands += struct.pack("<2I", 0x1B, 24) + uuid.UUID(image_uuid).bytes
    commands += struct.pack("<6I", 0x2, 24, symoff, len(nlists) // 16, stroff, len(strings))
    commands += struct.pack("<4I", 0x26, 16, function_starts_offset, len(function_starts))
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 2, 6, 4, len(commands), 0, 0)
    return header + commands + nlists + strings + function_starts


@pytest.fixture
def symbols_root(tmp_path: Path) -> Path:
    root = tmp_path / "Symbols"
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/libfoo.dylib").write_bytes(
        _macho(LIBFOO_UUID, LIBFOO_VMADDR, 0x1000, {"_foo": 0x100, "_bar": 0x200}, [0x100, 0x200, 0x300])
    )
    (root / "usr/lib/dyld").write_bytes(_macho(DYLD_UUID, 0, 0x1000, {"_start": 0x40}, [0x40]))
    (root / "usr/lib/not-a-macho").write_bytes(b"dyld_v1  arm64e\x00" * 4)
    return root


@pytest.fixture
def symbols(symbols_root: Path, tmp_path: Path) -> DeviceSupportSymbols:
    return DeviceSupportSymbols.load(symbols_root, tmp_path / "index")


def test_symbols_index_lists_the_images(symbols: DeviceSupportSymbols) -> None:
    assert [(image.path, image.uuid, image.vmaddr) for image in symbols.images] == [
        ("/usr/lib/dyld", DYLD_UUID, 0),
        ("/usr/lib/libfoo.dylib", LIBFOO_UUID, LIBFOO_VMADDR),
    ]
    assert symbols.has_shared_cache_images
    image = symbols.image_by_address(LIBFOO_VMADDR + 0x123)
    assert image is not None
    assert image.name == "libfoo.dylib"
    assert symbols.image_by_address(LIBFOO_VMADDR + 0x1000) is None
    assert symbols.image_by_uuid(LIBFOO_UUID.upper()) is image


def test_symbols_index_is_reused_until_the_tree_changes(
    symbols_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pymobiledevice3.services.dvt.instruments import device_support_symbols

    index_dir = tmp_path / "index"
    scans: list[Path] = []
    scan = device_support_symbols._scan

    def counting_scan(root: Path) -> Any:
        scans.append(root)
        return scan(root)

    monkeypatch.setattr(device_support_symbols, "_scan", counting_scan)
    assert len(DeviceSupportSymbols.load(symbols_root, index_dir).images) == 2
    assert len(DeviceSupportSymbols.load(symbols_root, index_dir).images) == 2
    assert len(scans) == 1

    # Splitting a shared cache fills directories which already exist
    (symbols_root / "usr/lib/libbar.dylib").write_bytes(_macho(APP_UUID, LIBFOO_VMADDR + 0x1000, 0x1000, {}, []))
    assert len(DeviceSupportSymbols.load(symbols_root, index_dir).images) == 3
    assert len(scans) == 2


def test_symbolicate(symbols: DeviceSupportSymbols) -> None:
    image = symbols.image_by_uuid(LIBFOO_UUID)
    assert image is not None
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x100) == ("foo", 0)
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x1FC) == ("foo", 0xFC)
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x210) == ("bar", 0x10)
    # Before the first symbol
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x80) is None
    # In the function at 0x300, which has no symbol: must not be attributed to `bar`
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x310) is None


def _stackshot(slide: int) -> dict[str, Any]:
    app_load_address = 0x100004000
    dyld_load_address = 0x1F0000000
    return {
        "shared_cache_dyld_load_info": {
            "imageLoadAddress": slide,
            "imageUUID": uuid.uuid4(),
            "imageSlidBaseAddress": SHARED_CACHE_BASE + slide,
        },
        "task_snapshots": {
            0: {
                "task_snapshot": {"ts_pid": 0, "ts_p_comm": "kernel_task"},
                "dyld_load_info_text_exec": [
                    {"imageLoadAddress": 0xFFFFFE0007004000, "imageUUID": "kernel-uuid"},
                    {"imageLoadAddress": 0xFFFFFE0008000000, "imageUUID": "kext-uuid"},
                ],
                "thread_snapshots": {
                    100: {
                        "thread_snapshot": {"ths_state": 0x1 | 0x8},
                        "pth_name": "VM_pageout_scan",
                        "kernel_stack_frames": [{"lr": 0xFFFFFE0008000010}, {"lr": 0xFFFFFE0007004020}],
                    }
                },
            },
            42: {
                "task_snapshot": {
                    "ts_pid": 42,
                    "ts_p_comm": "SpringBoard",
                    "ts_task_size": 1024,
                    "ts_max_resident_size": 2048,
                    "ts_suspend_count": 0,
                },
                "dyld_load_info": [
                    {"imageLoadAddress": dyld_load_address, "imageUUID": uuid.UUID(DYLD_UUID)},
                    {"imageLoadAddress": app_load_address, "imageUUID": uuid.UUID(APP_UUID)},
                ],
                "thread_snapshots": {
                    514: {
                        "thread_snapshot": {
                            "ths_state": 0x1,
                            "ths_eqos": 6,
                            "ths_sched_priority": 47,
                            "ths_wait_event": 0x1234,
                        },
                        "dispatch_queue_label": "com.apple.main-thread",
                        "cpu_times": {"user_usec": 1500000, "system_usec": 250000},
                        "user_stack_frames": [
                            {"lr": LIBFOO_VMADDR + slide + 0x208},
                            # Return address of a call ending `foo`: the next instruction is already `bar`
                            {"lr": LIBFOO_VMADDR + slide + 0x200},
                            {"lr": SHARED_CACHE_BASE + slide + 0x800},
                            {"lr": app_load_address + 0x4A38},
                            {"lr": dyld_load_address + 0x48},
                            {"lr": 0},
                        ],
                    }
                },
            },
        },
    }


@pytest.mark.parametrize("slide", [0, 0x4000000])
def test_resolve_stackshot(symbols: DeviceSupportSymbols, slide: int) -> None:
    kernel_task, process = resolve_stackshot(_stackshot(slide), symbols)

    assert (kernel_task.pid, kernel_task.name) == (0, "kernel_task")
    (thread,) = kernel_task.threads
    assert (thread.name, thread.states) == ("VM_pageout_scan", ["waiting", "uninterruptible"])
    assert [(frame.kernel, frame.image, frame.image_offset) for frame in thread.frames] == [
        (True, "kext-uuid", 0x10),
        (True, "kernel-uuid", 0x20),
    ]

    assert (process.pid, process.name, process.task_size, process.max_resident_size) == (42, "SpringBoard", 1024, 2048)
    (thread,) = process.threads
    assert thread.thread_id == 514
    assert thread.dispatch_queue == "com.apple.main-thread"
    assert (thread.states, thread.qos, thread.sched_priority) == (["waiting"], "user-interactive", 47)
    assert (thread.user_usec, thread.system_usec, thread.wait_event) == (1500000, 250000, 0x1234)
    assert [(frame.image, frame.image_offset, frame.symbol, frame.symbol_offset) for frame in thread.frames] == [
        ("libfoo.dylib", 0x208, "bar", 8),
        ("libfoo.dylib", 0x200, "foo", 0x100),
        (SHARED_CACHE_IMAGE_NAME, 0x800, None, None),
        (APP_UUID, 0x4A38, None, None),
        ("dyld", 0x48, "start", 8),
    ]


def test_resolve_stackshot_without_symbols() -> None:
    _kernel_task, process = resolve_stackshot(_stackshot(0x4000000))
    assert [(frame.image, frame.image_offset, frame.symbol) for frame in process.threads[0].frames] == [
        (SHARED_CACHE_IMAGE_NAME, 0x10208, None),
        (SHARED_CACHE_IMAGE_NAME, 0x10200, None),
        (SHARED_CACHE_IMAGE_NAME, 0x800, None),
        (APP_UUID, 0x4A38, None),
        (DYLD_UUID, 0x48, None),
    ]


@pytest.mark.asyncio
async def test_resolve_device_stackshot(dvt) -> None:
    """
    Test getting the call stacks out of a device stackshot.
    """
    async with CoreProfileSessionTap(dvt, {}) as tap:
        processes = resolve_stackshot(await tap.get_stackshot())

    kernel_task = next(process for process in processes if process.pid == 0)
    assert kernel_task.name == "kernel_task"
    assert any(frame.kernel for thread in kernel_task.threads for frame in thread.frames)
    launchd = next(process for process in processes if process.pid == 1)
    assert launchd.name == "launchd"
    assert any(thread.frames for thread in launchd.threads)
