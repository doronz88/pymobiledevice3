import uuid
from pathlib import Path
from typing import Any

import pytest
from apple_symbols import DeviceSupportSymbols, KernelSymbols
from apple_symbols.testing import build_fileset, build_macho

from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap
from pymobiledevice3.services.dvt.instruments.stackshot import SHARED_CACHE_IMAGE_NAME, resolve_stackshot

SHARED_CACHE_BASE = 0x180000000
KERNEL_UUID = "12121212-3434-5656-7878-909090909090"
KEXT_UUID = "abababab-cdcd-efef-0101-232323232323"
KERNEL_VMADDR = 0xFFFFFE0007004000
KEXT_VMADDR = 0xFFFFFE0007100000
# Offset of `__TEXT_EXEC` from `__TEXT` in the kernel images
TEXT_EXEC = 0x4000
LIBFOO_UUID = "11111111-2222-3333-4444-555555555555"
LIBFOO_VMADDR = SHARED_CACHE_BASE + 0x10000
DYLD_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
APP_UUID = "99999999-8888-7777-6666-555555555555"


@pytest.fixture
def symbols_root(tmp_path: Path) -> Path:
    root = tmp_path / "Symbols"
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/libfoo.dylib").write_bytes(
        build_macho(LIBFOO_UUID, LIBFOO_VMADDR, 0x1000, {"_foo": 0x100, "_bar": 0x200}, [0x100, 0x200, 0x300])
    )
    (root / "usr/lib/dyld").write_bytes(build_macho(DYLD_UUID, 0, 0x1000, {"_start": 0x40}, [0x40]))
    (root / "usr/lib/not-a-macho").write_bytes(b"dyld_v1  arm64e\x00" * 4)
    return root


@pytest.fixture
def symbols(symbols_root: Path, tmp_path: Path) -> DeviceSupportSymbols:
    return DeviceSupportSymbols.load(symbols_root, tmp_path / "index")


KERNEL_SLIDE = 0x1000000


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
                    {"imageLoadAddress": KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE, "imageUUID": KERNEL_UUID},
                    {"imageLoadAddress": KEXT_VMADDR + TEXT_EXEC + KERNEL_SLIDE, "imageUUID": uuid.UUID(KEXT_UUID)},
                ],
                "thread_snapshots": {
                    100: {
                        "thread_snapshot": {
                            "ths_state": 0x1 | 0x8,
                            "ths_continuation": KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x200,
                        },
                        "pth_name": "VM_pageout_scan",
                        "kernel_stack_frames": [
                            {"lr": KEXT_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x110},
                            # Return address of a call ending `thread_block`
                            {"lr": KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x200},
                            {"lr": KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x310},
                        ],
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
    assert thread.continuation is None
    assert [(frame.kernel, frame.image, frame.image_offset, frame.symbol) for frame in thread.frames] == [
        (True, KEXT_UUID, 0x110, None),
        (True, KERNEL_UUID, 0x200, None),
        (True, KERNEL_UUID, 0x310, None),
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


@pytest.fixture
def kernelcache(tmp_path: Path) -> Path:
    file = tmp_path / "kernelcache.decompressed"
    file.write_bytes(
        build_fileset([
            (
                "com.apple.kernel",
                {
                    "image_uuid": KERNEL_UUID,
                    "vmaddr": KERNEL_VMADDR,
                    "vmsize": 0x10000,
                    "symbols": {"_thread_block": TEXT_EXEC + 0x100, "_vm_pageout_continue": TEXT_EXEC + 0x200},
                    "functions": [TEXT_EXEC + 0x100, TEXT_EXEC + 0x200, TEXT_EXEC + 0x300],
                    "text_exec": TEXT_EXEC,
                },
            ),
            (
                "com.apple.driver.Foo",
                {
                    "image_uuid": KEXT_UUID,
                    "vmaddr": KEXT_VMADDR,
                    "vmsize": 0x10000,
                    "symbols": {},
                    "functions": [TEXT_EXEC + 0x100],
                    "text_exec": TEXT_EXEC,
                },
            ),
        ])
    )
    return file


def test_resolve_stackshot_with_kernel_symbols(kernelcache: Path, tmp_path: Path) -> None:
    kernel_symbols = KernelSymbols.load(kernelcache, index_dir=tmp_path / "index")

    kernel_task, _process = resolve_stackshot(_stackshot(0), kernel_symbols=kernel_symbols)

    (thread,) = kernel_task.threads
    assert thread.continuation == "vm_pageout_continue"
    assert [(frame.image, frame.image_offset, frame.symbol, frame.symbol_offset) for frame in thread.frames] == [
        ("com.apple.driver.Foo", 0x110, None, None),
        ("com.apple.kernel", 0x200, "thread_block", 0x100),
        ("com.apple.kernel", 0x310, None, None),
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


def test_resolve_stackshot_continuation_inside_a_function(kernelcache: Path, tmp_path: Path) -> None:
    kernel_symbols = KernelSymbols.load(kernelcache, index_dir=tmp_path / "index")
    stackshot = _stackshot(0)
    stackshot["task_snapshots"][0]["thread_snapshots"][100]["thread_snapshot"]["ths_continuation"] += 0x1C

    kernel_task, _process = resolve_stackshot(stackshot, kernel_symbols=kernel_symbols)

    assert kernel_task.threads[0].continuation == "vm_pageout_continue + 0x1c"
