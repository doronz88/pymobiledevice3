import json
import struct
import uuid
from pathlib import Path
from typing import Any

import pytest

from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap
from pymobiledevice3.services.dvt.instruments.device_support_symbols import DeviceSupportSymbols
from pymobiledevice3.services.dvt.instruments.kernel_symbols import KernelSymbols
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


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _macho(
    image_uuid: str,
    vmaddr: int,
    vmsize: int,
    symbols: dict[str, int],
    functions: list[int],
    file_offset: int = 0,
    text_exec: int = 0,
) -> bytes:
    """
    Build a Mach-O holding just the load commands and tables which symbolication reads.

    :param file_offset: Where the Mach-O gets placed in its file, for one held by a fileset.
    :param text_exec: Offset of a `__TEXT_EXEC` segment to add, as kernel images have.
    """
    strings = b"\x00"
    nlists = b""
    for name, offset in symbols.items():
        nlists += struct.pack("<IBBHQ", len(strings), 0x0F, 1, 0, vmaddr + offset)
        strings += name.encode() + b"\x00"
    # A debugging (stab) entry, which is not a symbol of the image
    nlists += struct.pack("<IBBHQ", 0, 0x24, 1, 0, vmaddr + 0x30)
    function_starts = b"".join(_uleb128(function - previous) for previous, function in zip([0, *functions], functions))
    function_starts += b"\x00"

    sizeofcmds = 72 + 24 + 24 + 16 + (72 if text_exec else 0)
    symoff = file_offset + 32 + sizeofcmds
    stroff = symoff + len(nlists)
    function_starts_offset = stroff + len(strings)
    commands = struct.pack("<2I16s4Q4I", 0x19, 72, b"__TEXT", vmaddr, vmsize, 0, 0, 5, 5, 0, 0)
    commands += struct.pack("<2I", 0x1B, 24) + uuid.UUID(image_uuid).bytes
    commands += struct.pack("<6I", 0x2, 24, symoff, len(nlists) // 16, stroff, len(strings))
    commands += struct.pack("<4I", 0x26, 16, function_starts_offset, len(function_starts))
    if text_exec:
        commands += struct.pack("<2I16s4Q4I", 0x19, 72, b"__TEXT_EXEC", vmaddr + text_exec, vmsize, 0, 0, 5, 5, 0, 0)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 2, 6, 4 + bool(text_exec), len(commands), 0, 0)
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


def _kernelcache() -> bytes:
    """Build a fileset holding a kernel and one extension."""
    entries = [("com.apple.kernel", KERNEL_VMADDR), ("com.apple.driver.Foo", KEXT_VMADDR)]
    offsets = [0x1000, 0x2000]
    commands = b""
    for (name, vmaddr), offset in zip(entries, offsets):
        entry_id = name.encode() + b"\x00"
        entry_id += b"\x00" * (-len(entry_id) % 8)
        commands += struct.pack("<2I2Q2I", 0x80000035, 24 + 8 + len(entry_id), vmaddr, offset, 32, 0) + entry_id
    kernel = _macho(
        KERNEL_UUID,
        KERNEL_VMADDR,
        0x10000,
        {"_thread_block": TEXT_EXEC + 0x100, "_vm_pageout_continue": TEXT_EXEC + 0x200},
        [TEXT_EXEC + 0x100, TEXT_EXEC + 0x200, TEXT_EXEC + 0x300],
        file_offset=offsets[0],
        text_exec=TEXT_EXEC,
    )
    kext = _macho(KEXT_UUID, KEXT_VMADDR, 0x10000, {}, [TEXT_EXEC + 0x100], file_offset=offsets[1], text_exec=TEXT_EXEC)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 2, 12, len(entries), len(commands), 0, 0)
    data = header + commands
    data = data.ljust(offsets[0], b"\x00") + kernel
    return data.ljust(offsets[1], b"\x00") + kext


@pytest.fixture
def kernelcache(tmp_path: Path) -> Path:
    file = tmp_path / "kernelcache.decompressed"
    file.write_bytes(_kernelcache())
    return file


def test_kernel_symbols_of_a_kernelcache(kernelcache: Path, tmp_path: Path) -> None:
    kernel_symbols = KernelSymbols.load(kernelcache, index_dir=tmp_path / "index")

    assert [(image.name, image.uuid, image.text_exec) for image in kernel_symbols.images] == [
        ("com.apple.kernel", KERNEL_UUID, KERNEL_VMADDR + TEXT_EXEC),
        ("com.apple.driver.Foo", KEXT_UUID, KEXT_VMADDR + TEXT_EXEC),
    ]
    assert kernel_symbols.has_symbols
    assert kernel_symbols.symbolicate(KERNEL_VMADDR + TEXT_EXEC + 0x1FC) == ("thread_block", 0xFC)
    assert kernel_symbols.symbolicate(KERNEL_VMADDR + TEXT_EXEC + 0x200) == ("vm_pageout_continue", 0)
    # In functions which have no symbol: must not be attributed to the symbol before them
    assert kernel_symbols.symbolicate(KERNEL_VMADDR + TEXT_EXEC + 0x310) is None
    assert kernel_symbols.symbolicate(KEXT_VMADDR + TEXT_EXEC + 0x110) is None


def test_kernel_symbols_come_from_signatures_and_are_kept(
    kernelcache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pymobiledevice3.services.dvt.instruments import kernel_symbols as kernel_symbols_module

    compressed = tmp_path / "kernelcache.release.iphone17"
    compressed.write_bytes(b"IM4P" + kernelcache.read_bytes())
    signatures = tmp_path / "signatures"
    signatures.mkdir()
    commands: list[list[str]] = []

    def run(*argv: Any) -> str:
        commands.append([str(arg) for arg in argv[:3]])
        output = Path(argv[argv.index("--output") + 1])
        output.mkdir(parents=True)
        if argv[2] == "dec":
            (output / "kernelcache.release.iphone17.decompressed").write_bytes(kernelcache.read_bytes())
        else:
            assert Path(argv[argv.index("--signatures") + 1]) == signatures.resolve()
            (output / "kernelcache.symbols.json").write_text(
                json.dumps({str(KEXT_VMADDR + TEXT_EXEC + 0x100): "Foo::start(IOService*)"})
            )
        return ""

    monkeypatch.setattr(kernel_symbols_module, "run", run)
    index_dir = tmp_path / "index"

    for _ in range(2):
        kernel_symbols = KernelSymbols.load(compressed, signatures, index_dir)
        assert kernel_symbols.symbolicate(KEXT_VMADDR + TEXT_EXEC + 0x110) == ("Foo::start(IOService*)", 0x10)
        assert kernel_symbols.symbolicate(KERNEL_VMADDR + TEXT_EXEC + 0x1FC) == ("thread_block", 0xFC)
    assert commands == [["ipsw", "kernel", "dec"], ["ipsw", "kernel", "symbolicate"]]

    # New signatures may name more functions
    (signatures / "27.0").mkdir()
    KernelSymbols.load(compressed, signatures, index_dir)
    assert len(commands) == 4


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
