"""Turn the stackshot of `CoreProfileSessionTap.get_stackshot()` into per-process call stacks."""

import bisect
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Optional, cast

from pymobiledevice3.services.dvt.instruments.device_support_symbols import DeviceSupportSymbols, SymbolImage
from pymobiledevice3.services.dvt.instruments.kernel_symbols import KernelSymbols

SHARED_CACHE_IMAGE_NAME = "dyld_shared_cache"

# `ths_state` bits (osfmk/kern/thread.h)
THREAD_STATES = {
    0x01: "waiting",
    0x02: "suspended",
    0x04: "runnable",
    0x08: "uninterruptible",
    0x10: "terminating",
    0x20: "terminated",
    0x80: "idle",
}

# `ths_eqos` values (osfmk/mach/thread_policy_private.h)
THREAD_QOS = {
    1: "maintenance",
    2: "background",
    3: "utility",
    4: "default",
    5: "user-initiated",
    6: "user-interactive",
}


@dataclass
class StackshotFrame:
    """One return address of a call stack, innermost first."""

    address: int
    kernel: bool = False
    # Name of the containing image: its file name when known, its UUID otherwise
    image: Optional[str] = None
    image_offset: Optional[int] = None
    symbol: Optional[str] = None
    symbol_offset: Optional[int] = None


@dataclass
class StackshotThread:
    thread_id: int
    name: Optional[str] = None
    dispatch_queue: Optional[str] = None
    states: list[str] = field(default_factory=list[str])
    qos: Optional[str] = None
    base_priority: Optional[int] = None
    sched_priority: Optional[int] = None
    user_usec: Optional[int] = None
    system_usec: Optional[int] = None
    wait_event: int = 0
    # The kernel function a blocked thread resumes in, which tells what it is waiting for
    continuation: Optional[str] = None
    frames: list[StackshotFrame] = field(default_factory=list[StackshotFrame])


@dataclass
class StackshotProcess:
    pid: int
    name: str
    task_size: Optional[int] = None
    max_resident_size: Optional[int] = None
    suspend_count: int = 0
    start_sec: Optional[int] = None
    threads: list[StackshotThread] = field(default_factory=list[StackshotThread])


class _LoadedImages:
    """Images sorted by load address. Stackshots do not carry their sizes."""

    def __init__(self, load_info: Any) -> None:
        infos = cast(list[Mapping[str, Any]], load_info if isinstance(load_info, list) else [])
        images = sorted(((int(info["imageLoadAddress"]), info) for info in infos), key=lambda image: image[0])
        self._addresses = [address for address, _ in images]
        self._images = [info for _, info in images]

    def find(self, address: int) -> Optional[tuple[int, Mapping[str, Any]]]:
        """Get the load address and info of the image loaded closest below `address`."""
        index = bisect.bisect_right(self._addresses, address) - 1
        return (self._addresses[index], self._images[index]) if index >= 0 else None


def _kernel_load_info(stackshot: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    tasks: Mapping[Any, Mapping[str, Any]] = stackshot.get("task_snapshots", {})
    kernel_task = next((task for pid, task in tasks.items() if int(pid) == 0), None)
    load_info = kernel_task.get("dyld_load_info_text_exec") if kernel_task is not None else None
    return cast(list[Mapping[str, Any]], load_info) if isinstance(load_info, list) else []


def kernel_image_uuids(stackshot: Mapping[str, Any]) -> list[str]:
    """Get the UUID of the kernel and of every kernel extension a stackshot was taken with."""
    return [str(image["imageUUID"]) for image in _kernel_load_info(stackshot)]


class _Resolver:
    def __init__(
        self,
        stackshot: Mapping[str, Any],
        symbols: Optional[DeviceSupportSymbols],
        kernel_symbols: Optional[KernelSymbols],
    ) -> None:
        self.symbols = symbols
        self.kernel_symbols = kernel_symbols
        self.shared_cache = stackshot.get("shared_cache_dyld_load_info")
        self.kernel_images = _LoadedImages(_kernel_load_info(stackshot))

    def _symbolicate(self, frame: StackshotFrame, image: SymbolImage, address: int, lookup_delta: int) -> None:
        assert self.symbols is not None
        frame.image = image.name
        frame.image_offset = address - image.vmaddr
        symbol = self.symbols.symbolicate(image, address - lookup_delta)
        if symbol is not None:
            frame.symbol = symbol[0]
            frame.symbol_offset = symbol[1] + lookup_delta

    def user_frame(
        self, address: int, images: _LoadedImages, shared_cache: Optional[Mapping[str, Any]], innermost: bool
    ) -> StackshotFrame:
        frame = StackshotFrame(address=address)
        # All but the innermost frame hold a return address, which may already belong to the
        # next function when the call never returns. Look up the call instruction instead.
        lookup_delta = 0 if innermost else 1
        slid_base: Optional[int] = None
        if shared_cache is not None:
            slid_base = int(shared_cache["imageSlidBaseAddress"])
            if self.symbols is not None:
                # `imageLoadAddress` of the shared cache is its slide
                unslid = address - int(shared_cache["imageLoadAddress"])
                image = self.symbols.image_by_address(unslid)
                if image is not None:
                    self._symbolicate(frame, image, unslid, lookup_delta)
                    return frame

        loaded = images.find(address)
        # Images may also get loaded above the shared cache
        if slid_base is not None and address >= slid_base and (loaded is None or loaded[0] < slid_base):
            frame.image = SHARED_CACHE_IMAGE_NAME
            frame.image_offset = address - slid_base
            return frame
        if loaded is None:
            return frame
        load_address, info = loaded
        image_uuid = str(info["imageUUID"])
        image = self.symbols.image_by_uuid(image_uuid) if self.symbols is not None else None
        if image is not None:
            self._symbolicate(frame, image, address - load_address + image.vmaddr, lookup_delta)
            return frame
        image_path = info.get("imagePath")
        frame.image = str(image_path).rsplit("/", 1)[-1] if image_path else image_uuid
        frame.image_offset = address - load_address
        return frame

    def kernel_frame(self, address: int, innermost: bool) -> StackshotFrame:
        frame = StackshotFrame(address=address, kernel=True)
        loaded = self.kernel_images.find(address)
        if loaded is None:
            return frame
        load_address, info = loaded
        image_uuid = str(info["imageUUID"])
        frame.image = image_uuid
        frame.image_offset = address - load_address
        image = self.kernel_symbols.image_by_uuid(image_uuid) if self.kernel_symbols is not None else None
        if image is not None:
            assert self.kernel_symbols is not None
            frame.image = image.name
            lookup_delta = 0 if innermost else 1
            # The stackshot reports where `__TEXT_EXEC` of a kernel image got loaded
            symbol = self.kernel_symbols.symbolicate(address - load_address + image.text_exec - lookup_delta)
            if symbol is not None:
                frame.symbol = symbol[0]
                frame.symbol_offset = symbol[1] + lookup_delta
        return frame

    def continuation(self, address: int) -> Optional[str]:
        if not address:
            return None
        frame = self.kernel_frame(address, innermost=True)
        if frame.symbol is None:
            return None
        return frame.symbol if not frame.symbol_offset else f"{frame.symbol} + 0x{frame.symbol_offset:x}"

    def thread(
        self, thread_id: int, snapshot: Mapping[str, Any], images: _LoadedImages, shared_cache: Any
    ) -> StackshotThread:
        info = snapshot.get("thread_snapshot", {})
        cpu_times = snapshot.get("cpu_times", {})
        state = int(info.get("ths_state", 0))
        thread = StackshotThread(
            thread_id=thread_id,
            name=snapshot.get("pth_name") or None,
            dispatch_queue=snapshot.get("dispatch_queue_label") or None,
            states=[name for bit, name in THREAD_STATES.items() if state & bit],
            qos=THREAD_QOS.get(int(info.get("ths_eqos", 0))),
            base_priority=info.get("ths_base_priority"),
            sched_priority=info.get("ths_sched_priority"),
            user_usec=cpu_times.get("user_usec"),
            system_usec=cpu_times.get("system_usec"),
            wait_event=int(info.get("ths_wait_event", 0)),
            continuation=self.continuation(int(info.get("ths_continuation", 0))),
        )
        # A thread caught in the kernel has its kernel stack on top of its user stack
        for raw_frame in snapshot.get("kernel_stack_frames", []):
            address = int(raw_frame["lr"])
            if address:
                thread.frames.append(self.kernel_frame(address, innermost=not thread.frames))
        innermost = not thread.frames
        for raw_frame in snapshot.get("user_stack_frames", []):
            address = int(raw_frame["lr"])
            if address:
                thread.frames.append(self.user_frame(address, images, shared_cache, innermost))
                innermost = False
        return thread

    def process(self, pid: int, task: Mapping[str, Any]) -> StackshotProcess:
        info = task.get("task_snapshot", {})
        process = StackshotProcess(
            pid=pid,
            name=str(info.get("ts_p_comm", "")),
            task_size=info.get("ts_task_size"),
            max_resident_size=info.get("ts_max_resident_size"),
            suspend_count=int(info.get("ts_suspend_count", 0)),
            start_sec=info.get("ts_p_start_sec"),
        )
        images = _LoadedImages(task.get("dyld_load_info"))
        # Tasks using another shared cache than the system's one carry their own load info
        shared_cache = task.get("shared_cache_dyld_load_info", self.shared_cache)
        for thread_id, snapshot in task.get("thread_snapshots", {}).items():
            process.threads.append(self.thread(int(thread_id), snapshot, images, shared_cache))
        return process


def resolve_stackshot(
    stackshot: Mapping[str, Any],
    symbols: Optional[DeviceSupportSymbols] = None,
    kernel_symbols: Optional[KernelSymbols] = None,
) -> list[StackshotProcess]:
    """
    Get the call stacks of every thread of every process in a stackshot.

    :param stackshot: A stackshot as returned by `CoreProfileSessionTap.get_stackshot()`.
    :param symbols: Symbols of the device the stackshot was taken on. Frames are left with just
        their image offset when omitted, or when their image is not part of the symbols.
    :param kernel_symbols: Symbols of the kernelcache the device runs. Kernel frames are left with
        just the UUID of their image and their offset in it when omitted.
    """
    resolver = _Resolver(stackshot, symbols, kernel_symbols)
    return [resolver.process(int(pid), task) for pid, task in stackshot.get("task_snapshots", {}).items()]
