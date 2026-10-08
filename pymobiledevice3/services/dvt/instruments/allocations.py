import dataclasses
import struct
from collections.abc import AsyncGenerator, Iterator
from enum import IntEnum
from typing import Any, Optional

from pymobiledevice3.dtx import DTXContext, DTXQueue, DTXService, QueueShutDown, dtx_method, dtx_on_data
from pymobiledevice3.dtx.exceptions import DTXNsError
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import DvtException, ProcessInspectionError

#: Heap events: ``malloc``/``realloc``/``free``, plus the class names of the allocated objects.
MALLOC_EVENTS_MASK = 0x000D0B00
#: Reference counting events: retain, release and autorelease.
REFERENCE_COUNT_EVENTS_MASK = 0x3040F008
#: Virtual memory events: region allocations, deallocations and names.
VM_EVENTS_MASK = 0x4F800000
#: Messages sent to deallocated objects; the device launches the process with ``NSZombieEnabled``.
ZOMBIE_EVENTS_MASK = 0x00200000
ALL_EVENTS_MASK = MALLOC_EVENTS_MASK | REFERENCE_COUNT_EVENTS_MASK | VM_EVENTS_MASK

#: Timestamp, type and flags, frame word, address, argument, thread and size.
_EVENT_HEADER = struct.Struct("<dIIQQQQ")
#: Every record ends with one more word than the frames it carries.
_EVENT_TRAILER_SIZE = 8
_EVENT_TYPE_MASK = 0xFF
#: The record carries a whole backtrace, which later records of its thread and type build upon.
_FLAG_KEY_FRAME = 0x400000
#: The record only carries the innermost frames that differ from its thread's key frame.
_FLAG_DELTA = 0x800000
_KEY_FRAME_DEPTH = 512
#: Addresses are sent XORed with this, so that the recording does not show up as references to them.
_ADDRESS_MASK = 0x5555


class AllocationEventType(IntEnum):
    AUTORELEASE = 3
    OBJECT_INVALIDATED = 8
    INVALIDATED_OBJECT_MESSAGED = 9
    #: `AllocationEvent.address` is an isa pointer and `AllocationEvent.name` its class name.
    ISA_CLASS_NAME = 10
    #: `AllocationEvent.name` is the class of the object allocated at `AllocationEvent.address`.
    CLASS_NAME = 11
    RETAIN = 12
    RELEASE = 13
    GC_RETAIN = 14
    GC_RELEASE = 15
    MALLOC = 16
    #: `AllocationEvent.argument` is the address the allocation moved from.
    REALLOC = 18
    FREE = 19
    #: `AllocationEvent.argument` is the isa pointer of the instance at `AllocationEvent.address`.
    INSTANCE_ISA = 20
    ZOMBIE = 21
    VM_ALLOCATE = 23
    VM_REALLOCATE = 25
    VM_DEALLOCATE = 26
    VM_REGION_NAME = 27
    CF_RETAIN = 28
    CF_RELEASE = 29


_NAME_EVENT_TYPES = frozenset((
    AllocationEventType.ISA_CLASS_NAME,
    AllocationEventType.CLASS_NAME,
    AllocationEventType.VM_REGION_NAME,
))
_SECOND_ADDRESS_EVENT_TYPES = frozenset((AllocationEventType.REALLOC, AllocationEventType.INSTANCE_ISA))


@dataclasses.dataclass(frozen=True)
class AllocationEvent:
    """One memory event of the traced process."""

    #: Device ``mach_absolute_time()`` of the event.
    timestamp: int
    #: An `AllocationEventType` value; kept as a plain integer since devices may send other types.
    type: int
    address: int
    #: Meaning depends on the type; see `AllocationEventType`.
    argument: int
    #: The ``pthread_t`` of the thread the event happened on.
    thread: int
    #: Size of the allocation, in bytes.
    size: int
    #: Return addresses of the call stack, innermost first; unsymbolicated.
    backtrace: tuple[int, ...]
    #: Set by the name events only.
    name: Optional[str] = None


class AllocationEventParser:
    """
    Decode the event stream of an allocations recording.

    Backtraces arrive compressed against earlier events, so one parser has to see the whole stream
    of a recording, in order.
    """

    def __init__(self) -> None:
        self._pending = b""
        self._key_frames: dict[tuple[int, int], list[int]] = {}

    def feed(self, data: bytes) -> Iterator[AllocationEvent]:
        """Decode the events completed by ``data``."""
        data = self._pending + data
        offset = 0
        while offset + _EVENT_HEADER.size <= len(data):
            timestamp, type_and_flags, frame_word, address, argument, thread, size = _EVENT_HEADER.unpack_from(
                data, offset
            )
            frame_count = frame_word >> 16 if type_and_flags & _FLAG_DELTA else frame_word & 0xFFFF
            frames_offset = offset + _EVENT_HEADER.size
            end = frames_offset + 8 * frame_count + _EVENT_TRAILER_SIZE
            if end > len(data):
                break
            event_type = type_and_flags & _EVENT_TYPE_MASK
            name = None
            frames = struct.unpack_from(f"<{frame_count}Q", data, frames_offset)
            backtrace = self._expand_frames(type_and_flags, frame_word, thread, frames)
            if event_type in _NAME_EVENT_TYPES:
                # A name travels in place of the frames, compressed the same way.
                name = struct.pack(f"<{len(backtrace)}Q", *backtrace)[:size].decode(errors="replace")
                backtrace = ()
                size = 0
            if event_type in _SECOND_ADDRESS_EVENT_TYPES:
                argument ^= _ADDRESS_MASK
            yield AllocationEvent(
                timestamp=int(timestamp),
                type=event_type,
                address=address ^ _ADDRESS_MASK,
                argument=argument,
                thread=thread,
                size=size,
                backtrace=backtrace,
                name=name,
            )
            offset = end
        self._pending = data[offset:]

    def _expand_frames(
        self, type_and_flags: int, frame_word: int, thread: int, frames: tuple[int, ...]
    ) -> tuple[int, ...]:
        key = (thread, type_and_flags & _EVENT_TYPE_MASK)
        if type_and_flags & _FLAG_KEY_FRAME:
            # A key frame is kept aligned to its end, where the outermost frames are.
            self._key_frames[key] = [0] * (_KEY_FRAME_DEPTH - len(frames)) + list(frames)
            return frames
        if type_and_flags & _FLAG_DELTA:
            key_frame = self._key_frames.get(key)
            if key_frame is None:
                return frames
            start = frame_word & 0xFFFF
            key_frame[start : start + len(frames)] = frames
            return tuple(key_frame[start:])
        return frames


@dataclasses.dataclass
class AllocationCategory:
    """The allocations of one kind: a class, or blocks of one size that have no class."""

    name: str
    #: Allocations that are still alive, and their size.
    persistent_count: int = 0
    persistent_bytes: int = 0
    #: Allocations that were freed during the recording.
    transient_count: int = 0
    #: Everything allocated, alive or freed.
    total_bytes: int = 0


class AllocationStatistics:
    """Sum heap events up into per-category statistics, as Instruments' Allocations summary does."""

    def __init__(self) -> None:
        self._live: dict[int, tuple[int, Optional[str]]] = {}
        self._freed: dict[str, AllocationCategory] = {}

    def add(self, event: AllocationEvent) -> None:
        """Account one event; anything but heap events is ignored."""
        if event.type == AllocationEventType.MALLOC:
            self._live[event.address] = (event.size, None)
        elif event.type == AllocationEventType.CLASS_NAME:
            live = self._live.get(event.address)
            if live is not None:
                self._live[event.address] = (live[0], event.name)
        elif event.type == AllocationEventType.REALLOC:
            moved = self._live.pop(event.argument, None)
            if moved is not None:
                self._account_freed(moved)
            self._live[event.address] = (event.size, None if moved is None else moved[1])
        elif event.type == AllocationEventType.FREE:
            freed = self._live.pop(event.address, None)
            if freed is not None:
                self._account_freed(freed)

    def categories(self) -> list[AllocationCategory]:
        """The categories seen so far, largest live size first."""
        categories = {name: dataclasses.replace(category) for name, category in self._freed.items()}
        for size, name in self._live.values():
            name = self._category_name(size, name)
            category = categories.setdefault(name, AllocationCategory(name))
            category.persistent_count += 1
            category.persistent_bytes += size
            category.total_bytes += size
        return sorted(categories.values(), key=lambda category: category.persistent_bytes, reverse=True)

    def _account_freed(self, allocation: tuple[int, Optional[str]]) -> None:
        size, name = allocation
        name = self._category_name(size, name)
        category = self._freed.setdefault(name, AllocationCategory(name))
        category.transient_count += 1
        category.total_bytes += size

    @staticmethod
    def _category_name(size: int, name: Optional[str]) -> str:
        return name if name is not None else f"Malloc {size} Bytes"


class AllocationsService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.objectalloc"

    def __init__(self, ctx: DTXContext) -> None:
        super().__init__(ctx)
        self.buffers: DTXQueue[bytes] = DTXQueue()

    def on_closed(self, reason: str = "") -> None:
        self.shutdown_queue(self.buffers)
        super().on_closed(reason)

    @dtx_method("preparedEnvironmentForLaunch:eventsMask:")
    async def prepared_environment_for_launch_events_mask_(
        self, environment: dict[str, Any], events_mask: int
    ) -> Optional[dict[str, Any]]: ...

    @dtx_method("attachToPid:eventsMask:")
    async def attach_to_pid_events_mask_(self, pid: int, events_mask: int) -> bool: ...

    @dtx_on_data
    async def _on_data(self, payload: bytes) -> None:
        await self.buffers.put(payload)


class Allocations(DtxService[AllocationsService]):
    """
    Record the memory events of a process through Instruments' Allocations channel.

    The events are produced by a library that has to be loaded into the process when it starts, so
    the process must be launched with the environment `launch_environment` returns, and then
    attached to::

        async with DvtProvider(lockdown) as dvt, ProcessControl(dvt) as process_control:
            async with Allocations(dvt) as allocations:
                environment = await allocations.launch_environment()
                pid = await process_control.launch(bundle_id, environment=environment)
                await allocations.attach(pid)
                async for event in allocations:
                    ...

    The device takes the target's task port, so on a production device this only works for apps
    that are debuggable (development-signed, with ``get-task-allow``). Each instance records one
    process.
    """

    async def launch_environment(
        self, environment: Optional[dict[str, Any]] = None, events_mask: int = MALLOC_EVENTS_MASK
    ) -> dict[str, Any]:
        """
        Get the environment a process has to be launched with for its events to be recorded.

        :param environment: environment variables to add the recording's own to.
        :param events_mask: the events to record, as a combination of the ``*_EVENTS_MASK`` values.
        :raises DvtException: if the device could not prepare a recording.
        """
        prepared = await self.service.prepared_environment_for_launch_events_mask_(environment or {}, events_mask)
        if prepared is None:
            raise DvtException("the device could not prepare an allocations recording")
        return prepared

    async def attach(self, pid: int, events_mask: int = MALLOC_EVENTS_MASK) -> None:
        """
        Start recording a process that was launched with `launch_environment`.

        :param pid: the process to record.
        :param events_mask: the events to record; the same mask the environment was prepared with.
        :raises ProcessInspectionError: if the device could not attach to the process.
        """
        try:
            attached = await self.service.attach_to_pid_events_mask_(pid, events_mask)
        except DTXNsError as e:
            reason = (e.error.user_info or {}).get("NSLocalizedDescription", e)
            raise ProcessInspectionError(pid, "record the allocations of", str(reason)) from e
        if not attached:
            raise ProcessInspectionError(pid, "record the allocations of")

    async def __aiter__(self) -> AsyncGenerator[AllocationEvent, None]:
        parser = AllocationEventParser()
        while True:
            try:
                buffer = await self.service.buffers.get()
            except QueueShutDown:
                return
            for event in parser.feed(buffer):
                yield event
