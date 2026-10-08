import asyncio
import contextlib
import struct
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.dtx import NSError, PInt64
from pymobiledevice3.dtx.exceptions import DTXNsError
from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    ProcessInspectionError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.services.dvt.instruments.allocations import (
    AllocationEvent,
    AllocationEventParser,
    AllocationEventType,
    Allocations,
    AllocationStatistics,
)
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.dyld_metrics import DyldMetrics
from pymobiledevice3.services.dvt.instruments.leaks import Leaks
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.vm_tracking import VMRegion, VMSnapshot, VMTracking
from pymobiledevice3.services.installation_proxy import InstallationProxyService

SYSTEM_APP = "com.apple.mobilesafari"
KEY_FRAME = 0x400000
DELTA = 0x800000
THREAD = 0x1F2136880


class FakeArchive:
    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values

    def decode(self, key: str) -> Any:
        return self._values.get(key)


def primitive_array(values: list[tuple[int, int]]) -> bytes:
    body = b"".join(struct.pack("<IQ" if kind == 6 else "<II", kind, value) for kind, value in values)
    return struct.pack("<QQ", 0x1F0, len(body)) + body


def region_archive(path: Optional[str] = "/usr/lib/dyld") -> FakeArchive:
    data = primitive_array([
        (6, 0x104440000),
        (6, 0x8000),
        (3, 5),
        (3, 7),
        (3, 1 << 24 | 2 << 16 | 30 << 8),
        (3, 2),
        (3, 0),
        (3, 1),
        (3, 3),
        (3, 4),
        (3, 14),
    ])
    return FakeArchive({"dataList": data, "path": path, "type": "__TEXT"})


def test_vm_region_is_decoded_from_its_archive() -> None:
    region = VMRegion.decode_archive(cast(Any, region_archive()))

    assert region == VMRegion(
        start=0x104440000,
        size=0x8000,
        protection=5,
        max_protection=7,
        share_mode=2,
        user_tag=30,
        is_submap=False,
        external_pager=True,
        pages_resident=2,
        pages_shared_now_private=0,
        pages_swapped_out=1,
        pages_dirtied=3,
        ref_count=4,
        page_shift=14,
        path="/usr/lib/dyld",
        type="__TEXT",
    )


def test_vm_region_rejects_an_unknown_primitive() -> None:
    archive = FakeArchive({"dataList": struct.pack("<QQI", 0x1F0, 4, 9)})

    with pytest.raises(PyMobileDevice3Exception, match="unexpected primitive type 9"):
        VMRegion.decode_archive(cast(Any, archive))


class FakeVMTrackingService:
    def __init__(self, *snapshots: Optional[VMSnapshot]) -> None:
        self.snapshots = list(snapshots)
        self.targets: list[int] = []

    async def set_target_pid_reference_date_(self, pid: int, reference_date: Any) -> None:
        self.targets.append(pid)

    async def request_vm_snapshot(self) -> Optional[VMSnapshot]:
        return self.snapshots.pop(0)


def region(start: int, size: int = 0x4000, path: Optional[str] = None, segment: Optional[str] = None) -> VMRegion:
    return VMRegion(
        start=start,
        size=size,
        protection=5,
        max_protection=5,
        share_mode=1,
        user_tag=0,
        is_submap=False,
        external_pager=False,
        pages_resident=1,
        pages_shared_now_private=0,
        pages_swapped_out=0,
        pages_dirtied=0,
        ref_count=1,
        page_shift=14,
        path=path,
        type=segment,
    )


def snapshot_of(*regions: Any) -> VMSnapshot:
    return VMSnapshot(regions=list(regions), total_size=1, mach_absolute_time=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("snapshot", [None, VMSnapshot(regions=[], total_size=0, mach_absolute_time=1)])
async def test_vm_snapshot_without_regions_is_an_error(snapshot: Optional[VMSnapshot]) -> None:
    service = FakeVMTrackingService(snapshot)
    vm_tracking = VMTracking(cast(Any, None), service=cast(Any, service))

    with pytest.raises(ProcessInspectionError, match="must be debuggable"):
        await vm_tracking.snapshot(77)
    assert service.targets == [77]


@pytest.mark.asyncio
async def test_later_vm_snapshots_get_their_unchanged_regions_back() -> None:
    text, heap, grown = region(0x1000), region(0x8000), region(0x8000, size=0x8000)
    # Two regions start at the same address, as a submap and the region mapped inside it do.
    outer, inner = region(0x20000, size=0x10000), region(0x20000)
    service = FakeVMTrackingService(
        snapshot_of(text, heap, outer, inner),
        snapshot_of(0x1000, grown, 0x20000, 0x20000),
        snapshot_of(0x1000, 0x8000, 0x20000, 0x20000),
    )
    vm_tracking = VMTracking(cast(Any, None), service=cast(Any, service))

    assert (await vm_tracking.snapshot(77)).regions == [text, heap, outer, inner]
    assert (await vm_tracking.snapshot(77)).regions == [text, grown, outer, inner]
    assert (await vm_tracking.snapshot(77)).regions == [text, grown, outer, inner]
    assert service.targets == [77]


@pytest.mark.asyncio
async def test_vm_snapshot_rejects_a_reference_to_an_unknown_region() -> None:
    service = FakeVMTrackingService(snapshot_of(region(0x1000)), snapshot_of(0x2000))
    vm_tracking = VMTracking(cast(Any, None), service=cast(Any, service))
    await vm_tracking.snapshot(77)

    with pytest.raises(PyMobileDevice3Exception, match="unknown memory region at 0x2000"):
        await vm_tracking.snapshot(77)


@pytest.mark.asyncio
async def test_vm_tracking_follows_a_single_process() -> None:
    service = FakeVMTrackingService(snapshot_of(region(0x1000)))
    vm_tracking = VMTracking(cast(Any, None), service=cast(Any, service))
    await vm_tracking.snapshot(77)

    with pytest.raises(PyMobileDevice3Exception, match="already tracks pid 77"):
        await vm_tracking.snapshot(78)


def test_image_for_address_only_matches_code() -> None:
    snapshot = snapshot_of(
        region(0x30000, path="/usr/lib/libB.dylib", segment="__TEXT"),
        region(0x10000, size=0x8000, path="/usr/lib/libA.dylib", segment="__TEXT"),
        region(0x18000, path="/usr/lib/libA.dylib", segment="__DATA"),
        region(0x40000),
    )

    assert snapshot.image_for_address(0x10000) == ("/usr/lib/libA.dylib", 0)
    assert snapshot.image_for_address(0x17FFF) == ("/usr/lib/libA.dylib", 0x7FFF)
    assert snapshot.image_for_address(0x30010) == ("/usr/lib/libB.dylib", 0x10)
    for address in (0xFFFF, 0x18000, 0x40000, 0x50000):
        assert snapshot.image_for_address(address) is None


class FakeLeaksService:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.requests: list[tuple[Any, dict[str, Any]]] = []

    async def request_graph_options_(self, pid: Any, options: dict[str, Any]) -> Any:
        self.requests.append((pid, options))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.mark.asyncio
async def test_memory_graph_sends_the_pid_as_a_64_bit_primitive() -> None:
    service = FakeLeaksService({"SerializedGraph": b"bplist00", "LeakedCount": 2, "LeakedAddresses": [16, 32]})
    leaks = Leaks(cast(Any, None), service=cast(Any, service))

    graph = await leaks.memory_graph(77, leaked_only=True)

    pid, options = service.requests[0]
    assert isinstance(pid, PInt64)
    assert pid == 77
    assert options == {"LeakedCount": True, "LeakedAddresses": True, "LeakedGraphOnly": True}
    assert (graph.data, graph.leaked_count, graph.leaked_addresses) == (b"bplist00", 2, [16, 32])


@pytest.mark.asyncio
async def test_memory_graph_reports_the_device_error() -> None:
    error = DTXNsError(
        NSError(-1, "DTLeaksService", {"NSLocalizedDescription": "Unable to acquire required task port"})
    )
    leaks = Leaks(cast(Any, None), service=cast(Any, FakeLeaksService(error)))

    with pytest.raises(ProcessInspectionError, match="pid 77: Unable to acquire required task port") as raised:
        await leaks.memory_graph(77)
    assert (raised.value.pid, raised.value.reason) == (77, "Unable to acquire required task port")


@pytest.mark.asyncio
async def test_leaked_only_memory_graph_of_a_process_without_leaks_has_no_data() -> None:
    service = FakeLeaksService({"LeakedCount": 0, "LeakedAddresses": []})
    leaks = Leaks(cast(Any, None), service=cast(Any, service))

    graph = await leaks.memory_graph(77, leaked_only=True)

    assert (graph.data, graph.leaked_count, graph.leaked_addresses) == (None, 0, [])


@pytest.mark.asyncio
async def test_memory_graph_without_a_graph_is_an_error() -> None:
    leaks = Leaks(cast(Any, None), service=cast(Any, FakeLeaksService({})))

    with pytest.raises(ProcessInspectionError, match="returned no graph"):
        await leaks.memory_graph(77)


class FakeDyldMetricsService:
    def __init__(self, answer: bytes) -> None:
        self.snapshots: asyncio.Queue[bytes] = asyncio.Queue()
        self.snapshots.put_nowait(answer)
        self.requests: list[dict[str, Any]] = []

    async def send_keyed_message(self, values: dict[str, Any]) -> None:
        self.requests.append(values)


@pytest.mark.asyncio
async def test_dyld_metrics_are_requested_with_a_keyed_message() -> None:
    service = FakeDyldMetricsService(b'{"pid":77,"counts":{"images":2}}')
    dyld_metrics = DyldMetrics(cast(Any, None), service=cast(Any, service))

    assert await dyld_metrics.capture(77, at_main=True) == {"pid": 77, "counts": {"images": 2}}
    assert service.requests == [{"command": "captureMetrics", "pid": 77, "atMain": 1, "pollingIntervalMs": 250}]


@pytest.mark.asyncio
async def test_dyld_metrics_report_the_device_error() -> None:
    service = FakeDyldMetricsService(b'{"error":"Failed to get task port for pid 77"}')
    dyld_metrics = DyldMetrics(cast(Any, None), service=cast(Any, service))

    with pytest.raises(ProcessInspectionError, match="pid 77: Failed to get task port"):
        await dyld_metrics.capture(77)


def record(
    event_type: int, frame_word: int, words: list[int], address: int = 0, argument: int = 0, size: int = 0
) -> bytes:
    header = struct.pack("<dIIQQQQ", 1000.0, event_type, frame_word, address ^ 0x5555, argument, THREAD, size)
    return header + struct.pack(f"<{len(words) + 1}Q", *words, len(words))


def name_words(name: str) -> list[int]:
    raw = name.encode() + b"\0"
    raw += b"\0" * (-len(raw) % 8)
    return list(struct.unpack(f"<{len(raw) // 8}Q", raw))


def test_allocation_backtraces_are_expanded_from_key_frames() -> None:
    malloc = AllocationEventType.MALLOC
    stream = (
        record(malloc | KEY_FRAME, 3, [0x30, 0x20, 0x10], address=0x1000, size=32)
        # Two new innermost frames over the outermost one of the key frame.
        + record(malloc | DELTA, 2 << 16 | 509, [0x50, 0x40], address=0x2000, size=64)
        # Nothing new: the two outermost frames of the previous event.
        + record(malloc | DELTA, 510, [], address=0x3000, size=16)
    )

    events = list(AllocationEventParser().feed(stream))

    assert [(event.address, event.size, event.backtrace) for event in events] == [
        (0x1000, 32, (0x30, 0x20, 0x10)),
        (0x2000, 64, (0x50, 0x40, 0x10)),
        (0x3000, 16, (0x40, 0x10)),
    ]
    assert all(event.type == malloc and event.thread == THREAD and event.timestamp == 1000 for event in events)


def test_allocation_names_are_expanded_like_backtraces() -> None:
    class_name = AllocationEventType.CLASS_NAME
    leaky, other = name_words("LeakyNode"), name_words("LeakyNodf")
    stream = (
        record(class_name | KEY_FRAME, 2, leaky, address=0x1000, size=9)
        # The same name again travels as no words at all.
        + record(class_name | DELTA, 510, [], address=0x2000, size=9)
        # A name that shares its last word only sends the first one.
        + record(class_name | DELTA, 1 << 16 | 510, other[:1], address=0x3000, size=9)
    )

    events = list(AllocationEventParser().feed(stream))

    assert [(event.address, event.name, event.backtrace) for event in events] == [
        (0x1000, "LeakyNode", ()),
        (0x2000, "LeakyNode", ()),
        (0x3000, "LeakyNode", ()),
    ]


def test_allocation_events_split_across_buffers_are_joined() -> None:
    stream = record(AllocationEventType.MALLOC | KEY_FRAME, 2, [0x20, 0x10], address=0x1000, size=32)
    parser = AllocationEventParser()

    assert list(parser.feed(stream[:60])) == []
    (event,) = parser.feed(stream[60:])
    assert (event.address, event.backtrace) == (0x1000, (0x20, 0x10))


def test_realloc_carries_the_address_it_moved_from() -> None:
    stream = record(AllocationEventType.REALLOC, 0, [], address=0x2000, argument=0x1000 ^ 0x5555, size=64)

    (event,) = AllocationEventParser().feed(stream)

    assert (event.address, event.argument, event.size) == (0x2000, 0x1000, 64)


def event(
    event_type: int, address: int, size: int = 0, argument: int = 0, name: Optional[str] = None
) -> AllocationEvent:
    return AllocationEvent(
        timestamp=0, type=event_type, address=address, argument=argument, thread=0, size=size, backtrace=(), name=name
    )


def test_allocation_statistics_group_by_class_or_size() -> None:
    statistics = AllocationStatistics()
    for item in (
        event(AllocationEventType.MALLOC, 0x1000, 32),
        event(AllocationEventType.CLASS_NAME, 0x1000, name="LeakyNode"),
        event(AllocationEventType.MALLOC, 0x2000, 32),
        event(AllocationEventType.CLASS_NAME, 0x2000, name="LeakyNode"),
        event(AllocationEventType.FREE, 0x2000),
        event(AllocationEventType.MALLOC, 0x3000, 1024),
        event(AllocationEventType.REALLOC, 0x4000, 2048, argument=0x3000),
        event(AllocationEventType.FREE, 0x9000),
        event(AllocationEventType.RETAIN, 0x1000),
    ):
        statistics.add(item)

    categories = {category.name: category for category in statistics.categories()}

    assert statistics.categories()[0].name == "Malloc 2048 Bytes"
    leaky = categories["LeakyNode"]
    assert (leaky.persistent_count, leaky.persistent_bytes, leaky.transient_count, leaky.total_bytes) == (1, 32, 1, 64)
    assert categories["Malloc 1024 Bytes"].transient_count == 1
    assert categories["Malloc 2048 Bytes"].persistent_bytes == 2048


async def debuggable_app(service_provider) -> str:
    """The bundle identifier of an installed app the device lets Instruments inspect."""
    async with InstallationProxyService(service_provider) as installation_proxy:
        apps = await installation_proxy.get_apps(application_type="User")
    for bundle_id, app in apps.items():
        if app.get("Entitlements", {}).get("get-task-allow"):
            return bundle_id
    pytest.skip("no development-signed app is installed on the device")


@pytest.mark.asyncio
async def test_memory_channels_refuse_a_system_app(dvt) -> None:
    async with ProcessControl(dvt) as process_control:
        pid = await process_control.launch(SYSTEM_APP)
        async with VMTracking(dvt) as vm_tracking:
            with pytest.raises(ProcessInspectionError, match="must be debuggable"):
                await vm_tracking.snapshot(pid)
        async with Leaks(dvt) as leaks:
            with pytest.raises(ProcessInspectionError, match="task port"):
                await leaks.memory_graph(pid)
        async with DyldMetrics(dvt) as dyld_metrics:
            with pytest.raises(ProcessInspectionError, match="task port"):
                await dyld_metrics.capture(pid)


@pytest.mark.asyncio
async def test_memory_of_a_debuggable_app(dvt, service_provider) -> None:
    bundle_id = await debuggable_app(service_provider)
    async with ProcessControl(dvt) as process_control, Allocations(dvt) as allocations:
        environment = await allocations.launch_environment()
        pid = await process_control.launch(bundle_id, environment=environment, kill_existing=True)
        try:
            try:
                await allocations.attach(pid)
            except (ProcessInspectionError, ConnectionTerminatedError):
                # The device drops the connection when the app dies while it is being attached to.
                pytest.skip(f"{bundle_id} exited right after launch")
            events: list[AllocationEvent] = []

            async def record_events() -> None:
                async for item in allocations:
                    events.append(item)

            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(record_events(), 3)
            async with DeviceInfo(dvt) as device_info:
                if pid not in [process["pid"] for process in await device_info.proclist()]:
                    pytest.skip(f"{bundle_id} exited right after launch")
            mallocs = [item for item in events if item.type == AllocationEventType.MALLOC]
            assert mallocs
            assert all(item.address % 16 == 0 for item in mallocs)
            assert any(len(item.backtrace) > 1 for item in mallocs)
            names = {item.name for item in events if item.type == AllocationEventType.CLASS_NAME}
            assert names
            assert all(name and name.isprintable() for name in names)

            async with VMTracking(dvt) as vm_tracking:
                first_snapshot = await vm_tracking.snapshot(pid)
                snapshot = await vm_tracking.snapshot(pid)
            assert all(isinstance(item, VMRegion) for item in snapshot.regions)
            assert abs(len(snapshot.regions) - len(first_snapshot.regions)) < len(first_snapshot.regions) / 2
            frames = [frame for item in mallocs[-100:] for frame in item.backtrace]
            assert sum(snapshot.image_for_address(frame) is not None for frame in frames) > len(frames) / 2
            assert 0 < snapshot.total_size <= sum(region.size for region in snapshot.regions)
            assert any(region.type == "__TEXT" for region in snapshot.regions)

            async with DyldMetrics(dvt) as dyld_metrics:
                metrics = await dyld_metrics.capture(pid)
            assert metrics["pid"] == pid
            assert metrics["counts"]["images"] > 1
            assert metrics["timing"]["init"] <= metrics["timing"]["main"]

            async with Leaks(dvt) as leaks:
                graph = await leaks.memory_graph(pid)
            assert graph.data is not None
            assert graph.data.startswith(b"bplist00")
            assert graph.leaked_count == len(graph.leaked_addresses)
        finally:
            with contextlib.suppress(ConnectionTerminatedError):
                await process_control.kill(pid)
