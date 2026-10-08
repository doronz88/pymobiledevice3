from typing import Any, Optional, cast

import pytest

from pymobiledevice3.cli.developer import dvt as dvt_cli
from pymobiledevice3.cli.developer.dvt import AllocationBacktraceFormatter

pytestmark = pytest.mark.asyncio


class FakeSnapshot:
    def __init__(self, images: dict[int, tuple[str, int]]) -> None:
        self._images = images

    def image_for_address(self, address: int) -> Optional[tuple[str, int]]:
        return self._images.get(address)


class FakeVMTracking:
    def __init__(self, *snapshots: FakeSnapshot) -> None:
        self.snapshots = list(snapshots)
        self.pids: list[int] = []

    async def snapshot(self, pid: int) -> FakeSnapshot:
        self.pids.append(pid)
        return self.snapshots.pop(0)


async def test_backtrace_frames_are_formatted_as_image_and_offset() -> None:
    vm_tracking = FakeVMTracking(FakeSnapshot({0x1010: ("/usr/lib/libA.dylib", 0x10)}))
    formatter = AllocationBacktraceFormatter(cast(Any, vm_tracking), 77)

    assert await formatter.format((0x1010, 0x2)) == ["libA.dylib+0x10", "0x2"]
    assert vm_tracking.pids == [77]


async def test_images_are_looked_up_again_only_after_an_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 100.0
    monkeypatch.setattr(dvt_cli.time, "monotonic", lambda: now)
    vm_tracking = FakeVMTracking(FakeSnapshot({}), FakeSnapshot({0x2020: ("/usr/lib/libB.dylib", 0x20)}))
    formatter = AllocationBacktraceFormatter(cast(Any, vm_tracking), 77)

    assert await formatter.format((0x2020,)) == ["0x2020"]
    assert await formatter.format((0x2020,)) == ["0x2020"]
    assert len(vm_tracking.pids) == 1

    now += dvt_cli.ALLOCATION_IMAGES_REFRESH_INTERVAL
    assert await formatter.format((0x2020,)) == ["libB.dylib+0x20"]
    assert len(vm_tracking.pids) == 2
