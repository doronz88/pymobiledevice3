import bisect
import dataclasses
import struct
from functools import cached_property
from typing import Any, Optional, Union, cast

from bpylist2 import archiver

from pymobiledevice3.dtx import DTXService, dtx_method
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import DvtException, ProcessInspectionError

_PRIMITIVE_ARRAY_HEADER = struct.Struct("<QQ")
_PRIMITIVE_INT32 = 3
_PRIMITIVE_INT64 = 6


def _parse_primitive_array(data: bytes) -> list[int]:
    """Decode a serialized DTX primitive array of unsigned integers."""
    _, length = _PRIMITIVE_ARRAY_HEADER.unpack_from(data)
    values: list[int] = []
    offset = _PRIMITIVE_ARRAY_HEADER.size
    end = offset + length
    while offset < end:
        (type_code,) = struct.unpack_from("<I", data, offset)
        offset += 4
        if type_code == _PRIMITIVE_INT32:
            values.append(struct.unpack_from("<I", data, offset)[0])
            offset += 4
        elif type_code == _PRIMITIVE_INT64:
            values.append(struct.unpack_from("<Q", data, offset)[0])
            offset += 8
        else:
            raise DvtException(f"unexpected primitive type {type_code} in a VM region record")
    return values


@dataclasses.dataclass(frozen=True)
class VMRegion:
    """One region of a process's virtual address space."""

    start: int
    size: int
    #: Current and maximum protection, as ``VM_PROT_*`` bits (read 1, write 2, execute 4).
    protection: int
    max_protection: int
    #: The ``SM_*`` share mode and the ``VM_MEMORY_*`` tag the region was allocated with.
    share_mode: int
    user_tag: int
    is_submap: bool
    external_pager: bool
    pages_resident: int
    pages_shared_now_private: int
    pages_swapped_out: int
    pages_dirtied: int
    ref_count: int
    #: Log2 of the page size the page counts are in.
    page_shift: int
    #: The mapped file, or a description such as ``thread 5aa5``; ``None`` for anonymous memory.
    path: Optional[str]
    #: The segment (``__TEXT``, ``__DATA``...) or region type, when known.
    type: Optional[str]

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> "VMRegion":
        values = _parse_primitive_array(cast(bytes, archive_obj.decode("dataList")))
        packed = values[4]
        return VMRegion(
            start=values[0],
            size=values[1],
            protection=values[2],
            max_protection=values[3],
            external_pager=bool(packed >> 24 & 0xFF),
            share_mode=packed >> 16 & 0xFF,
            user_tag=packed >> 8 & 0xFF,
            is_submap=bool(packed & 0xFF),
            pages_resident=values[5],
            pages_shared_now_private=values[6],
            pages_swapped_out=values[7],
            pages_dirtied=values[8],
            ref_count=values[9],
            # Older senders leave the page shift out; they are 16 KiB-page arm64 devices.
            page_shift=values[10] if len(values) > 10 else 14,
            path=cast(Optional[str], archive_obj.decode("path")),
            type=cast(Optional[str], archive_obj.decode("type")),
        )


@dataclasses.dataclass(frozen=True)
class VMSnapshot:
    """The virtual memory layout of a process at one moment."""

    #: Not sorted by address, and they can overlap.
    regions: list[VMRegion]
    #: Total virtual size in bytes, as computed by the device; less than the plain sum of `regions`.
    total_size: int
    #: Device ``mach_absolute_time()`` when the snapshot was taken.
    mach_absolute_time: int

    @cached_property
    def _images(self) -> list[tuple[int, int, str]]:
        return sorted(
            (region.start, region.start + region.size, region.path)
            for region in self.regions
            if region.type == "__TEXT" and region.path
        )

    def image_for_address(self, address: int) -> Optional[tuple[str, int]]:
        """
        Find the image whose code contains an address.

        :param address: an address of the process, such as a frame of a backtrace.
        :returns: the path of the image and the offset of the address from where it is loaded, or
            ``None`` if the address is not inside the ``__TEXT`` segment of any image.
        """
        index = bisect.bisect_right(self._images, (address, float("inf"), "")) - 1
        if index < 0:
            return None
        start, end, path = self._images[index]
        return (path, address - start) if address < end else None

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> "VMSnapshot":
        return VMSnapshot(
            # After the first snapshot of a process, a region that did not change is only named by
            # its start address; `VMTracking.snapshot` puts the region back.
            regions=list(cast(list[VMRegion], archive_obj.decode("VMStateRegions"))),
            total_size=cast(int, archive_obj.decode("VMStateTotalSize")),
            mach_absolute_time=cast(int, archive_obj.decode("VMStateMachAbsolute")),
        )


class _VMRegionAnnotation:
    """Per-region bookkeeping the snapshot also carries; not exposed."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> None:
        return None


def register_vm_tracking_classes() -> None:
    """Register the archive classes a VM snapshot is made of. Idempotent."""
    archiver.update_class_map({
        "XRVMState": VMSnapshot,
        "XRVMRegion": VMRegion,
        "XRVMRegionAnnotation": _VMRegionAnnotation,
    })


class VMTrackingService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.vmtracking"

    @dtx_method("setTargetPid:referenceDate:")
    async def set_target_pid_reference_date_(self, pid: int, reference_date: Any) -> None: ...

    @dtx_method("requestVMSnapshot")
    async def request_vm_snapshot(self) -> Optional[VMSnapshot]: ...


class VMTracking(DtxService[VMTrackingService]):
    """
    Read a process's virtual memory layout through Instruments' VM Tracker channel.

    The device takes the target's task port, so on a production device this only works for apps
    that are debuggable (development-signed, with ``get-task-allow``).

    Constructed with a `DvtProvider` and used as an async context manager. Each instance tracks one
    process, which can be captured any number of times.
    """

    _pid: Optional[int] = None
    _previous: Optional[VMSnapshot] = None

    async def snapshot(self, pid: int) -> VMSnapshot:
        """
        Capture the regions of a process.

        :param pid: the process to inspect; the same one on every call.
        :raises ProcessInspectionError: if the device could not inspect the process.
        """
        register_vm_tracking_classes()
        if self._pid is None:
            await self.service.set_target_pid_reference_date_(pid, None)
            self._pid = pid
        elif pid != self._pid:
            raise DvtException(f"this instance already tracks pid {self._pid}")
        snapshot = await self.service.request_vm_snapshot()
        if snapshot is None or not snapshot.regions:
            raise ProcessInspectionError(pid, "read the memory regions of")
        snapshot = dataclasses.replace(snapshot, regions=self._restore_unchanged_regions(snapshot.regions))
        self._previous = snapshot
        return snapshot

    def _restore_unchanged_regions(self, regions: list[VMRegion]) -> list[VMRegion]:
        """Replace the start addresses the device sends for unchanged regions with those regions."""
        previous: dict[int, list[VMRegion]] = {}
        for region in self._previous.regions if self._previous is not None else ():
            previous.setdefault(region.start, []).append(region)
        restored: list[VMRegion] = []
        for region in cast(list[Union[VMRegion, int]], regions):
            if isinstance(region, VMRegion):
                restored.append(region)
                continue
            unchanged = previous.get(region)
            if not unchanged:
                raise DvtException(f"the device referred to an unknown memory region at {region:#x}")
            # Regions that start at the same address come back in the order they were first sent.
            restored.append(unchanged.pop(0) if len(unchanged) > 1 else unchanged[0])
        return restored
