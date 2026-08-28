import ctypes
import ctypes.util
import datetime
import logging
import shutil
import struct
import sys
import warnings
from collections.abc import Awaitable, Iterable, Mapping, Sequence
from io import BufferedWriter
from pathlib import Path
from typing import Any, Callable, Optional, cast

from pymobiledevice3.exceptions import NotEnoughDiskSpaceError, PyMobileDevice3Exception
from pymobiledevice3.service_connection import ServiceConnection

SIZE_FORMAT = ">I"
CODE_FORMAT = ">B"
CODE_FILE_DATA = 0xC
CODE_ERROR_REMOTE = 0xB
CODE_ERROR_LOCAL = 0x6
CODE_SUCCESS = 0
FILE_TRANSFER_TERMINATOR = b"\x00\x00\x00\x00"
BULK_OPERATION_ERROR = -13
PURGE_DISK_SPACE_ERROR = -1
PURGE_DISK_SPACE_ERROR_STRING = "DLPurgeDiskSpace failed to purge"
# `-[MBDriveBackupEngine _prepareFreeSpace]` pads every purge request by this much beyond the
# space it actually needs, so `CACHE_DELETE_AMOUNT` overstates the requirement by a flat 2 GiB.
# See `purge_disk_space()` for how this was measured.
PURGE_REQUEST_OVERSHOOT = 0x80000000
# MBErrorDomain/105, the device's own verdict once the host answers the purge request.
MB_ERROR_INSUFFICIENT_DISK_SPACE = 105
APPLE_EPOCH = 978307200
ERRNO_TO_DEVICE_ERROR = {
    2: -6,
    17: -7,
    20: -8,
    21: -9,
    62: -10,
    5: -11,
    28: -15,
}

DLMessage = Sequence[Any]
ProgressCallback = Callable[[Any], None]
DLHandler = Callable[[DLMessage], Awaitable[None]]

logger = logging.getLogger(__name__)


def _darwin_important_available_capacity(path: Path) -> Optional[int]:
    """Return the purgeable-aware free space macOS is willing to hand to writes.

    ``shutil.disk_usage().free`` (statvfs) excludes APFS purgeable space (local
    Time Machine snapshots, evictable iCloud files) that the OS reclaims on
    demand, so it under-reports available capacity by tens of GB. This mirrors
    Finder/iTunes by reading NSURL's
    ``NSURLVolumeAvailableCapacityForImportantUsageKey`` via the Objective-C
    runtime. Returns ``None`` on any failure so callers fall back to statvfs.
    """
    try:
        objc = ctypes.CDLL(ctypes.util.find_library("objc"))
        foundation = ctypes.CDLL(ctypes.util.find_library("Foundation"))
    except (OSError, TypeError):
        return None

    objc.objc_getClass.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = [ctypes.c_char_p]
    objc.sel_registerName.restype = ctypes.c_void_p
    objc.sel_registerName.argtypes = [ctypes.c_char_p]

    def msg(
        restype: Any, receiver: Any, selector: bytes, argtypes: Sequence[Any] = (), args: Sequence[Any] = ()
    ) -> Any:
        send = objc.objc_msgSend
        send.restype = restype
        send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, *argtypes]
        return send(receiver, objc.sel_registerName(selector), *args)

    try:
        key = ctypes.c_void_p.in_dll(foundation, "NSURLVolumeAvailableCapacityForImportantUsageKey")

        ns_string = objc.objc_getClass(b"NSString")
        ns_path = msg(ctypes.c_void_p, ns_string, b"stringWithUTF8String:", [ctypes.c_char_p], [str(path).encode()])
        ns_url = objc.objc_getClass(b"NSURL")
        url = msg(ctypes.c_void_p, ns_url, b"fileURLWithPath:", [ctypes.c_void_p], [ns_path])
        if not url:
            return None

        value = ctypes.c_void_p(0)
        error = ctypes.c_void_p(0)
        ok = msg(
            ctypes.c_bool,
            url,
            b"getResourceValue:forKey:error:",
            [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            [ctypes.byref(value), key, ctypes.byref(error)],
        )
        if not ok or not value.value:
            return None
        return int(msg(ctypes.c_longlong, value, b"longLongValue"))
    except (ValueError, OSError):
        return None


class DeviceLink:
    def __init__(
        self,
        service: ServiceConnection,
        root_path: Path,
        preserve_file: Optional[Callable[[str, str], bool]] = None,
        post_file_receive: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.service: ServiceConnection = service
        self.root_path: Path = root_path
        self.preserve_file = preserve_file
        self.post_file_receive = post_file_receive
        self._discarded_files: set[Path] = set()
        # Last figure answered to `DLMessageGetFreeDiskSpace`, and the requirement derived from it
        # when the device follows up with a purge request. See `purge_disk_space()`.
        self._reported_free_space: Optional[int] = None
        self._required_free_space: Optional[int] = None
        self._dl_handlers: dict[str, DLHandler] = {
            "DLMessageCreateDirectory": self.create_directory,
            "DLMessageUploadFiles": self.upload_files,
            "DLMessageGetFreeDiskSpace": self.get_free_disk_space,
            "DLMessageMoveItems": self.move_items,
            "DLMessageRemoveItems": self.remove_items,
            "DLMessageDownloadFiles": self.download_files,
            "DLContentsOfDirectory": self.contents_of_directory,
            "DLMessageCopyItem": self.copy_item,
            "DLMessagePurgeDiskSpace": self.purge_disk_space,
        }

    async def _sendall(self, payload: bytes) -> None:
        await self.service.sendall(payload)

    async def _recvall(self, size: int) -> bytes:
        return await self.service.recvall(size)

    async def dl_loop(self, progress_callback: Optional[ProgressCallback] = None) -> Any:
        def _noop(_: Any) -> None:
            return None

        callback: ProgressCallback = progress_callback if progress_callback is not None else _noop

        while True:
            message = await self.receive_message()
            command = message[0]

            if command in (
                "DLMessageDownloadFiles",
                "DLMessageMoveFiles",
                "DLMessageMoveItems",
                "DLMessageRemoveFiles",
                "DLMessageRemoveItems",
            ):
                callback(message[3])
            elif command == "DLMessageUploadFiles":
                callback(message[2])

            if command == "DLMessageProcessMessage":
                if not message[1]["ErrorCode"]:
                    return message[1].get("Content")
                elif message[1]["ErrorCode"] == MB_ERROR_INSUFFICIENT_DISK_SPACE:
                    raise NotEnoughDiskSpaceError(self._insufficient_disk_space_error(message[1]))
                else:
                    raise PyMobileDevice3Exception(f"Device link error: {message[1]}")
            await self._dl_handlers[command](message)

    def _insufficient_disk_space_error(self, response: Mapping[str, Any]) -> str:
        """Describe an ``MBErrorDomain/105`` refusal in terms of the bytes involved.

        The device only reaches this after the host has answered its purge request, so
        :meth:`purge_disk_space` has normally already recovered the threshold the device is
        comparing against. Without it - an unrecognised amount, or a 105 that arrived with no
        preceding purge - fall back to the device's own wording.

        The requirement can dwarf the device's used space, which reads as a bug until you see how
        it is accumulated. ``-[MBDriveBackupEngine _addFileToUploadAndMove:flags:]`` tags each
        upload operation with a two-bit flag - bit 0 when the file hardlinks an inode already seen
        in this backup, bit 1 when it clones an already-seen ``cloneID``::

            v9 = 0;
            if ([file isHardLink])
                if ([_inodeCache containsObject:file.inodeNumber])  v9 = 1;
                else [_inodeCache addObject:file.inodeNumber];
            if ([file isFullClone])
                if ([_cloneIDCache containsObject:file.cloneID])    v9 |= 2;
                else [_cloneIDCache addObject:file.cloneID];
            op = [MBBackupOperation backupOperationWithType:2 ... size:file.size flags:v9];

        ``-[MBBackupOperationJournal addOperation:]`` then adds ``op.size`` to ``_sizeByType``
        unconditionally, and to ``_sizeExcludingHardlinksAndClonesForType`` only when both bits are
        clear. ``_prepareFreeSpace`` gates on the former, so every repeat reference counts at full
        size. That is not an over-estimate: :meth:`upload_files` writes each file to its own path
        under the backup root, so a device-side clone family really does land as N full copies.

        The device logs both totals as ``uploadSize:<inclusive>(<excluding>)`` before the
        free-space check, which is the cheapest way to see how far the two diverge.
        """
        detail = (
            " The device counts every hardlink and clone at full size, because each is stored as a "
            "separate file in the backup, so this can far exceed the data stored on the device."
        )
        if self._required_free_space is None or self._reported_free_space is None:
            return f"Device refused the backup: {response}.{detail}"
        return (
            f"Device refused the backup: it needs more than {self._required_free_space} bytes free "
            f"at {self.root_path}, host reported {self._reported_free_space} "
            f"({self._required_free_space + 1 - self._reported_free_space} more needed) "
            f"(MBErrorDomain/{MB_ERROR_INSUFFICIENT_DISK_SPACE}).{detail}"
        )

    async def version_exchange(self) -> None:
        dl_message_version_exchange = await self.receive_message()
        version_major = dl_message_version_exchange[1]
        await self.service.send_plist(["DLMessageVersionExchange", "DLVersionsOk", version_major])
        dl_message_device_ready = await self.receive_message()
        if dl_message_device_ready[0] != "DLMessageDeviceReady":
            raise PyMobileDevice3Exception("Device link didn't return ready state")

    async def send_process_message(self, message: Mapping[str, Any]) -> None:
        await self.service.send_plist(["DLMessageProcessMessage", message])

    async def download_files(self, message: DLMessage) -> None:
        status: dict[str, dict[str, Any]] = {}
        files = cast(Iterable[str], message[1])
        for file in files:
            file_bytes = file.encode()
            await self._sendall(struct.pack(SIZE_FORMAT, len(file_bytes)) + file_bytes)

            try:
                file_path = self.root_path / file

                # Split each file into small protocol frames. BackupAgent2 buffers a whole
                # frame in memory before flushing it to disk, so large frames drive its RSS
                # up: on an incremental backup the host sends the previous Manifest.db back
                # (via DLMessageDownloadFiles) for the device to diff, and a big Manifest.db
                # (issues #1165, #1857) pushes BackupAgent2 past its jetsam memory limit --
                # the process is killed mid-transfer and the backup hangs at 0%.
                #
                # Apple's own DeviceLink.framework (the host side Finder uses) sends file
                # data in 32 KiB frames by default (the "BufferSize" preference under
                # com.apple.DeviceLink; _DLSendFileForBulkOperation reads BufferSize-1 bytes
                # per frame), so match that. Measured against a 1.55 GB Manifest.db: 128 MiB
                # frames breach the device memory limit and crawl at ~8.5 MB/s, while 32 KiB
                # frames stay under it and run ~4.6x faster (same ~40 MB/s as 1 MiB).
                chunk_size = 32 * 1024  # 32 KiB, matching Apple's DeviceLink BufferSize default

                with file_path.open("rb") as file_handle:
                    while True:
                        chunk_data = file_handle.read(chunk_size)
                        if not chunk_data:
                            break
                        await self._sendall(
                            struct.pack(SIZE_FORMAT, len(chunk_data) + struct.calcsize(CODE_FORMAT))
                            + struct.pack(CODE_FORMAT, CODE_FILE_DATA)
                            + chunk_data
                        )

                buffer = struct.pack(SIZE_FORMAT, struct.calcsize(CODE_FORMAT)) + struct.pack(CODE_FORMAT, CODE_SUCCESS)
                await self._sendall(buffer)
            except OSError as e:
                # file-operation OSErrors always carry errno/strerror
                assert e.errno is not None and e.strerror is not None
                status[file] = {
                    "DLFileErrorString": e.strerror,
                    "DLFileErrorCode": ctypes.c_uint64(ERRNO_TO_DEVICE_ERROR[e.errno]).value,
                }
                error_bytes = e.strerror.encode()
                await self._sendall(
                    struct.pack(SIZE_FORMAT, len(error_bytes) + struct.calcsize(CODE_FORMAT))
                    + struct.pack(CODE_FORMAT, CODE_ERROR_LOCAL)
                    + error_bytes
                )

        await self._sendall(FILE_TRANSFER_TERMINATOR)
        if status:
            await self.status_response(BULK_OPERATION_ERROR, "Multi status", status)
        else:
            await self.status_response(0)

    async def contents_of_directory(self, message: DLMessage) -> None:
        data = {}
        path = self.root_path / cast(str, message[1])
        for file in path.iterdir():
            ftype = "DLFileTypeUnknown"
            if file.is_dir():
                ftype = "DLFileTypeDirectory"
            if file.is_file():
                ftype = "DLFileTypeRegular"
            modifications_data = datetime.datetime.fromtimestamp(file.stat().st_mtime - APPLE_EPOCH)
            modifications_data = modifications_data.replace(tzinfo=None)
            data[file.name] = {
                "DLFileType": ftype,
                "DLFileSize": file.stat().st_size,
                "DLFileModificationDate": modifications_data,
            }
        await self.status_response(0, status_dict=data)

    async def upload_files(self, _message: DLMessage) -> None:
        while True:
            device_name = await self._prefixed_recv()
            if not device_name:
                break
            file_name = await self._prefixed_recv()
            (size,) = struct.unpack(SIZE_FORMAT, await self._recvall(struct.calcsize(SIZE_FORMAT)))
            (code,) = struct.unpack(CODE_FORMAT, await self._recvall(struct.calcsize(CODE_FORMAT)))
            size -= struct.calcsize(CODE_FORMAT)
            should_preserve = self.preserve_file(file_name, device_name) if self.preserve_file is not None else True
            if should_preserve:
                with open(self.root_path / file_name, "wb") as fd:
                    size, code = await self._consume_file_transfer(size, code, fd)
            else:
                path = self.root_path / file_name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
                self._discarded_files.add(Path(file_name))
                size, code = await self._consume_file_transfer(size, code)
            if code == CODE_ERROR_REMOTE:
                # iOS 17 beta devices give this error for: backup_manifest.db
                error_message = (await self._recvall(size)).decode()
                warnings.warn(
                    f"Failed to fully upload: {file_name}. Device file name: {device_name}. Reason: {error_message}",
                    stacklevel=2,
                )
                continue
            assert code == CODE_SUCCESS
            if self.post_file_receive is not None:
                self.post_file_receive(file_name, device_name)
        await self.status_response(0)

    async def _consume_file_transfer(
        self, size: int, code: int, destination: Optional[BufferedWriter] = None
    ) -> tuple[int, int]:
        while size and code == CODE_FILE_DATA:
            chunk = await self._recvall(size)
            if destination is not None:
                destination.write(chunk)
            (size,) = struct.unpack(SIZE_FORMAT, await self._recvall(struct.calcsize(SIZE_FORMAT)))
            (code,) = struct.unpack(CODE_FORMAT, await self._recvall(struct.calcsize(CODE_FORMAT)))
            size -= struct.calcsize(CODE_FORMAT)
        return size, code

    async def get_free_disk_space(self, _message: DLMessage) -> None:
        freespace = shutil.disk_usage(self.root_path).free
        if sys.platform == "darwin":
            # statvfs excludes APFS purgeable space; report the capacity macOS will
            # actually satisfy (matches Finder), so the device doesn't refuse a
            # backup that fits. See https://github.com/doronz88/pymobiledevice3/issues/1769
            important = _darwin_important_available_capacity(self.root_path)
            if important is not None:
                freespace = max(freespace, important)
        logger.debug("reporting %d bytes free at %s", freespace, self.root_path)
        self._reported_free_space = freespace
        await self.status_response(0, status_dict=freespace)

    async def move_items(self, message: DLMessage) -> None:
        items = cast(Mapping[str, str], message[1])
        for src, dst in items.items():
            source = self.root_path / src
            if not source.exists() and self.preserve_file is not None:
                continue
            dest = self.root_path / dst
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(source, dest)
            # the source is gone after the move; the destination mirrors its kind
            self._move_discarded_files(Path(src), Path(dst), is_dir=dest.is_dir())
            if self.post_file_receive is not None:
                self.post_file_receive(dst, src)
        await self.status_response(0)

    async def copy_item(self, message: DLMessage) -> None:
        src = self.root_path / cast(str, message[1])
        if not src.exists() and self.preserve_file is not None:
            await self.status_response(0)
            return
        dest = self.root_path / cast(str, message[2])
        dest.parent.mkdir(parents=True, exist_ok=True)
        is_dir = src.is_dir()
        if is_dir:
            shutil.copytree(src, dest)
        else:
            shutil.copy(src, dest)
        self._copy_discarded_files(Path(cast(str, message[1])), Path(cast(str, message[2])), is_dir=is_dir)
        if self.post_file_receive is not None:
            self.post_file_receive(cast(str, message[2]), cast(str, message[1]))
        await self.status_response(0)

    async def purge_disk_space(self, message: DLMessage) -> None:
        """Answer the device's request that the host free up disk space.

        ``DLMessagePurgeDiskSpace`` is a request, not a fatal error. Apple's own host
        (``_DLPurgeDiskSpaceOnComputer`` in ``DeviceLink.framework``) builds a dictionary of
        ``CACHE_DELETE_VOLUME`` (the backup root), ``CACHE_DELETE_AMOUNT`` (``message[1]``, the
        bytes the device wants freed) and ``CACHE_DELETE_URGENCY_LIMIT`` (``message[2]``), hands
        it to ``CacheDeletePurgeSpaceWithInfo()``, then replies with a ``DLMessageStatusResponse``
        and keeps serving the connection either way.

        There is no portable CacheDelete equivalent, so mirror Apple's purge-failed path
        (status -1, "DLPurgeDiskSpace failed to purge", zero bytes reclaimed) and let the device
        decide how to continue. Tearing the link down here instead hid the device's own diagnosis
        behind a guessed "not enough disk space" (issue #1879).

        ``CACHE_DELETE_AMOUNT`` is *not* the amount of free space the backup requires - it
        overstates it by a flat 2 GiB - so derive and log the real threshold. In
        ``-[MBDriveBackupEngine _prepareFreeSpace]`` (``BackupAgent2``, ``MobileBackup-2969.120.2``,
        iPhone17,3 iOS 26.5 23F77, ``0x10001e484``)::

            v4  = [_operationJournal sizeForType:2];        // uploadSize
            v12 = v4 + 0x8000000;                           // + 128 MiB of headroom
            [_drive freeSpace:&reported error:&e];          // -> DLMessageGetFreeDiskSpace
            if ((int64) (v12 - reported) < 0) goto ok;      // proceed iff reported > v12
            [_drive purgeDiskSpace:&out
                    amountRequested:(v12 - reported) + 0x80000000
                       urgencyLevel:4 error:&e];            // -> DLMessagePurgeDiskSpace

        So ``amount == (required - reported) + 0x80000000`` and therefore
        ``required == amount + reported - 0x80000000``, where the backup proceeds only when free
        space *exceeds* ``required``. Because the purge is requested only when
        ``required - reported >= 0``, ``amount`` is always at least ``0x80000000``; an amount below
        that means this model no longer holds, so fall back to reporting the raw request.

        Measured against the above on an iPhone18,4 running iOS 26.6.1 (23G83), by answering
        ``DLMessageGetFreeDiskSpace`` with controlled figures while reading the device's own log.
        The last two rows answer the purge request with *success* instead, which makes the device
        re-read free space, so the threshold recovered from the first exchange can be replayed
        back to it exactly:

        ==============  ==================  ============================================
        reported        CACHE_DELETE_AMOUNT device log
        ==============  ==================  ============================================
        1,000,000       2,335,105,975       ``uploadSize:54404599`` / deficit ``187622327``
        188,500,000     2,147,606,193       ``uploadSize:54404817`` / deficit ``122545``
        188,622,945     -                   refused; ``54405217 + 134217728`` exactly
        188,622,946     -                   accepted, backup ran
        ==============  ==================  ============================================

        The last two rows pin the comparison as strict: the device refuses at exactly
        ``uploadSize + 128 MiB`` and accepts one byte above it. (Its own error string prints
        ``(188622945 < 188622945)`` there, because the message says ``<`` while the code tests
        ``required - reported >= 0``.)

        Both constants were read on iOS 26.5 and confirmed on 26.6 (issue #1879) and 26.6.1. They
        are unverified on earlier majors, hence the guard in :meth:`_derive_required_free_space`.
        """
        amount = message[1] if len(message) > 1 else None
        urgency = message[2] if len(message) > 2 else None
        self._required_free_space = self._derive_required_free_space(amount)
        if self._required_free_space is None:
            logger.warning(
                "device asked the host to free %s bytes under %s at %s; no purge backend available",
                amount,
                urgency,
                self.root_path,
            )
        else:
            logger.warning(
                "device needs more than %d bytes free at %s to back up; host reported %d "
                "(%d more needed). No purge backend available, so the device decides how to proceed",
                self._required_free_space,
                self.root_path,
                self._reported_free_space,
                self._required_free_space + 1 - cast(int, self._reported_free_space),
            )
            logger.debug("DLMessagePurgeDiskSpace: amount=%s urgency=%s", amount, urgency)
        await self.status_response(PURGE_DISK_SPACE_ERROR, PURGE_DISK_SPACE_ERROR_STRING, status_dict=0)

    def _derive_required_free_space(self, amount: Any) -> Optional[int]:
        """Recover the free space the device demands from a ``CACHE_DELETE_AMOUNT``.

        Returns ``None`` when the figures don't fit the model documented in
        :meth:`purge_disk_space` - an unknown reported figure, a non-integer amount, or an amount
        below the 2 GiB overshoot that the device always adds. Callers then report the raw request
        rather than a derived number that may be wrong on an untested iOS version.
        """
        if self._reported_free_space is None or not isinstance(amount, int) or isinstance(amount, bool):
            return None
        if amount < PURGE_REQUEST_OVERSHOOT:
            return None
        return amount + self._reported_free_space - PURGE_REQUEST_OVERSHOOT

    async def remove_items(self, message: DLMessage) -> None:
        for path in cast(Iterable[str], message[1]):
            rm_path = self.root_path / path
            is_dir = rm_path.is_dir()
            if is_dir:
                shutil.rmtree(rm_path)
            else:
                rm_path.unlink(missing_ok=True)
            self._forget_discarded_files(Path(path), is_dir=is_dir)
        await self.status_response(0)

    def _discarded_files_below(self, path: Path, is_dir: bool) -> set[Path]:
        """Return the discarded-placeholder entries at or below ``path``.

        The set only ever contains file paths (one placeholder per rejected
        payload), so unless ``path`` is a directory the only possible match is
        ``path`` itself — an O(1) lookup. Reserving the full scan for directories
        keeps bulk per-file operations linear instead of quadratic; a filtered
        whole-device backup issues one move per sent file against a set holding
        every rejected file (https://github.com/doronz88/pymobiledevice3/issues/1833).
        """
        if not is_dir:
            return {path} if path in self._discarded_files else set()
        return {candidate for candidate in self._discarded_files if candidate == path or path in candidate.parents}

    def _move_discarded_files(self, source: Path, destination: Path, is_dir: bool) -> None:
        discarded_files = self._discarded_files_below(source, is_dir)
        self._discarded_files.difference_update(discarded_files)
        self._discarded_files.update(destination / path.relative_to(source) for path in discarded_files)

    def _copy_discarded_files(self, source: Path, destination: Path, is_dir: bool) -> None:
        self._discarded_files.update(
            destination / path.relative_to(source) for path in self._discarded_files_below(source, is_dir)
        )

    def _forget_discarded_files(self, path: Path, is_dir: bool) -> None:
        self._discarded_files.difference_update(self._discarded_files_below(path, is_dir))

    def cleanup_discarded_files(self) -> None:
        """Remove temporary placeholders created for payloads rejected by a backup filter."""
        for relative_path in sorted(self._discarded_files, key=lambda path: len(path.parts), reverse=True):
            path = self.root_path / relative_path
            path.unlink(missing_ok=True)

            parent = path.parent
            while parent != self.root_path:
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent
        self._discarded_files.clear()

    async def create_directory(self, message: DLMessage) -> None:
        path = cast(str, message[1])
        (self.root_path / path).mkdir(parents=True, exist_ok=True)
        await self.status_response(0)

    async def status_response(self, status_code: int, status_str: str = "", status_dict: Any = None) -> None:
        await self.service.send_plist([
            "DLMessageStatusResponse",
            ctypes.c_uint64(status_code).value,
            status_str if status_str else "___EmptyParameterString___",
            status_dict if status_dict is not None else {},
        ])

    async def receive_message(self) -> DLMessage:
        return cast(DLMessage, await self.service.recv_plist())

    async def disconnect(self) -> None:
        await self.service.send_plist(["DLMessageDisconnect", "___EmptyParameterString___"])

    async def _prefixed_recv(self) -> str:
        (size,) = struct.unpack(SIZE_FORMAT, await self._recvall(struct.calcsize(SIZE_FORMAT)))
        return (await self._recvall(size)).decode()
