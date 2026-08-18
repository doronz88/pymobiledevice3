import ctypes
import ctypes.util
import datetime
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
                else:
                    raise PyMobileDevice3Exception(f"Device link error: {message[1]}")
            await self._dl_handlers[command](message)

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

    async def purge_disk_space(self, _message: DLMessage) -> None:
        raise NotEnoughDiskSpaceError()

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
