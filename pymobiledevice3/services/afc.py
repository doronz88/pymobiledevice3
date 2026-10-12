#!/usr/bin/env python3
"""
AFC (Apple File Connection) Service Module

This module provides an interface to interact with iOS devices' file systems through the AFC protocol.
It supports file operations like reading, writing, deleting, and directory traversal, as well as an
interactive shell for navigating the device's file system rooted at /var/mobile/Media.
"""

import asyncio
import contextlib
import inspect
import os
import pathlib
import posixpath
import shutil
import stat as stat_module
import struct
import sys
from collections.abc import AsyncIterator, Coroutine, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from re import Pattern
from types import TracebackType
from typing import Annotated, Any, Callable, NamedTuple, Optional, TextIO, TypeVar, cast

from construct import Bytes, CString, GreedyRange, Int64sl, Int64ul, Tell
from construct_typed import DataclassMixin, EnumBase, TEnum, TStruct, csfield
from prompt_toolkit import HTML, print_formatted_text

# `ls_cli` is a real-click command; the click it raises exceptions from is pygnuutils' own
# dependency, so resolve it through pygnuutils instead of importing click directly.
from pygnuutils.cli.ls import click as _ls_cli_click
from pygnuutils.cli.ls import ls as ls_cli
from pygnuutils.ls import Ls, LsStub
from tqdm.auto import tqdm

from pymobiledevice3.common import get_home_folder
from pymobiledevice3.construct_compat import const_field
from pymobiledevice3.exceptions import AfcException, AfcFileNotFoundError, ArgumentError, ConnectionTerminatedError
from pymobiledevice3.interactive_shell import Arg, CompletionContext, InteractiveShell, shell_command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.safe_paths import device_file_path, validate_device_filename
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import get_asyncio_loop, hexdump, path_to_str

_T = TypeVar("_T")

MAXIMUM_READ_SIZE = 4 * 1024**2  # 4 MB
MODE_MASK = 0o0000777


class StatResult(NamedTuple):
    st_mode: int
    st_ino: int
    st_dev: int
    st_nlink: int
    st_uid: int
    st_gid: int
    st_size: int
    st_atime: float
    st_mtime: float
    st_ctime: float
    st_blocks: int
    st_blksize: int
    st_birthtime: float


class AfcOpcode(EnumBase):
    STATUS = 0x00000001
    DATA = 0x00000002  # Data
    READ_DIR = 0x00000003  # ReadDir
    READ_FILE = 0x00000004  # ReadFile
    WRITE_FILE = 0x00000005  # WriteFile
    WRITE_PART = 0x00000006  # WritePart
    TRUNCATE = 0x00000007  # TruncateFile
    REMOVE_PATH = 0x00000008  # RemovePath
    MAKE_DIR = 0x00000009  # MakeDir
    GET_FILE_INFO = 0x0000000A  # GetFileInfo
    GET_DEVINFO = 0x0000000B  # GetDeviceInfo
    WRITE_FILE_ATOM = 0x0000000C  # WriteFileAtomic (tmp file+rename)
    FILE_OPEN = 0x0000000D  # FileRefOpen
    FILE_OPEN_RES = 0x0000000E  # FileRefOpenResult
    READ = 0x0000000F  # FileRefRead
    WRITE = 0x00000010  # FileRefWrite
    FILE_SEEK = 0x00000011  # FileRefSeek
    FILE_TELL = 0x00000012  # FileRefTell
    FILE_TELL_RES = 0x00000013  # FileRefTellResult
    FILE_CLOSE = 0x00000014  # FileRefClose
    FILE_SET_SIZE = 0x00000015  # FileRefSetFileSize (ftruncate)
    GET_CON_INFO = 0x00000016  # GetConnectionInfo
    SET_CON_OPTIONS = 0x00000017  # SetConnectionOptions
    RENAME_PATH = 0x00000018  # RenamePath
    SET_FS_BS = 0x00000019  # SetFSBlockSize (0x800000)
    SET_SOCKET_BS = 0x0000001A  # SetSocketBlockSize (0x800000)
    FILE_LOCK = 0x0000001B  # FileRefLock
    MAKE_LINK = 0x0000001C  # MakeLink
    SET_FILE_TIME = 0x0000001E  # set st_mtime


class AfcError(EnumBase):
    SUCCESS = 0
    UNKNOWN_ERROR = 1
    OP_HEADER_INVALID = 2
    NO_RESOURCES = 3
    READ_ERROR = 4
    WRITE_ERROR = 5
    UNKNOWN_PACKET_TYPE = 6
    INVALID_ARG = 7
    OBJECT_NOT_FOUND = 8
    OBJECT_IS_DIR = 9
    PERM_DENIED = 10
    SERVICE_NOT_CONNECTED = 11
    OP_TIMEOUT = 12
    TOO_MUCH_DATA = 13
    END_OF_DATA = 14
    OP_NOT_SUPPORTED = 15
    OBJECT_EXISTS = 16
    OBJECT_BUSY = 17
    NO_SPACE_LEFT = 18
    OP_WOULD_BLOCK = 19
    IO_ERROR = 20
    OP_INTERRUPTED = 21
    OP_IN_PROGRESS = 22
    INTERNAL_ERROR = 23
    MUX_ERROR = 30
    NO_MEM = 31
    NOT_ENOUGH_DATA = 32
    DIR_NOT_EMPTY = 33


class AfcLinkType(EnumBase):
    HARDLINK = 1
    SYMLINK = 2


class AfcFopenMode(EnumBase):
    RDONLY = 0x00000001  # r   O_RDONLY
    RW = 0x00000002  # r+  O_RDWR   | O_CREAT
    WRONLY = 0x00000003  # w   O_WRONLY | O_CREAT  | O_TRUNC
    WR = 0x00000004  # w+  O_RDWR   | O_CREAT  | O_TRUNC
    APPEND = 0x00000005  # a   O_WRONLY | O_APPEND | O_CREAT
    RDAPPEND = 0x00000006  # a+  O_RDWR   | O_APPEND | O_CREAT


# typed construct adapters for the enums
afc_opcode_t = TEnum(Int64ul, AfcOpcode)
afc_error_construct = TEnum(Int64ul, AfcError)
afc_link_type_construct = TEnum(Int64ul, AfcLinkType)
afc_fopen_mode_construct = TEnum(Int64ul, AfcFopenMode)

AFC_FOPEN_TEXTUAL_MODES = {
    "r": AfcFopenMode.RDONLY,
    "r+": AfcFopenMode.RW,
    "w": AfcFopenMode.WRONLY,
    "w+": AfcFopenMode.WR,
    "a": AfcFopenMode.APPEND,
    "a+": AfcFopenMode.RDAPPEND,
}

AFC_LOCK_SH = 1 | 4  # shared lock
AFC_LOCK_EX = 2 | 4  # exclusive lock
AFC_LOCK_UN = 8 | 4  # unlock

MAXIMUM_WRITE_SIZE = 1 << 30

AFCMAGIC = b"CFA6LPAA"


@dataclass
class AfcHeader(DataclassMixin):
    # const_field() makes ``magic`` init=False at runtime, but pyright can't see that through the
    # construct-typing stubs and flags the non-default fields that follow. Field order is the AFC wire
    # format.
    magic: bytes = const_field(Bytes(len(AFCMAGIC)), AFCMAGIC)
    entire_length: int = csfield(Int64ul)  # pyright: ignore[reportGeneralTypeIssues]
    this_length: int = csfield(Int64ul)  # pyright: ignore[reportGeneralTypeIssues]
    packet_num: int = csfield(Int64ul)  # pyright: ignore[reportGeneralTypeIssues]
    operation: AfcOpcode = csfield(afc_opcode_t)  # pyright: ignore[reportGeneralTypeIssues]
    _data_offset: int = field(default=0, init=False, metadata={"subcon": Tell})


@dataclass
class AfcReadDirRequest(DataclassMixin):
    filename: str = csfield(CString("utf8"))


@dataclass
class AfcReadDirResponse(DataclassMixin):
    filenames: list[str] = csfield(GreedyRange(CString("utf8")))


@dataclass
class AfcMkdirRequest(DataclassMixin):
    filename: str = csfield(CString("utf8"))


@dataclass
class AfcStatRequest(DataclassMixin):
    filename: str = csfield(CString("utf8"))


@dataclass
class AfcMakeLinkRequest(DataclassMixin):
    type: AfcLinkType = csfield(afc_link_type_construct)
    target: str = csfield(CString("utf8"))
    source: str = csfield(CString("utf8"))


@dataclass
class AfcFopenRequest(DataclassMixin):
    mode: AfcFopenMode = csfield(afc_fopen_mode_construct)
    filename: str = csfield(CString("utf8"))


@dataclass
class AfcFopenResponse(DataclassMixin):
    handle: int = csfield(Int64ul)


@dataclass
class AfcFcloseRequest(DataclassMixin):
    handle: int = csfield(Int64ul)


@dataclass
class AfcRmRequest(DataclassMixin):
    filename: str = csfield(CString("utf8"))


@dataclass
class AfcRenameRequest(DataclassMixin):
    source: str = csfield(CString("utf8"))
    target: str = csfield(CString("utf8"))


@dataclass
class AfcFreadRequest(DataclassMixin):
    handle: int = csfield(Int64ul)
    size: int = csfield(Int64ul)


@dataclass
class AfcLockRequest(DataclassMixin):
    handle: int = csfield(Int64ul)
    op: int = csfield(Int64ul)


@dataclass
class AfcFileSeekRequest(DataclassMixin):
    handle: int = csfield(Int64ul)
    whence: int = csfield(Int64ul)
    offset: int = csfield(Int64sl)


afc_header_t = TStruct(AfcHeader)
afc_read_dir_req_t = TStruct(AfcReadDirRequest)
afc_read_dir_resp_t = TStruct(AfcReadDirResponse)
afc_mkdir_req_t = TStruct(AfcMkdirRequest)
afc_stat_t = TStruct(AfcStatRequest)
afc_make_link_req_t = TStruct(AfcMakeLinkRequest)
afc_fopen_req_t = TStruct(AfcFopenRequest)
afc_fopen_resp_t = TStruct(AfcFopenResponse)
afc_fclose_req_t = TStruct(AfcFcloseRequest)
afc_rm_req_t = TStruct(AfcRmRequest)
afc_rename_req_t = TStruct(AfcRenameRequest)
afc_fread_req_t = TStruct(AfcFreadRequest)
afc_lock_t = TStruct(AfcLockRequest)
afc_fseek_req_t = TStruct(AfcFileSeekRequest)


def list_to_dict(raw: bytes) -> dict[str, str]:
    """
    Convert a null-terminated key-value list to a dictionary.

    The input is expected to be a byte string with alternating keys and values,
    each separated by null bytes (``\\x00``).
    """
    parts = raw.decode("utf-8").split("\x00")[:-1]
    if len(parts) % 2:
        raise ValueError("AFC list is not key/value aligned")
    return dict(zip(parts[::2], parts[1::2]))


class AfcService(LockdownService):
    """
    Apple File Connection (AFC) Service for iOS device file system access.

    This service provides full file system access to the /var/mobile/Media directory
    on iOS devices. It supports standard file operations including read, write, delete,
    rename, and directory operations.

    The service communicates using a custom binary protocol with operation codes for
    different file system operations. AFC responses echo the ``packet_num`` from the
    request, enabling full concurrent operation: multiple callers may issue operations
    simultaneously and a background reader task routes each response to the correct waiter
    via a per-``packet_num`` Future.

    Attributes:
        SERVICE_NAME: Service identifier for lockdown-based connections
        RSD_SERVICE_NAME: Service identifier for RSD-based connections
        packet_num: Counter for tracking packet sequence numbers
    """

    SERVICE_NAME = "com.apple.afc"
    RSD_SERVICE_NAME = "com.apple.afc.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider, service_name: Optional[str] = None):
        """
        Initialize the AFC service.

        :param lockdown: Lockdown service provider for establishing connection
        :param service_name: Optional service name override. Auto-detected if None
        """
        if service_name is None:
            service_name = self.SERVICE_NAME if isinstance(lockdown, LockdownClient) else self.RSD_SERVICE_NAME
        super().__init__(lockdown, service_name)
        self.packet_num = 0
        # Demux state — populated in __aenter__, torn down in __aexit__
        self._afc_pending: dict[int, asyncio.Future[Any]] = {}
        self._afc_write_lock = asyncio.Lock()
        self._afc_reader_task: Optional[asyncio.Task[None]] = None
        # Set (and never cleared) once the connection terminates; the reader task handle
        # itself is not a stable signal because _send_and_wait restarts exited readers.
        self._afc_terminated = asyncio.Event()

    async def __aenter__(self):
        await super().__aenter__()
        self._afc_reader_task = asyncio.create_task(self._afc_reader_loop(), name="afc-reader")
        return self

    async def aclose(self) -> None:
        """Shut down the service: stop the reader task, fail all in-flight requests with
        ``ConnectionTerminatedError``, and close the underlying connection."""
        if self._afc_reader_task is not None:
            self._afc_reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._afc_reader_task
            self._afc_reader_task = None
        for fut in self._afc_pending.values():
            if not fut.done():
                fut.set_exception(ConnectionTerminatedError())
        self._afc_pending.clear()
        await super().close()

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        await self.aclose()

    async def wait_terminated(self) -> None:
        """Block until the AFC connection terminates (e.g. the device disconnects).

        Ensures the background reader is running so termination is detected even when no
        AFC operation is in flight. Returns immediately if the connection already died.
        """
        if not self._afc_terminated.is_set():
            await self.connect()
            if self._afc_reader_task is None or self._afc_reader_task.done():
                self._afc_reader_task = asyncio.create_task(self._afc_reader_loop(), name="afc-reader")
        await self._afc_terminated.wait()

    async def _afc_reader_loop(self) -> None:
        """Background task: read AFC response packets and route them to waiting callers."""
        try:
            while True:
                header_bytes = await self.service.recvall(afc_header_t.sizeof())
                if not header_bytes:
                    break
                header = afc_header_t.parse(header_bytes)
                assert header.entire_length >= afc_header_t.sizeof()
                length = header.entire_length - afc_header_t.sizeof()
                data = await self.service.recvall(length) if length else b""

                status = AfcError.SUCCESS
                if header.operation == AfcOpcode.STATUS:
                    if length != 8:
                        self.logger.error("Status length != 8")
                    status = afc_error_construct.parse(data)
                elif header.operation != AfcOpcode.DATA:
                    self.logger.debug("Unexpected AFC opcode %s", header.operation)

                fut = self._afc_pending.pop(header.packet_num, None)
                if fut is not None and not fut.done():
                    fut.set_result((status, data))
                else:
                    self.logger.warning("AFC: no waiter for packet_num=%d", header.packet_num)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # Propagate to all pending waiters so they don't hang
            for fut in self._afc_pending.values():
                if not fut.done():
                    fut.set_exception(e)
            self._afc_pending.clear()
        finally:
            self._afc_terminated.set()

    async def pull(
        self,
        relative_src: str,
        dst: str,
        match: Optional[Pattern[str]] = None,
        callback: Optional[Callable[..., Any]] = None,
        src_dir: str = "",
        ignore_errors: bool = False,
        progress_bar: bool = True,
    ) -> None:
        """
        Pull (download) a file or directory from the device to the local machine.

        The source is resolved through any symbolic link before transfer. A regular file is
        written to ``dst``; if ``dst`` is an existing local directory, the file is placed
        inside it under the source's basename. Files larger than ``MAXIMUM_READ_SIZE`` (4 MB)
        are streamed in chunks. The local file's modification time is set to match the
        device's ``st_mtime``. A directory source is copied recursively into a subdirectory
        of ``dst`` named after the source's basename.

        :param relative_src: Source path on the device, resolved relative to ``src_dir``.
        :param dst: Destination path on the local machine.
        :param match: Optional regex; only entries whose basename matches (via ``search``) are
            copied. Non-matching files are skipped.
        :param callback: Optional callable invoked as ``callback(src, dst)`` after each regular
            file is copied. If it returns an awaitable, the awaitable is awaited.
        :param src_dir: Base directory on the device against which ``relative_src`` is joined.
        :param ignore_errors: If True, per-entry errors during directory recursion are logged
            and skipped instead of propagated.
        :param progress_bar: If True, display a tqdm progress bar while streaming large files.
        """
        src = await self.resolve_path(posixpath.join(src_dir, relative_src))

        if not await self.isdir(src):
            # normal file
            if match is not None and not match.search(posixpath.basename(src)):
                return
            if os.path.isdir(dst):
                dst = os.path.join(dst, os.path.basename(relative_src))
            with open(dst, "wb") as f:
                src_size = (await self.stat(src))["st_size"]
                if src_size <= MAXIMUM_READ_SIZE:
                    contents = await self.get_file_contents(src)
                    f.write(contents)
                else:
                    handle = await self.fopen(src)
                    # Bytes-scaled bar (B/KB/MB with a live rate) rather than a chunk
                    # counter — the rate readout doubles as a transfer benchmark.
                    with tqdm(
                        total=src_size,
                        unit="B",
                        unit_scale=True,
                        unit_divisor=1024,
                        desc=posixpath.basename(src),
                        disable=not progress_bar,
                    ) as pbar:
                        for offset in range(0, src_size, MAXIMUM_READ_SIZE):
                            to_read = min(MAXIMUM_READ_SIZE, src_size - offset)
                            chunk = await self.fread(handle, to_read)
                            f.write(chunk)
                            pbar.update(len(chunk))
                    await self.fclose(handle)
            os.utime(dst, (os.stat(dst).st_atime, (await self.stat(src))["st_mtime"].timestamp()))
            if callback is not None:
                result = callback(src, dst)
                if inspect.isawaitable(result):
                    await result
        else:
            # directory
            dst_path = pathlib.Path(dst) / os.path.basename(relative_src)
            dst_path.mkdir(parents=True, exist_ok=True)

            for filename in await self.listdir(src):
                src_filename = posixpath.join(src, filename)
                src_filename = await self.resolve_path(src_filename)

                if match is not None and not match.search(posixpath.basename(src_filename)):
                    continue

                try:
                    dst_filename = device_file_path(dst_path, filename)
                    # A link is pulled under its target's name, which is just as device-supplied
                    validate_device_filename(posixpath.basename(src_filename))
                    if await self.isdir(src_filename):
                        dst_filename.mkdir(exist_ok=True)
                        await self.pull(
                            src_filename,
                            str(dst_path),
                            match=match,
                            callback=callback,
                            ignore_errors=ignore_errors,
                            progress_bar=progress_bar,
                        )
                        continue

                    await self.pull(
                        src_filename,
                        str(dst_path),
                        match=match,
                        callback=callback,
                        ignore_errors=ignore_errors,
                        progress_bar=progress_bar,
                    )

                except Exception as afc_exception:
                    if not ignore_errors:
                        raise
                    self.logger.warning(f"(Ignoring) Error: {afc_exception} occurred during the copy of {src_filename}")

    @path_to_str()
    async def exists(self, filename: str):
        """
        Check whether a path exists on the device.

        Implemented by attempting `stat`; a missing path is reported as False and any
        other AFC error propagates.

        :param filename: Path to check.
        :return: True if the path exists, False if it was not found.
        """
        try:
            await self.stat(filename)
        except AfcFileNotFoundError:
            return False
        return True

    @path_to_str()
    async def wait_exists(self, filename: str):
        """
        Block until a path exists on the device.

        Polls `exists` every 0.1 seconds until the path appears. Does not return
        until the path exists.

        :param filename: Path to wait for.
        """
        while not await self.exists(filename):
            await asyncio.sleep(0.1)

    @path_to_str()
    async def _push_internal(
        self,
        local_path: str,
        remote_path: str,
        callback: Optional[Callable[[str, str], Any]] = None,
        progress_bar: bool = True,
    ):
        """
        Internal method for pushing files to the device.

        :param local_path: Local file or directory path
        :param remote_path: Remote destination path on the device
        :param callback: Optional callback function called for each file copied (src, dst)
        :param progress_bar: If True, display a tqdm progress bar while streaming large files.
        """
        if callback is not None:
            callback(local_path, remote_path)

        if not os.path.isdir(local_path):
            # normal file
            try:
                if await self.isdir(remote_path):
                    # Remote is dir.
                    remote_path = posixpath.join(remote_path, os.path.basename(local_path))
            except AfcFileNotFoundError:
                # Remote is file.
                remote_parent = posixpath.dirname(remote_path)
                if not await self.exists(remote_parent):
                    raise
                remote_path = posixpath.join(remote_parent, os.path.basename(remote_path))
            src_size = os.path.getsize(local_path)
            if src_size <= MAXIMUM_READ_SIZE:
                with open(local_path, "rb") as f:
                    await self.set_file_contents(remote_path, f.read())
            else:
                # Stream large files in chunks instead of loading them whole into memory,
                # with the same bytes-scaled bar `pull` shows — the live rate readout
                # doubles as a transfer benchmark.
                handle = await self.fopen(remote_path, "w")
                try:
                    with (
                        open(local_path, "rb") as f,
                        tqdm(
                            total=src_size,
                            unit="B",
                            unit_scale=True,
                            unit_divisor=1024,
                            desc=os.path.basename(local_path),
                            disable=not progress_bar,
                        ) as pbar,
                    ):
                        while True:
                            chunk = f.read(MAXIMUM_READ_SIZE)
                            if not chunk:
                                break
                            await self.fwrite(handle, chunk)
                            pbar.update(len(chunk))
                finally:
                    await self.fclose(handle)
        else:
            # directory
            if not await self.exists(remote_path):
                await self.makedirs(remote_path)

            for filename in os.listdir(local_path):
                local_filename = os.path.join(local_path, filename)
                remote_filename = posixpath.join(remote_path, filename).removeprefix("/")

                if os.path.isdir(local_filename):
                    if not await self.exists(remote_filename):
                        await self.makedirs(remote_filename)
                    await self._push_internal(
                        local_filename, remote_filename, callback=callback, progress_bar=progress_bar
                    )
                    continue

                await self._push_internal(local_filename, remote_filename, callback=callback, progress_bar=progress_bar)

    @path_to_str()
    async def push(
        self,
        local_path: str,
        remote_path: str,
        callback: Optional[Callable[[str, str], Any]] = None,
        progress_bar: bool = True,
    ):
        """
        Push (upload) a file or directory from the local machine to the device.

        A regular file is written to ``remote_path`` (or, if ``remote_path`` is an existing
        remote directory, into it under the file's basename). Files larger than
        ``MAXIMUM_READ_SIZE`` (4 MB) are streamed in chunks with a byte-scaled progress bar.
        A local directory is copied recursively into ``remote_path``/<basename of local_path>,
        creating remote directories as needed.

        :param local_path: Source path on the local machine.
        :param remote_path: Destination path on the device.
        :param callback: Optional callable invoked as ``callback(local_path, remote_path)``
            before each entry is transferred.
        :param progress_bar: If True, display a tqdm progress bar while streaming large files.
        """
        if os.path.isdir(local_path):
            remote_path = posixpath.join(remote_path, os.path.basename(local_path))
        await self._push_internal(local_path, remote_path, callback, progress_bar=progress_bar)

    @path_to_str()
    async def rm_single(self, filename: str, force: bool = False) -> bool:
        """
        Remove a single file or empty directory on the device.

        Issues a single ``REMOVE_PATH`` operation; it does not recurse into a non-empty
        directory.

        :param filename: Path to the file or directory to remove.
        :param force: If True, swallow an `AfcException` and return False instead of raising.
        :return: True on success; False if the removal failed and ``force`` is True.
        :raises AfcException: if the removal fails and ``force`` is False.
        """
        try:
            await self._do_operation(
                AfcOpcode.REMOVE_PATH, afc_rm_req_t.build(AfcRmRequest(filename=filename)), filename
            )
        except AfcException:
            if force:
                return False
            raise
        return True

    @path_to_str()
    async def rm(self, filename: str, match: Optional[Pattern[str]] = None, force: bool = False) -> list[str]:
        """
        Recursively remove a file or directory tree on the device.

        For a directory, every entry is removed depth-first and the directory itself is removed
        last. The ``match`` pattern, when given, filters which top-level entries of ``filename``
        are considered (matched against their basename via ``match``); nested entries are always
        removed once their parent is selected.

        :param filename: Path to the file or directory to remove.
        :param match: Optional regex; only directory entries whose basename matches are removed.
            None removes all entries.
        :param force: If True, suppress the final `AfcException` and instead return the
            list of paths that could not be deleted.
        :return: List of paths that could not be deleted (empty on full success).
        :raises AfcException: if any path could not be deleted and ``force`` is False.
        """
        if not await self.exists(filename) and not await self.rm_single(filename, force=force):
            return [filename]

        # single file
        if not await self.isdir(filename):
            if await self.rm_single(filename, force=force):
                return []
            return [filename]

        # directory content
        undeleted_items: list[str] = []
        for entry in await self.listdir(filename):
            current_filename = posixpath.join(filename, entry)

            if match is not None and not match.match(posixpath.basename(current_filename)):
                continue

            if await self.isdir(current_filename):
                ret_undeleted_items = await self.rm(current_filename, force=True)
                undeleted_items.extend(ret_undeleted_items)
            else:
                if not await self.rm_single(current_filename, force=True):
                    undeleted_items.append(current_filename)

        # directory path
        try:
            if not await self.rm_single(filename, force=force):
                undeleted_items.append(filename)
                return undeleted_items
        except AfcException:
            if undeleted_items:
                undeleted_items.append(filename)
            else:
                raise

        if undeleted_items:
            # AfcException mis-annotates `status` as str; it accepts AfcError/None at runtime
            raise AfcException(
                f"Failed to delete paths: {undeleted_items}",
                None,
            )

        return []

    async def get_device_info(self):
        """
        Query device file-system information.

        Issues a ``GET_DEVINFO`` operation and decodes the null-terminated key/value list into
        a dictionary (e.g. model, total/free bytes, block size).

        :return: Dictionary of device file-system attributes (all values are strings).
        """
        return list_to_dict(await self._do_operation(AfcOpcode.GET_DEVINFO))

    @path_to_str()
    async def listdir(self, filename: str) -> list[str]:
        """
        List the entries of a directory on the device.

        :param filename: Path to the directory.
        :return: Entry names in the directory, excluding ``.`` and ``..``.
        :raises AfcFileNotFoundError: if the path does not exist.
        :raises AfcException: if the path is not a directory or cannot be listed.
        """
        data = await self._do_operation(
            AfcOpcode.READ_DIR, afc_read_dir_req_t.build(AfcReadDirRequest(filename=filename)), filename
        )
        return afc_read_dir_resp_t.parse(data).filenames[2:]  # skip the . and ..

    @path_to_str()
    async def makedirs(self, filename: str):
        """
        Create a directory on the device.

        Issues a ``MAKE_DIR`` operation, creating any missing parent directories.

        :param filename: Path of the directory to create.
        :return: Raw response payload from the operation (typically empty).
        :raises AfcException: if the directory could not be created.
        """
        return await self._do_operation(
            AfcOpcode.MAKE_DIR, afc_mkdir_req_t.build(AfcMkdirRequest(filename=filename)), filename
        )

    @path_to_str()
    async def isdir(self, filename: str) -> bool:
        """
        Check whether a path is a directory.

        Stats the path and tests whether its ``st_ifmt`` is ``S_IFDIR``.

        :param filename: Path to check.
        :return: True if the path is a directory, False otherwise.
        :raises AfcFileNotFoundError: if the path does not exist.
        """
        stat = await self.stat(filename)
        return stat.get("st_ifmt") == "S_IFDIR"

    @path_to_str()
    async def stat(self, filename: str) -> dict[str, Any]:
        """
        Get file or directory metadata.

        Issues a ``GET_FILE_INFO`` operation and returns the decoded attribute dictionary.
        Numeric fields (``st_size``, ``st_blocks``, ``st_nlink``) are converted to ints;
        ``st_mtime`` and ``st_birthtime`` are converted from device nanosecond timestamps to
        `datetime`. A ``st_ifmt`` entry (e.g. ``S_IFREG``, ``S_IFDIR``,
        ``S_IFLNK``) describes the file type, and symbolic links also carry a ``LinkTarget``.

        :param filename: Path to the file or directory.
        :return: Dictionary of file attributes.
        :raises AfcFileNotFoundError: if the path does not exist (AFC ``READ_ERROR``).
        :raises AfcException: for any other failure status.
        """
        try:
            stat: dict[str, Any] = list_to_dict(
                await self._do_operation(
                    AfcOpcode.GET_FILE_INFO, afc_stat_t.build(AfcStatRequest(filename=filename)), filename
                )
            )
        except AfcException as e:
            if e.status != AfcError.READ_ERROR:
                raise
            raise AfcFileNotFoundError(e.args[0], e.status) from e

        stat["st_size"] = int(stat["st_size"])
        stat["st_blocks"] = int(stat["st_blocks"])
        stat["st_mtime"] = int(stat["st_mtime"])
        stat["st_birthtime"] = int(stat["st_birthtime"])
        stat["st_nlink"] = int(stat["st_nlink"])
        stat["st_mtime"] = datetime.fromtimestamp(stat["st_mtime"] / (10**9))
        stat["st_birthtime"] = datetime.fromtimestamp(stat["st_birthtime"] / (10**9))
        return stat

    @path_to_str()
    async def os_stat(self, path: str):
        """
        Get file statistics as an `stat`-style result.

        Wraps `stat`, mapping the AFC ``st_ifmt`` to a numeric mode and packing the
        attributes into a `StatResult` namedtuple. ``st_ino`` is synthesized from the
        normalized path, ``st_uid``/``st_gid``/``st_dev`` are reported as 0 and ``st_blksize``
        as 4096 (AFC does not expose these). ``st_atime`` mirrors ``st_mtime``.

        :param path: Path to the file or directory.
        :return: A `StatResult` namedtuple.
        :raises AfcFileNotFoundError: if the path does not exist.
        """
        stat = await self.stat(path)
        mode = 0
        for s_mode in ["S_IFDIR", "S_IFCHR", "S_IFBLK", "S_IFREG", "S_IFIFO", "S_IFLNK", "S_IFSOCK"]:
            if stat["st_ifmt"] == s_mode:
                mode = getattr(stat_module, s_mode)
        return StatResult(
            mode,
            hash(posixpath.normpath(path)),
            0,
            stat["st_nlink"],
            0,
            0,
            stat["st_size"],
            stat["st_mtime"].timestamp(),
            stat["st_mtime"].timestamp(),
            stat["st_birthtime"].timestamp(),
            stat["st_blocks"],
            4096,
            stat["st_birthtime"].timestamp(),
        )

    @path_to_str()
    async def link(self, target: str, source: str, type_: AfcLinkType = AfcLinkType.SYMLINK):
        """
        Create a symbolic or hard link on the device.

        :param target: Path the link points to.
        :param source: Path at which the link is created.
        :param type_: `AfcLinkType` to create (``SYMLINK`` by default, or ``HARDLINK``).
        :return: Raw response payload from the operation (typically empty).
        :raises AfcException: if the link could not be created.
        """
        return await self._do_operation(
            AfcOpcode.MAKE_LINK,
            afc_make_link_req_t.build(AfcMakeLinkRequest(type=type_, target=target, source=source)),
        )

    @path_to_str()
    async def fopen(self, filename: str, mode: str = "r") -> int:
        """
        Open a file on the device and return its handle.

        :param filename: Path to the file.
        :param mode: Textual open mode; one of ``'r'``, ``'r+'``, ``'w'``, ``'w+'``, ``'a'``,
            ``'a+'`` (mapped to the corresponding AFC fopen mode).
        :return: Integer handle usable with `fread`, `fwrite`, `lock` and
            `fclose`.
        :raises ArgumentError: if ``mode`` is not one of the supported textual modes.
        :raises AfcException: if the file could not be opened.
        """
        if mode not in AFC_FOPEN_TEXTUAL_MODES:
            raise ArgumentError(f"mode can be only one of: {AFC_FOPEN_TEXTUAL_MODES.keys()}")

        data = await self._do_operation(
            AfcOpcode.FILE_OPEN,
            afc_fopen_req_t.build(
                AfcFopenRequest(mode=AFC_FOPEN_TEXTUAL_MODES[mode], filename=filename),
            ),
        )
        return afc_fopen_resp_t.parse(data).handle

    async def fclose(self, handle: int):
        """
        Close an open file handle.

        :param handle: Handle returned by `fopen`.
        :return: Raw response payload from the operation (typically empty).
        :raises AfcException: if the close operation fails.
        """
        return await self._do_operation(AfcOpcode.FILE_CLOSE, afc_fclose_req_t.build(AfcFcloseRequest(handle=handle)))

    @path_to_str()
    async def rename(self, source: str, target: str) -> None:
        """
        Rename or move a file or directory on the device.

        :param source: Current path of the file or directory.
        :param target: New path for the file or directory.
        :raises AfcFileNotFoundError: if the operation fails and ``source`` no longer exists.
        :raises AfcException: if the operation fails while ``source`` still exists.
        """
        try:
            await self._do_operation(
                AfcOpcode.RENAME_PATH,
                afc_rename_req_t.build(AfcRenameRequest(source=source, target=target)),
            )
        except AfcException as e:
            if await self.exists(source):
                raise
            raise AfcFileNotFoundError(
                f"Failed to rename {source} into {target}. Got status: {e.status}", e.args[0], str(e.status)
            ) from e

    async def fread(self, handle: int, sz: int) -> bytes:
        """
        Read data from an open file handle.

        Automatically handles large reads by splitting into multiple operations.
        Each chunk send+receive is performed atomically via the demux reader so
        concurrent callers on the same AfcService instance are safe.

        :param handle: Handle returned by `fopen`.
        :param sz: Number of bytes to read. Reads larger than ``MAXIMUM_READ_SIZE`` (4 MB) are
            split into successive operations.
        :return: The bytes read.
        :raises AfcException: if any read operation returns a non-success status.
        """
        data = b""
        while sz > 0:
            to_read = MAXIMUM_READ_SIZE if sz > MAXIMUM_READ_SIZE else sz
            status, chunk = await self._send_and_wait(
                AfcOpcode.READ, afc_fread_req_t.build(AfcFreadRequest(handle=handle, size=to_read))
            )
            if status != AfcError.SUCCESS:
                raise AfcException("fread error", status)
            sz -= to_read
            data += chunk
        return data

    async def fseek(self, handle: int, offset: int, whence: int = os.SEEK_SET) -> None:
        """
        Seek within an open file handle.

        :param handle: Handle returned by `fopen`.
        :param offset: Byte offset relative to ``whence``.
        :param whence: One of ``os.SEEK_SET`` (0), ``os.SEEK_CUR`` (1), ``os.SEEK_END`` (2).
        :raises AfcException: if the seek operation fails.
        """
        await self._do_operation(
            AfcOpcode.FILE_SEEK,
            afc_fseek_req_t.build(AfcFileSeekRequest(handle=handle, whence=whence, offset=offset)),
        )

    async def fwrite(self, handle: int, data: bytes, chunk_size: int = MAXIMUM_WRITE_SIZE) -> None:
        """
        Write data to an open file handle.

        Automatically handles large writes by splitting into multiple operations.
        Each chunk send+receive is performed atomically via the demux reader so
        concurrent callers on the same AfcService instance are safe.

        :param handle: Handle returned by `fopen`.
        :param data: Bytes to write.
        :param chunk_size: Maximum bytes per ``WRITE`` operation (default ``MAXIMUM_WRITE_SIZE``).
        :raises AfcException: if any write operation returns a non-success status.
        """
        file_handle = struct.pack("<Q", handle)
        chunks_count = len(data) // chunk_size
        for i in range(chunks_count):
            chunk = data[i * chunk_size : (i + 1) * chunk_size]
            status, _ = await self._send_and_wait(AfcOpcode.WRITE, file_handle + chunk, this_length=48)
            if status != AfcError.SUCCESS:
                raise AfcException(f"failed to write chunk: {status}", status)

        if len(data) % chunk_size:
            chunk = data[chunks_count * chunk_size :]
            status, _ = await self._send_and_wait(AfcOpcode.WRITE, file_handle + chunk, this_length=48)
            if status != AfcError.SUCCESS:
                raise AfcException(f"failed to write last chunk: {status}", status)

    @path_to_str()
    async def resolve_path(self, filename: str) -> str:
        """
        Resolve a symbolic link to its target path.

        Stats the path; if it is a symbolic link, returns its ``LinkTarget`` (joined against
        the link's parent directory when the target is relative). Non-links are returned
        unchanged. Only a single level of link is resolved.

        :param filename: Path to resolve.
        :return: The link target, or ``filename`` unchanged if it is not a symbolic link.
        :raises AfcFileNotFoundError: if the path does not exist.
        """
        info = await self.stat(filename)
        if info["st_ifmt"] == "S_IFLNK":
            target = info["LinkTarget"]
            filename = posixpath.join(posixpath.dirname(filename), target) if not target.startswith("/") else target
        return filename

    @path_to_str()
    async def get_file_contents(self, filename: str) -> bytes:
        """
        Read and return the entire contents of a file.

        Resolves any symbolic link, verifies the target is a regular file, then opens it,
        reads ``st_size`` bytes and closes the handle.

        :param filename: Path to the file.
        :return: The file contents as bytes.
        :raises AfcException: if the path is not a regular file (``S_IFREG``) or could not be opened.
        :raises AfcFileNotFoundError: if the path does not exist.
        """
        filename = await self.resolve_path(filename)
        info = await self.stat(filename)

        if info["st_ifmt"] != "S_IFREG":
            raise AfcException(f"{filename} isn't a file", AfcError.INVALID_ARG, filename)

        h = await self.fopen(filename)
        if not h:
            raise AfcException(f"failed to open {filename}", AfcError.INTERNAL_ERROR, filename)
        d = await self.fread(h, int(info["st_size"]))
        await self.fclose(h)
        return d

    @path_to_str()
    async def set_file_contents(self, filename: str, data: bytes) -> None:
        """
        Write data to a file, creating or truncating it.

        Opens the file in ``'w'`` mode (create/truncate), writes ``data`` and closes the handle.

        :param filename: Path to the file.
        :param data: Bytes to write.
        :raises AfcException: if the open or write operation fails.
        """
        h = await self.fopen(filename, "w")
        await self.fwrite(h, data)
        await self.fclose(h)

    @path_to_str()
    async def walk(self, dirname: str) -> AsyncIterator[tuple[str, list[str], list[str]]]:
        """
        Recursively walk a directory tree, similar to `walk`.

        Yields one ``(dirpath, dirnames, filenames)`` tuple per directory, top-down, starting
        at ``dirname``. ``dirnames`` lists subdirectory names and ``filenames`` lists all other
        entries. Symbolic links to directories are classified as files (not descended into).

        As with `os.walk`, the caller may modify ``dirnames`` in place to prune the descent:
        only the names still listed when the generator resumes are walked.

        :param dirname: Root directory to walk.
        :yields: ``(dirpath, dirnames, filenames)`` tuples.
        """
        dirs: list[str] = []
        files: list[str] = []
        for fd in await self.listdir(dirname):
            if fd in (".", "..", ""):
                continue
            infos = await self.stat(posixpath.join(dirname, fd))
            if infos and infos.get("st_ifmt") == "S_IFDIR":
                dirs.append(fd)
            else:
                files.append(fd)

        yield dirname, dirs, files

        if dirs:
            for d in dirs:
                async for item in self.walk(posixpath.join(dirname, d)):
                    yield item

    @path_to_str()
    async def dirlist(self, root: str, depth: int = -1) -> AsyncIterator[str]:
        """
        Recursively yield paths under a directory up to a maximum depth.

        Yields ``root`` itself first, followed by the full path of every entry found while
        walking, pruning descent once a directory's depth (in path separators) reaches
        ``depth``.

        :param root: Root directory to list.
        :param depth: Maximum traversal depth; ``-1`` for unlimited, ``0`` to yield only ``root``.
        :yields: Full paths of files and directories.
        """
        async for folder, dirs, files in self.walk(root):
            if folder == root:
                yield folder
                if depth == 0:
                    break
            for entry in dirs + files:
                yield posixpath.join(folder, entry)
            if depth != -1:
                # Prune in place so `walk` never reads directories beyond the requested depth
                dirs[:] = [d for d in dirs if posixpath.join(folder, d).count(posixpath.sep) < depth]

    async def lock(self, handle: int, operation: int):
        """
        Apply or release an advisory ``flock``-style lock on an open file.

        :param handle: Handle returned by `fopen`.
        :param operation: Lock operation, one of ``AFC_LOCK_SH`` (shared), ``AFC_LOCK_EX``
            (exclusive) or ``AFC_LOCK_UN`` (unlock).
        :return: Raw response payload from the operation (typically empty).
        :raises AfcException: if the lock operation fails.
        """
        return await self._do_operation(
            AfcOpcode.FILE_LOCK, afc_lock_t.build(AfcLockRequest(handle=handle, op=operation))
        )

    async def _dispatch_packet(self, operation: AfcOpcode, data: bytes, this_length: int = 0) -> int:
        """
        Send an AFC protocol packet to the device.

        :param operation: AFC operation code
        :param data: Packet payload data
        :param this_length: Override for the packet length field (0 for auto-calculation)
        :return: The packet_num assigned to this packet (used to match the response)
        """
        pkt_num = self.packet_num
        entire_length = afc_header_t.sizeof() + len(data)
        header = afc_header_t.build(
            AfcHeader(
                entire_length=entire_length,
                this_length=this_length or entire_length,
                packet_num=pkt_num,
                operation=operation,
            )
        )
        self.packet_num += 1
        await self.service.sendall(header + data)
        return pkt_num

    async def _receive_data(self):
        """
        Receive an AFC protocol response packet from the device.

        .. deprecated::
            Internal use only. External callers should use `_do_operation` or
            `_send_and_wait` which use the background demux reader.

        :return: Tuple of (status_code, response_data)
        """
        header_bytes = await self.service.recvall(afc_header_t.sizeof())
        status = AfcError.SUCCESS
        data = b""
        if header_bytes:
            header = afc_header_t.parse(header_bytes)
            assert header.entire_length >= afc_header_t.sizeof()
            length = header.entire_length - afc_header_t.sizeof()
            data = await self.service.recvall(length)
            if header.operation == AfcOpcode.STATUS:
                if length != 8:
                    self.logger.error("Status length != 8")
                status = afc_error_construct.parse(data)
            elif header.operation != AfcOpcode.DATA:
                self.logger.debug("Unexpected AFC opcode %s", header.operation)
        return status, data

    async def _send_and_wait(self, operation: AfcOpcode, data: bytes, this_length: int = 0):
        """
        Atomically send one AFC packet and wait for its response via the demux reader.

        The write lock ensures that ``packet_num`` assignment, Future registration, and
        the actual ``sendall`` are an uninterruptible unit so the background reader always
        finds a registered Future before the response arrives.

        If the background reader task has not been started yet (e.g. when the service is
        used without ``async with``), it is started lazily on the first call.

        :param operation: AFC operation code
        :param data: Packet payload
        :param this_length: Override for the ``this_length`` header field
        :return: Tuple of (AfcError, response_bytes)
        """
        # Ensure we're connected (lazy connect for non-async-with usage)
        await self.connect()
        # Start background reader lazily for callers that don't use async with.
        # Also restart it if it exited (e.g. connection error): the new task will
        # fail immediately on the broken socket and propagate the error to the caller
        # via _afc_pending, giving a clean exception rather than an infinite hang.
        if self._afc_reader_task is None or self._afc_reader_task.done():
            self._afc_reader_task = asyncio.create_task(self._afc_reader_loop(), name="afc-reader")
        loop = asyncio.get_event_loop()
        async with self._afc_write_lock:
            fut: asyncio.Future[Any] = loop.create_future()
            # Register *before* sending so the reader never misses the response
            pkt_num = self.packet_num
            self._afc_pending[pkt_num] = fut
            try:
                await self._dispatch_packet(operation, data, this_length)
            except BaseException:
                self._afc_pending.pop(pkt_num, None)
                raise
        return await fut

    async def _do_operation(self, opcode: AfcOpcode, data: bytes = b"", filename: Optional[str] = None) -> bytes:
        """
        Performs a low-level operation using the specified opcode and additional data.

        This method dispatches a packet with the given opcode and data, waits for a
        response via the background demux reader, and processes the result to determine
        success or failure. Multiple callers may call this concurrently on the same
        instance; each operation is matched to its response by ``packet_num``.

        :param opcode: The operation code specifying the type of operation to perform.
        :param data: The additional data to send along with the operation. Defaults to an empty byte string.
        :param filename: The filename associated with the operation, if applicable. Defaults to None.

        :returns: bytes: The data received as a response to the operation.

        :raises:
            AfcException: General exception raised if the operation fails with an
                          unspecified error status.
            AfcFileNotFoundError: Exception raised when the operation fails due to
                                  an object not being found (e.g., file or directory).
        """
        status, data = await self._send_and_wait(opcode, data)

        exception = AfcException
        if status != AfcError.SUCCESS:
            if status == AfcError.OBJECT_NOT_FOUND:
                exception = AfcFileNotFoundError

            opcode_name = opcode.name
            message = f"Opcode: {opcode_name} failed with status: {status}"
            if filename is not None:
                message += f" for file: {filename}"
            # AfcException mis-annotates `status` as str; it accepts AfcError/None at runtime
            raise exception(message, status, filename)

        return data


class AfcLsStub(LsStub):
    """
    Adapter that lets the pygnuutils ls implementation list an AFC file system.

    pygnuutils is blocking, so ``Ls`` runs on a worker thread and every device access made
    through this adapter is handed to the event loop the AFC service lives on.
    """

    def __init__(self, afc: "AfcService", loop: asyncio.AbstractEventLoop, stdout: TextIO):
        """
        Initialize the ls stub.

        :param afc: AFC service to list
        :param loop: Event loop the AFC service lives on
        :param stdout: Output stream for ls results
        """
        self.afc = afc
        self.stdout = stdout
        self._loop = loop

    def _wait(self, coro: Coroutine[Any, Any, _T]) -> _T:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    @property
    def sep(self):
        return posixpath.sep

    def join(self, path: str, *paths: str):
        return posixpath.join(path, *paths)

    def abspath(self, path: str):
        return posixpath.normpath(path)

    def stat(self, path: str, dir_fd: Optional[int] = None, follow_symlinks: bool = True) -> Any:
        # AFC's StatResult stands in for os.stat_result: it carries the fields ls reads
        if follow_symlinks:
            path = self._wait(self.afc.resolve_path(path))
        return self._wait(self.afc.os_stat(path))

    def readlink(self, path: str, dir_fd: Optional[int] = None):
        return self._wait(self.afc.resolve_path(path))

    def isabs(self, path: str):
        return posixpath.isabs(path)

    def dirname(self, path: str):
        return posixpath.dirname(path)

    def basename(self, path: str):
        return posixpath.basename(path)

    def getgroup(self, st_gid: int):
        return "-"

    def getuser(self, st_uid: int):
        return "-"

    def now(self):
        timestamp = self.afc.lockdown.all_values.get("TimeIntervalSince1970", 0)
        return datetime.fromtimestamp(timestamp)

    def listdir(self, path: str = "."):
        return self._wait(self.afc.listdir(path))

    def system(self):
        return "Darwin"

    def getenv(self, key: str, default: Optional[str] = None):
        return ""

    def print(self, *objects: Any, sep: str = " ", end: str = "\n", file: TextIO = sys.stdout, flush: bool = False):
        """
        Print ls output to the constructor-provided stream.

        The fourth argument is accepted only for compatibility with Python's
        ``print(file=...)`` style calls used by ``pygnuutils``. It is ignored.
        """
        print(*objects, sep=sep, end=end, file=self.stdout, flush=flush)

    def get_tty_width(self):
        return shutil.get_terminal_size().columns


async def _complete_remote_path(context: CompletionContext, directories_only: bool) -> list[str]:
    shell = cast(AfcShell, context.shell)
    prefix = context.prefix
    dirpath = posixpath.join(shell.cwd, prefix)
    is_dir = False
    with contextlib.suppress(AfcException):
        is_dir = await shell.afc.isdir(dirpath)
    if not is_dir:
        dirpath = posixpath.dirname(dirpath)

    result: list[str] = []
    for name, is_dir in await shell.list_directory(dirpath):
        if directories_only and not is_dir:
            continue
        option = posixpath.join(dirpath, name)
        if not prefix.startswith("/"):
            option = posixpath.relpath(option, shell.cwd)
        result.append(f"{option}/" if is_dir else option)
    return result


async def path_completer(context: CompletionContext) -> list[str]:
    """
    Provide path completion for shell commands.

    Generates completion suggestions based on the current working directory
    and available files/directories on the device.

    :return: List of completion suggestions
    """
    return await _complete_remote_path(context, directories_only=False)


async def dir_completer(context: CompletionContext) -> list[str]:
    """
    Provide directory-only completion for shell commands.

    Similar to path_completer but only suggests directories, not files.

    :return: List of directory completion suggestions
    """
    return await _complete_remote_path(context, directories_only=True)


#: A path on the device, completed against its file system.
RemotePath = Annotated[str, Arg(completer=path_completer)]
#: A directory on the device, completed against its file system.
RemoteDir = Annotated[str, Arg(completer=dir_completer)]


class AfcShell(InteractiveShell):
    """
    Interactive shell for navigating an iOS device's file system via AFC.

    Provides a familiar shell environment with common commands (ls, cd, cat, etc.)
    that operate on the remote device's file system, with tab completion, history,
    pipes into a few host tools (``cat file | grep foo``) and redirection into local
    files (``cat file > copy``).

    Attributes:
        afc: AfcService instance for file operations
        cwd: Current working directory on the device
    """

    #: Host text utilities that device commands can be piped into. Deliberately few.
    HOST_COMMANDS = ("grep", "egrep", "sed", "awk", "sort", "uniq", "cut", "tr", "tail", "wc", "less", "yes")

    @classmethod
    def create(
        cls,
        service_provider: LockdownServiceProvider,
        service_name: Optional[str] = None,
        service: Optional[LockdownService] = None,
        auto_cd: Optional[str] = "/",
    ) -> None:
        """
        Create and launch an AFC shell session, blocking until the user leaves it.

        The shell runs on the CLI event loop. From a coroutine, construct the shell and await
        :meth:`interact` instead.

        :param service_provider: Lockdown service provider for device connection
        :param service_name: Optional AFC service name override
        :param service: Optional pre-initialized AFC service instance
        :param auto_cd: Initial working directory (default: "/")
        """
        afc = cast(AfcService, service) if service is not None else AfcService(service_provider, service_name)
        get_asyncio_loop().run_until_complete(cls(afc, cwd=auto_cd or "/").interact())

    def __init__(self, afc: AfcService, cwd: str = "/", host_tools: Iterable[str] = ()):
        """
        :param afc: AFC service instance for file operations
        :param cwd: Initial working directory
        :param host_tools: Names of more host executables to offer as commands
        """
        super().__init__(host_tools)
        self.afc = afc
        self.cwd = cwd
        self._directory_cache: dict[str, list[tuple[str, bool]]] = {}

    async def interact(self) -> None:
        print_formatted_text(
            HTML(
                "\n<b>Welcome to the AFC shell!</b> 👋\n"
                "Type <ansicyan>help</ansicyan> to list the commands, <ansicyan>exit</ansicyan> or Ctrl-D to leave.\n"
            )
        )
        await super().interact()

    async def run_line(self, line: str) -> int:
        # a command may change what is on the device
        self._directory_cache.clear()
        return await super().run_line(line)

    async def list_directory(self, directory: str) -> list[tuple[str, bool]]:
        """
        List a device directory as ``(name, is_directory)`` pairs, for completion.

        Remembered until the next command runs, so completing in a large directory asks the
        device once.
        """
        cached = self._directory_cache.get(directory)
        if cached is not None:
            return cached
        entries: list[tuple[str, bool]] = []
        for name in await self.afc.listdir(directory):
            is_dir = False
            with contextlib.suppress(AfcException):
                is_dir = await self.afc.isdir(posixpath.join(directory, name))
            entries.append((name, is_dir))
        self._directory_cache[directory] = entries
        return entries

    def _history_path(self) -> pathlib.Path:
        return get_home_folder() / "afc_shell_history"

    def _prompt_label(self) -> str:
        return f"{self.afc.service_name}:{self.cwd}"

    @shell_command
    def _do_pwd(self) -> None:
        """Print the current working directory."""
        print(self.cwd)

    @shell_command
    async def _do_link(self, target: str, source: str) -> None:
        """
        Create a symbolic link on the device.

        :param target: Target path that the link will point to
        :param source: Path where the link will be created
        """
        await self.afc.link(self.relative_path(target), self.relative_path(source), AfcLinkType.SYMLINK)

    @shell_command
    async def _do_cd(self, directory: RemoteDir = "/") -> None:
        """
        Change the current working directory.

        :param directory: Directory path to change to (relative or absolute). The root when omitted
        """
        directory = self.relative_path(directory)
        directory = posixpath.normpath(directory)
        if not await self.afc.exists(directory):
            raise ArgumentError(f"{directory} does not exist")
        self.cwd = directory

    @shell_command(raw=True, completer=path_completer)
    async def _do_ls(self, args: list[str]):
        """
        List directory contents with Unix ls-like formatting.

        Supports various ls options for formatting and filtering.
        """
        try:
            with ls_cli.make_context("ls", args) as ctx:
                files = list(map(self.relative_path, ctx.params.pop("files")))
                files = files if files else [self.cwd]
                ls = Ls(AfcLsStub(self.afc, asyncio.get_running_loop(), sys.stdout))
                await asyncio.to_thread(ls, *files, **ctx.params)
        except _ls_cli_click.exceptions.Exit:
            pass

    @shell_command
    async def _do_walk(self, directory: RemoteDir):
        """
        Recursively walk a directory tree and print all paths.

        :param directory: Root directory to walk
        """
        async for root, dirs, files in self.afc.walk(self.relative_path(directory)):
            for name in files:
                print(posixpath.join(root, name))
            for name in dirs:
                print(posixpath.join(root, name))

    @shell_command
    async def _do_cat(self, filename: RemotePath):
        """
        Write the contents of a file to the output, byte for byte.

        :param filename: Path to the file to display
        """
        self._write(await self.afc.get_file_contents(self.relative_path(filename)))

    @shell_command
    async def _do_rm(self, files: list[RemotePath]):
        """
        Remove one or more files or directories.

        :param files: List of file/directory paths to remove
        """
        for filename in files:
            await self.afc.rm(self.relative_path(filename))

    @shell_command
    async def _do_pull(
        self,
        remote_path: RemotePath,
        local_path: str,
        *,
        ignore_errors: bool = False,
        progress_bar: bool = False,
    ) -> None:
        """
        Pull a file or directory from device to local machine.

        :param remote_path: Path on the device to pull from
        :param local_path: Local destination path
        :param ignore_errors: Ignore errors and continue
        :param progress_bar: Show a progress bar for large files
        """

        def log(src: str, dst: str):
            print(f"{src} --> {dst}")

        await self.afc.pull(
            remote_path,
            local_path,
            callback=log,
            src_dir=self.cwd,
            ignore_errors=ignore_errors,
            progress_bar=progress_bar,
        )

    @shell_command
    async def _do_push(self, local_path: str, remote_path: RemotePath):
        """
        Push a file or directory from local machine to device.

        :param local_path: Local source path
        :param remote_path: Destination path on the device
        """

        def log(src: str, dst: str):
            print(f"{src} --> {dst}")

        await self.afc.push(local_path, self.relative_path(remote_path), callback=log)

    @shell_command
    async def _do_head(self, filename: RemotePath, *, lines: Annotated[int, Arg("-n")] = 10):
        """
        Display the first lines of a file.

        :param filename: Path to the file
        :param lines: How many lines to display
        """
        data = await self.afc.get_file_contents(self.relative_path(filename))
        self._write(b"".join(data.splitlines(keepends=True)[:lines]))

    @shell_command
    async def _do_hexdump(self, filename: RemotePath):
        """
        Display a hexadecimal dump of a file's contents.

        :param filename: Path to the file
        """
        print(hexdump(await self.afc.get_file_contents(self.relative_path(filename))))

    @shell_command
    async def _do_mkdir(self, filename: RemotePath):
        """
        Create a directory on the device.

        :param filename: Path of the directory to create
        """
        await self.afc.makedirs(self.relative_path(filename))

    @shell_command
    async def _do_info(self):
        """Display device file system information."""
        for k, v in (await self.afc.get_device_info()).items():
            print(f"{k}: {v}")

    @shell_command
    async def _do_mv(
        self,
        source: RemotePath,
        dest: RemotePath,
    ):
        """
        Move or rename a file or directory.

        :param source: Source path
        :param dest: Destination path
        """
        await self.afc.rename(self.relative_path(source), self.relative_path(dest))

    @shell_command
    async def _do_stat(self, filename: RemotePath):
        """
        Display detailed file or directory statistics.

        :param filename: Path to the file or directory
        """
        for k, v in (await self.afc.stat(self.relative_path(filename))).items():
            print(f"{k}: {v}")

    @staticmethod
    def _write(data: bytes) -> None:
        """Write to the command's output as is, so a file piped or redirected arrives byte for byte."""
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    def relative_path(self, filename: str) -> str:
        """
        Convert a relative path to an absolute path based on cwd.

        :param filename: Relative or absolute path
        :return: Absolute path
        """
        return posixpath.join(self.cwd, filename)
