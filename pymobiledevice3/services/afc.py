#!/usr/bin/env python3
"""
AFC (Apple File Connection) Service Module

This module provides an interface to interact with iOS devices' file systems through the AFC protocol.
It supports file operations like reading, writing, deleting, and directory traversal, as well as an
interactive shell for navigating the device's file system rooted at /var/mobile/Media.
"""

import logging
import os
import pathlib
import posixpath
import shlex
import shutil
import stat as stat_module
import struct
import sys
import warnings
from collections import namedtuple
from datetime import datetime
from re import Pattern
from typing import Callable, Optional, Union

import hexdump
from click.exceptions import Exit
from construct import Const, Container, CString, Enum, GreedyRange, Int64ul, Struct, Tell
from parameter_decorators import path_to_str
from pygments import formatters, highlight, lexers
from pygnuutils.cli.ls import ls as ls_cli
from pygnuutils.ls import Ls, LsStub
from tqdm.auto import trange
from xonsh.built_ins import XSH
from xonsh.cli_utils import Annotated, Arg, ArgParserAlias
from xonsh.main import main as xonsh_main
from xonsh.tools import print_color

from pymobiledevice3.exceptions import AfcException, AfcFileNotFoundError, ArgumentError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import try_decode

MAXIMUM_READ_SIZE = 4 * 1024**2  # 4 MB
MODE_MASK = 0o0000777

StatResult = namedtuple(
    "StatResult",
    [
        "st_mode",
        "st_ino",
        "st_dev",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_atime",
        "st_mtime",
        "st_ctime",
        "st_blocks",
        "st_blksize",
        "st_birthtime",
    ],
)

afc_opcode_t = Enum(
    Int64ul,
    STATUS=0x00000001,
    DATA=0x00000002,  # Data */
    READ_DIR=0x00000003,  # ReadDir */
    READ_FILE=0x00000004,  # ReadFile */
    WRITE_FILE=0x00000005,  # WriteFile */
    WRITE_PART=0x00000006,  # WritePart */
    TRUNCATE=0x00000007,  # TruncateFile */
    REMOVE_PATH=0x00000008,  # RemovePath */
    MAKE_DIR=0x00000009,  # MakeDir */
    GET_FILE_INFO=0x0000000A,  # GetFileInfo */
    GET_DEVINFO=0x0000000B,  # GetDeviceInfo */
    WRITE_FILE_ATOM=0x0000000C,  # WriteFileAtomic (tmp file+rename) */
    FILE_OPEN=0x0000000D,  # FileRefOpen */
    FILE_OPEN_RES=0x0000000E,  # FileRefOpenResult */
    READ=0x0000000F,  # FileRefRead */
    WRITE=0x00000010,  # FileRefWrite */
    FILE_SEEK=0x00000011,  # FileRefSeek */
    FILE_TELL=0x00000012,  # FileRefTell */
    FILE_TELL_RES=0x00000013,  # FileRefTellResult */
    FILE_CLOSE=0x00000014,  # FileRefClose */
    FILE_SET_SIZE=0x00000015,  # FileRefSetFileSize (ftruncate) */
    GET_CON_INFO=0x00000016,  # GetConnectionInfo */
    SET_CON_OPTIONS=0x00000017,  # SetConnectionOptions */
    RENAME_PATH=0x00000018,  # RenamePath */
    SET_FS_BS=0x00000019,  # SetFSBlockSize (0x800000) */
    SET_SOCKET_BS=0x0000001A,  # SetSocketBlockSize (0x800000) */
    FILE_LOCK=0x0000001B,  # FileRefLock */
    MAKE_LINK=0x0000001C,  # MakeLink */
    SET_FILE_TIME=0x0000001E,  # set st_mtime */
)

afc_error_t = Enum(
    Int64ul,
    SUCCESS=0,
    UNKNOWN_ERROR=1,
    OP_HEADER_INVALID=2,
    NO_RESOURCES=3,
    READ_ERROR=4,
    WRITE_ERROR=5,
    UNKNOWN_PACKET_TYPE=6,
    INVALID_ARG=7,
    OBJECT_NOT_FOUND=8,
    OBJECT_IS_DIR=9,
    PERM_DENIED=10,
    SERVICE_NOT_CONNECTED=11,
    OP_TIMEOUT=12,
    TOO_MUCH_DATA=13,
    END_OF_DATA=14,
    OP_NOT_SUPPORTED=15,
    OBJECT_EXISTS=16,
    OBJECT_BUSY=17,
    NO_SPACE_LEFT=18,
    OP_WOULD_BLOCK=19,
    IO_ERROR=20,
    OP_INTERRUPTED=21,
    OP_IN_PROGRESS=22,
    INTERNAL_ERROR=23,
    MUX_ERROR=30,
    NO_MEM=31,
    NOT_ENOUGH_DATA=32,
    DIR_NOT_EMPTY=33,
)

afc_link_type_t = Enum(
    Int64ul,
    HARDLINK=1,
    SYMLINK=2,
)

afc_fopen_mode_t = Enum(
    Int64ul,
    RDONLY=0x00000001,  # /**< r   O_RDONLY */
    RW=0x00000002,  # /**< r+  O_RDWR   | O_CREAT */
    WRONLY=0x00000003,  # /**< w   O_WRONLY | O_CREAT  | O_TRUNC */
    WR=0x00000004,  # /**< w+  O_RDWR   | O_CREAT  | O_TRUNC */
    APPEND=0x00000005,  # /**< a   O_WRONLY | O_APPEND | O_CREAT */
    RDAPPEND=0x00000006,  # /**< a+  O_RDWR   | O_APPEND | O_CREAT */
)

AFC_FOPEN_TEXTUAL_MODES = {
    "r": afc_fopen_mode_t.RDONLY,
    "r+": afc_fopen_mode_t.RW,
    "w": afc_fopen_mode_t.WRONLY,
    "w+": afc_fopen_mode_t.WR,
    "a": afc_fopen_mode_t.APPEND,
    "a+": afc_fopen_mode_t.RDAPPEND,
}

AFC_LOCK_SH = 1 | 4  # /**< shared lock */
AFC_LOCK_EX = 2 | 4  # /**< exclusive lock */
AFC_LOCK_UN = 8 | 4  # /**< unlock */

MAXIMUM_WRITE_SIZE = 1 << 30

AFCMAGIC = b"CFA6LPAA"

afc_header_t = Struct(
    "magic" / Const(AFCMAGIC),
    "entire_length" / Int64ul,
    "this_length" / Int64ul,
    "packet_num" / Int64ul,
    "operation" / afc_opcode_t,
    "_data_offset" / Tell,
)

afc_read_dir_req_t = Struct(
    "filename" / CString("utf8"),
)

afc_read_dir_resp_t = Struct(
    "filenames" / GreedyRange(CString("utf8")),
)

afc_mkdir_req_t = Struct(
    "filename" / CString("utf8"),
)

afc_stat_t = Struct(
    "filename" / CString("utf8"),
)

afc_make_link_req_t = Struct(
    "type" / afc_link_type_t,
    "target" / CString("utf8"),
    "source" / CString("utf8"),
)

afc_fopen_req_t = Struct(
    "mode" / afc_fopen_mode_t,
    "filename" / CString("utf8"),
)

afc_fopen_resp_t = Struct(
    "handle" / Int64ul,
)

afc_fclose_req_t = Struct(
    "handle" / Int64ul,
)

afc_rm_req_t = Struct(
    "filename" / CString("utf8"),
)

afc_rename_req_t = Struct(
    "source" / CString("utf8"),
    "target" / CString("utf8"),
)

afc_fread_req_t = Struct(
    "handle" / Int64ul,
    "size" / Int64ul,
)

afc_lock_t = Struct(
    "handle" / Int64ul,
    "op" / Int64ul,
)


def list_to_dict(d):
    """
    Convert a null-terminated key-value list to a dictionary.

    The input is expected to be a byte string with alternating keys and values,
    each separated by null bytes (\x00).

    :param d: Byte string containing null-terminated key-value pairs
    :return: Dictionary mapping keys to values
    :raises: AssertionError if the list doesn't contain an even number of elements
    """
    d = d.decode("utf-8")
    t = d.split("\x00")
    t = t[:-1]

    assert len(t) % 2 == 0
    res = {}
    for i in range(int(len(t) / 2)):
        res[t[i * 2]] = t[i * 2 + 1]
    return res


class AfcService(LockdownService):
    """
    Apple File Connection (AFC) Service for iOS device file system access.

    This service provides full file system access to the /var/mobile/Media directory
    on iOS devices. It supports standard file operations including read, write, delete,
    rename, and directory operations.

    The service communicates using a custom binary protocol with operation codes for
    different file system operations.

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

    def pull(
        self,
        relative_src: str,
        dst: str,
        match: Optional[Pattern] = None,
        callback: Optional[Callable] = None,
        src_dir: str = "",
        ignore_errors: bool = False,
        progress_bar: bool = True,
    ) -> None:
        """
        Pull (download) a file or directory from the device to the local machine.

        Recursively copies files and directories from the device to the local file system.
        Preserves modification times and handles large files by reading in chunks.

        :param relative_src: Source path relative to src_dir on the device
        :param dst: Destination path on the local machine
        :param match: Optional regex pattern to filter files (by basename)
        :param callback: Optional callback function called for each file copied (src, dst)
        :param src_dir: Base directory for resolving relative_src
        :param ignore_errors: If True, continue on errors instead of raising exceptions
        :param progress_bar: If True, show progress bar for large files
        """
        src = self.resolve_path(posixpath.join(src_dir, relative_src))

        if not self.isdir(src):
            # normal file
            if os.path.isdir(dst):
                dst = os.path.join(dst, os.path.basename(relative_src))
            with open(dst, "wb") as f:
                src_size = self.stat(src)["st_size"]
                if src_size <= MAXIMUM_READ_SIZE:
                    f.write(self.get_file_contents(src))
                else:
                    left_size = src_size
                    handle = self.fopen(src)
                    if progress_bar:
                        pb = trange(src_size // MAXIMUM_READ_SIZE + 1)
                    else:
                        pb = range(src_size // MAXIMUM_READ_SIZE + 1)
                    for _ in pb:
                        f.write(self.fread(handle, min(MAXIMUM_READ_SIZE, left_size)))
                        left_size -= MAXIMUM_READ_SIZE
                    self.fclose(handle)
            os.utime(dst, (os.stat(dst).st_atime, self.stat(src)["st_mtime"].timestamp()))
            if callback is not None:
                callback(src, dst)
        else:
            # directory
            dst_path = pathlib.Path(dst) / os.path.basename(relative_src)
            dst_path.mkdir(parents=True, exist_ok=True)

            for filename in self.listdir(src):
                src_filename = posixpath.join(src, filename)
                dst_filename = dst_path / filename

                src_filename = self.resolve_path(src_filename)

                if match is not None and not match.match(posixpath.basename(src_filename)):
                    continue

                try:
                    if self.isdir(src_filename):
                        dst_filename.mkdir(exist_ok=True)
                        self.pull(
                            src_filename,
                            str(dst_path),
                            callback=callback,
                            ignore_errors=ignore_errors,
                            progress_bar=progress_bar,
                        )
                        continue

                    self.pull(
                        src_filename,
                        str(dst_path),
                        callback=callback,
                        ignore_errors=ignore_errors,
                        progress_bar=progress_bar,
                    )

                except Exception as afc_exception:
                    if not ignore_errors:
                        raise
                    self.logger.warning(f"(Ignoring) Error: {afc_exception} occurred during the copy of {src_filename}")

    @path_to_str()
    def exists(self, filename):
        """
        Check if a file or directory exists on the device.

        :param filename: Path to check
        :return: True if the path exists, False otherwise
        """
        try:
            self.stat(filename)
        except AfcFileNotFoundError:
            return False
        return True

    @path_to_str()
    def wait_exists(self, filename):
        """
        Block until a file or directory exists on the device.

        Continuously polls the device until the specified path exists.
        Warning: This is a busy-wait and may consume significant resources.

        :param filename: Path to wait for
        """
        while not self.exists(filename):
            pass

    @path_to_str()
    def _push_internal(self, local_path, remote_path, callback=None):
        """
        Internal method for pushing files to the device.

        :param local_path: Local file or directory path
        :param remote_path: Remote destination path on the device
        :param callback: Optional callback function called for each file copied (src, dst)
        """
        if callback is not None:
            callback(local_path, remote_path)

        if not os.path.isdir(local_path):
            # normal file
            try:
                if self.isdir(remote_path):
                    # Remote is dir.
                    remote_path = posixpath.join(remote_path, os.path.basename(local_path))
            except AfcFileNotFoundError:
                # Remote is file.
                remote_parent = posixpath.dirname(remote_path)
                if not self.exists(remote_parent):
                    raise
                remote_path = posixpath.join(remote_parent, os.path.basename(remote_path))
            with open(local_path, "rb") as f:
                self.set_file_contents(remote_path, f.read())
        else:
            # directory
            if not self.exists(remote_path):
                self.makedirs(remote_path)

            for filename in os.listdir(local_path):
                local_filename = os.path.join(local_path, filename)
                remote_filename = posixpath.join(remote_path, filename).removeprefix("/")

                if os.path.isdir(local_filename):
                    if not self.exists(remote_filename):
                        self.makedirs(remote_filename)
                    self._push_internal(local_filename, remote_filename, callback=callback)
                    continue

                self._push_internal(local_filename, remote_filename, callback=callback)

    @path_to_str()
    def push(self, local_path, remote_path, callback=None):
        """
        Push (upload) a file or directory from the local machine to the device.

        Recursively copies files and directories from the local file system to the device.
        Creates necessary parent directories if they don't exist.

        :param local_path: Source path on the local machine
        :param remote_path: Destination path on the device
        :param callback: Optional callback function called for each file copied (src, dst)
        """
        if os.path.isdir(local_path):
            remote_path = posixpath.join(remote_path, os.path.basename(local_path))
        self._push_internal(local_path, remote_path, callback)

    @path_to_str()
    def rm_single(self, filename: str, force: bool = False) -> bool:
        """remove single file or directory

         return if succeed or raise exception depending on force parameter.

        :param filename: path to directory or a file
        :param force: True for ignore exception and return False
        :return: if succeed
        :rtype: bool
        """
        try:
            self._do_operation(afc_opcode_t.REMOVE_PATH, afc_rm_req_t.build({"filename": filename}), filename)
        except AfcException:
            if force:
                return False
            raise
        return True

    @path_to_str()
    def rm(self, filename: str, match: Optional[Pattern] = None, force: bool = False) -> list[str]:
        """recursive removal of a directory or a file

        if did not succeed, return list of undeleted filenames or raise exception depending on force parameter.

        :param filename: path to directory or a file
        :param match: Pattern of directory entries to remove or None to remove all
        :param force: True for ignore exception and return list of undeleted paths
        :return: list of undeleted paths
        :rtype: list[str]
        """
        if not self.exists(filename) and not self.rm_single(filename, force=force):
            return [filename]

        # single file
        if not self.isdir(filename):
            if self.rm_single(filename, force=force):
                return []
            return [filename]

        # directory content
        undeleted_items = []
        for entry in self.listdir(filename):
            current_filename = posixpath.join(filename, entry)

            if match is not None and not match.match(posixpath.basename(current_filename)):
                continue

            if self.isdir(current_filename):
                ret_undeleted_items = self.rm(current_filename, force=True)
                undeleted_items.extend(ret_undeleted_items)
            else:
                if not self.rm_single(current_filename, force=True):
                    undeleted_items.append(current_filename)

        # directory path
        try:
            if not self.rm_single(filename, force=force):
                undeleted_items.append(filename)
                return undeleted_items
        except AfcException:
            if undeleted_items:
                undeleted_items.append(filename)
            else:
                raise

        if undeleted_items:
            raise AfcException(f"Failed to delete paths: {undeleted_items}", None)

        return []

    def get_device_info(self):
        """
        Get device file system information.

        Returns information about the device's file system such as total capacity,
        free space, and block size.

        :return: Dictionary containing device file system information
        """
        return list_to_dict(self._do_operation(afc_opcode_t.GET_DEVINFO))

    @path_to_str()
    def listdir(self, filename: str):
        """
        List contents of a directory on the device.

        :param filename: Path to the directory
        :return: List of filenames in the directory (excluding '.' and '..')
        :raises: AfcException if the path is not a directory or doesn't exist
        """
        data = self._do_operation(afc_opcode_t.READ_DIR, afc_read_dir_req_t.build({"filename": filename}))
        return afc_read_dir_resp_t.parse(data).filenames[2:]  # skip the . and ..

    @path_to_str()
    def makedirs(self, filename: str):
        """
        Create a directory on the device.

        Note: Unlike os.makedirs, this does not create parent directories automatically.

        :param filename: Path of the directory to create
        :return: Response data from the operation
        """
        return self._do_operation(afc_opcode_t.MAKE_DIR, afc_mkdir_req_t.build({"filename": filename}))

    @path_to_str()
    def isdir(self, filename: str) -> bool:
        """
        Check if a path is a directory.

        :param filename: Path to check
        :return: True if the path is a directory, False otherwise
        """
        stat = self.stat(filename)
        return stat.get("st_ifmt") == "S_IFDIR"

    @path_to_str()
    def stat(self, filename: str):
        """
        Get file or directory statistics.

        :param filename: Path to the file or directory
        :return: Dictionary containing file statistics (size, mode, mtime, etc.)
        :raises: AfcFileNotFoundError if the path doesn't exist
        """
        try:
            stat = list_to_dict(
                self._do_operation(afc_opcode_t.GET_FILE_INFO, afc_stat_t.build({"filename": filename}), filename)
            )
        except AfcException as e:
            if e.status != afc_error_t.READ_ERROR:
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
    def os_stat(self, path: str):
        """
        Get file statistics in os.stat format.

        Returns a StatResult namedtuple compatible with os.stat results,
        suitable for use with standard Python file handling code.

        :param path: Path to the file or directory
        :return: StatResult namedtuple with file statistics
        """
        stat = self.stat(path)
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
    def link(self, target: str, source: str, type_=afc_link_type_t.SYMLINK):
        """
        Create a symbolic or hard link on the device.

        :param target: The target path that the link will point to
        :param source: The path where the link will be created
        :param type_: Link type (SYMLINK or HARDLINK)
        :return: Response data from the operation
        """
        return self._do_operation(
            afc_opcode_t.MAKE_LINK, afc_make_link_req_t.build({"type": type_, "target": target, "source": source})
        )

    @path_to_str()
    def fopen(self, filename: str, mode: str = "r") -> int:
        """
        Open a file on the device and return a file handle.

        :param filename: Path to the file
        :param mode: Open mode ('r', 'r+', 'w', 'w+', 'a', 'a+')
        :return: Integer file handle for subsequent operations
        :raises: ArgumentError if mode is invalid
        """
        if mode not in AFC_FOPEN_TEXTUAL_MODES:
            raise ArgumentError(f"mode can be only one of: {AFC_FOPEN_TEXTUAL_MODES.keys()}")

        data = self._do_operation(
            afc_opcode_t.FILE_OPEN, afc_fopen_req_t.build({"mode": AFC_FOPEN_TEXTUAL_MODES[mode], "filename": filename})
        )
        return afc_fopen_resp_t.parse(data).handle

    def fclose(self, handle: int):
        """
        Close an open file handle.

        :param handle: File handle returned from fopen
        :return: Response data from the operation
        """
        return self._do_operation(afc_opcode_t.FILE_CLOSE, afc_fclose_req_t.build({"handle": handle}))

    @path_to_str()
    def rename(self, source: str, target: str) -> None:
        """
        Rename or move a file or directory on the device.

        :param source: Current path of the file or directory
        :param target: New path for the file or directory
        :raises: AfcFileNotFoundError if source doesn't exist
        """
        try:
            self._do_operation(
                afc_opcode_t.RENAME_PATH,
                afc_rename_req_t.build({"source": source, "target": target}, filename=f"{source}->{target}"),
            )
        except AfcException as e:
            if self.exists(source):
                raise
            raise AfcFileNotFoundError(
                f"Failed to rename {source} into {target}. Got status: {e.status}", e.args[0], str(e.status)
            ) from e

    def fread(self, handle: int, sz: bytes) -> bytes:
        """
        Read data from an open file handle.

        Automatically handles large reads by splitting into multiple operations.

        :param handle: File handle returned from fopen
        :param sz: Number of bytes to read
        :return: Bytes read from the file
        :raises: AfcException if read operation fails
        """
        data = b""
        while sz > 0:
            to_read = MAXIMUM_READ_SIZE if sz > MAXIMUM_READ_SIZE else sz
            self._dispatch_packet(afc_opcode_t.READ, afc_fread_req_t.build({"handle": handle, "size": to_read}))
            status, chunk = self._receive_data()
            if status != afc_error_t.SUCCESS:
                raise AfcException("fread error", status)
            sz -= to_read
            data += chunk
        return data

    def fwrite(self, handle, data, chunk_size=MAXIMUM_WRITE_SIZE):
        """
        Write data to an open file handle.

        Automatically handles large writes by splitting into multiple operations.

        :param handle: File handle returned from fopen
        :param data: Bytes to write
        :param chunk_size: Size of each write chunk (default: MAXIMUM_WRITE_SIZE)
        :raises: AfcException if write operation fails
        """
        file_handle = struct.pack("<Q", handle)
        chunks_count = len(data) // chunk_size
        b = b""
        for i in range(chunks_count):
            chunk = data[i * chunk_size : (i + 1) * chunk_size]
            self._dispatch_packet(afc_opcode_t.WRITE, file_handle + chunk, this_length=48)
            b += chunk

            status, _response = self._receive_data()
            if status != afc_error_t.SUCCESS:
                raise AfcException(f"failed to write chunk: {status}", status)

        if len(data) % chunk_size:
            chunk = data[chunks_count * chunk_size :]
            self._dispatch_packet(afc_opcode_t.WRITE, file_handle + chunk, this_length=48)

            b += chunk

            status, _response = self._receive_data()
            if status != afc_error_t.SUCCESS:
                raise AfcException(f"failed to write last chunk: {status}", status)

    @path_to_str()
    def resolve_path(self, filename: str):
        """
        Resolve symbolic links to their target paths.

        If the path is a symbolic link, returns the target path. Otherwise,
        returns the path unchanged.

        :param filename: Path to resolve
        :return: Resolved path (or original path if not a symlink)
        """
        info = self.stat(filename)
        if info["st_ifmt"] == "S_IFLNK":
            target = info["LinkTarget"]
            filename = posixpath.join(posixpath.dirname(filename), target) if not target.startswith("/") else target
        return filename

    @path_to_str()
    def get_file_contents(self, filename):
        """
        Read and return the entire contents of a file.

        Convenience method that opens a file, reads all its contents, and closes it.

        :param filename: Path to the file
        :return: Bytes containing the file contents
        :raises: AfcException if the path is not a regular file
        """
        filename = self.resolve_path(filename)
        info = self.stat(filename)

        if info["st_ifmt"] != "S_IFREG":
            raise AfcException(f"{filename} isn't a file", afc_error_t.INVALID_ARG)

        h = self.fopen(filename)
        if not h:
            return
        d = self.fread(h, int(info["st_size"]))
        self.fclose(h)
        return d

    @path_to_str()
    def set_file_contents(self, filename: str, data: bytes) -> None:
        """
        Write data to a file, creating or overwriting it.

        Convenience method that opens a file in write mode, writes data, and closes it.

        :param filename: Path to the file
        :param data: Bytes to write to the file
        """
        h = self.fopen(filename, "w")
        self.fwrite(h, data)
        self.fclose(h)

    @path_to_str()
    def walk(self, dirname: str):
        """
        Walk a directory tree, similar to os.walk.

        Generates tuples of (dirpath, dirnames, filenames) for each directory
        in the tree, starting from dirname.

        :param dirname: Root directory to walk
        :yields: Tuples of (dirpath, dirnames, filenames)
        """
        dirs = []
        files = []
        for fd in self.listdir(dirname):
            if fd in (".", "..", ""):
                continue
            infos = self.stat(posixpath.join(dirname, fd))
            if infos and infos.get("st_ifmt") == "S_IFDIR":
                dirs.append(fd)
            else:
                files.append(fd)

        yield dirname, dirs, files

        if dirs:
            for d in dirs:
                yield from self.walk(posixpath.join(dirname, d))

    @path_to_str()
    def dirlist(self, root, depth=-1):
        """
        List all files and directories recursively up to a specified depth.

        :param root: Root directory to list
        :param depth: Maximum depth to traverse (-1 for unlimited)
        :yields: Full paths of files and directories
        """
        for folder, dirs, files in self.walk(root):
            if folder == root:
                yield folder
                if depth == 0:
                    break
            if folder != root and depth != -1 and folder.count(posixpath.sep) >= depth:
                continue
            for entry in dirs + files:
                yield posixpath.join(folder, entry)

    def lock(self, handle, operation):
        """
        Apply or remove an advisory lock on an open file.

        :param handle: File handle returned from fopen
        :param operation: Lock operation (AFC_LOCK_SH, AFC_LOCK_EX, or AFC_LOCK_UN)
        :return: Response data from the operation
        """
        return self._do_operation(afc_opcode_t.FILE_LOCK, afc_lock_t.build({"handle": handle, "op": operation}))

    def _dispatch_packet(self, operation, data, this_length=0):
        """
        Send an AFC protocol packet to the device.

        :param operation: AFC operation code
        :param data: Packet payload data
        :param this_length: Override for the packet length field (0 for auto-calculation)
        """
        afcpack = Container(
            magic=AFCMAGIC,
            entire_length=afc_header_t.sizeof() + len(data),
            this_length=afc_header_t.sizeof() + len(data),
            packet_num=self.packet_num,
            operation=operation,
        )
        if this_length:
            afcpack.this_length = this_length
        header = afc_header_t.build(afcpack)
        self.packet_num += 1
        self.service.sendall(header + data)

    def _receive_data(self):
        """
        Receive an AFC protocol response packet from the device.

        :return: Tuple of (status_code, response_data)
        """
        res = self.service.recvall(afc_header_t.sizeof())
        status = afc_error_t.SUCCESS
        data = ""
        if res:
            res = afc_header_t.parse(res)
            assert res["entire_length"] >= afc_header_t.sizeof()
            length = res["entire_length"] - afc_header_t.sizeof()
            data = self.service.recvall(length)
            if res.operation == afc_opcode_t.STATUS:
                if length != 8:
                    self.logger.error("Status length != 8")
                status = afc_error_t.parse(data)
            elif res.operation != afc_opcode_t.DATA:
                pass
        return status, data

    def _do_operation(self, opcode: int, data: bytes = b"", filename: Optional[str] = None) -> bytes:
        """
        Performs a low-level operation using the specified opcode and additional data.

        This method dispatches a packet with the given opcode and data, waits for a
        response, and processes the result to determine success or failure. If the
        operation is unsuccessful, an appropriate exception is raised.

        :param opcode: The operation code specifying the type of operation to perform.
        :param data: The additional data to send along with the operation. Defaults to an empty byte string.
        :param  filename: The filename associated with the operation, if applicable. Defaults to None.

        :returns: bytes: The data received as a response to the operation.

        :raises:
            AfcException: General exception raised if the operation fails with an
                          unspecified error status.
            AfcFileNotFoundError: Exception raised when the operation fails due to
                                  an object not being found (e.g., file or directory).
        """
        self._dispatch_packet(opcode, data)
        status, data = self._receive_data()

        exception = AfcException
        if status != afc_error_t.SUCCESS:
            if status == afc_error_t.OBJECT_NOT_FOUND:
                exception = AfcFileNotFoundError

            message = f"Opcode: {opcode} failed with status: {status}"
            if filename is not None:
                message += f" for file: {filename}"
            raise exception(message, status, filename)

        return data


class AfcLsStub(LsStub):
    """
    Adapter class to make AfcShell compatible with pygnuutils ls implementation.

    This stub provides an interface between the pygnuutils Ls class and the AFC
    file system, translating calls to work with remote device paths.
    """

    def __init__(self, afc_shell, stdout):
        """
        Initialize the ls stub.

        :param afc_shell: AfcShell instance providing device access
        :param stdout: Output stream for ls results
        """
        self.afc_shell = afc_shell
        self.stdout = stdout

    @property
    def sep(self):
        return posixpath.sep

    def join(self, path, *paths):
        return posixpath.join(path, *paths)

    def abspath(self, path):
        return posixpath.normpath(path)

    def stat(self, path, dir_fd=None, follow_symlinks=True):
        if follow_symlinks:
            path = self.afc_shell.afc.resolve_path(path)
        return self.afc_shell.afc.os_stat(path)

    def readlink(self, path, dir_fd=None):
        return self.afc_shell.afc.resolve_path(path)

    def isabs(self, path):
        return posixpath.isabs(path)

    def dirname(self, path):
        return posixpath.dirname(path)

    def basename(self, path):
        return posixpath.basename(path)

    def getgroup(self, st_gid):
        return "-"

    def getuser(self, st_uid):
        return "-"

    def now(self):
        return self.afc_shell.lockdown.date

    def listdir(self, path="."):
        return self.afc_shell.afc.listdir(path)

    def system(self):
        return "Darwin"

    def getenv(self, key, default=None):
        return ""

    def print(self, *objects, sep=" ", end="\n", file=sys.stdout, flush=False):
        print(objects[0], end=end)

    def get_tty_width(self):
        return os.get_terminal_size().columns


def path_completer(xsh, action, completer, alias, command) -> list[str]:
    """
    Provide path completion for xonsh shell commands.

    Generates completion suggestions based on the current working directory
    and available files/directories on the device.

    :param xsh: Xonsh shell instance
    :param action: Completion action
    :param completer: Completer instance
    :param alias: Command alias
    :param command: Command being completed
    :return: List of completion suggestions
    """
    shell: AfcShell = XSH.ctx["_shell"]
    pwd = shell.cwd
    is_absolute = command.prefix.startswith("/")
    dirpath = posixpath.join(pwd, command.prefix)
    if not shell.afc.exists(dirpath):
        dirpath = posixpath.dirname(dirpath)
    result = []
    for f in shell.afc.listdir(dirpath):
        if is_absolute:
            completion_option = posixpath.join(dirpath, f)
        else:
            completion_option = posixpath.relpath(posixpath.join(dirpath, f), pwd)
        try:
            if shell.afc.isdir(posixpath.join(dirpath, f)):
                result.append(f"{completion_option}/")
            else:
                result.append(completion_option)
        except AfcException:
            result.append(completion_option)
    return result


def dir_completer(xsh, action, completer, alias, command):
    """
    Provide directory-only completion for xonsh shell commands.

    Similar to path_completer but only suggests directories, not files.

    :param xsh: Xonsh shell instance
    :param action: Completion action
    :param completer: Completer instance
    :param alias: Command alias
    :param command: Command being completed
    :return: List of directory completion suggestions
    """
    shell: AfcShell = XSH.ctx["_shell"]
    pwd = shell.cwd
    is_absolute = command.prefix.startswith("/")
    dirpath = posixpath.join(pwd, command.prefix)
    if not shell.afc.exists(dirpath):
        dirpath = posixpath.dirname(dirpath)
    result = []
    for f in shell.afc.listdir(dirpath):
        if is_absolute:
            completion_option = posixpath.join(dirpath, f)
        else:
            completion_option = posixpath.relpath(posixpath.join(dirpath, f), pwd)
        try:
            if shell.afc.isdir(posixpath.join(dirpath, f)):
                result.append(f"{completion_option}/")
        except AfcException:
            result.append(completion_option)
    return result


class AfcShell:
    """
    Interactive xonsh-based shell for navigating an iOS device's file system via AFC.

    Provides a familiar shell environment with common commands (ls, cd, cat, etc.)
    that operate on the remote device's file system. The shell is powered by xonsh
    and includes features like tab completion, history, and command aliases.

    Attributes:
        lockdown: Lockdown service provider for device communication
        afc: AfcService instance for file operations
        cwd: Current working directory on the device
    """

    @classmethod
    def create(
        cls,
        service_provider: LockdownServiceProvider,
        service_name: Optional[str] = None,
        service: Optional[LockdownService] = None,
        auto_cd: Optional[str] = "/",
    ):
        """
        Create and launch an AFC shell session.

        This class method sets up the xonsh environment and starts an interactive
        shell session for navigating the device's file system.

        :param service_provider: Lockdown service provider for device connection
        :param service_name: Optional AFC service name override
        :param service: Optional pre-initialized AFC service instance
        :param auto_cd: Initial working directory (default: "/")
        """
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        args = ["--rc", str(pathlib.Path(__file__).absolute())]
        os.environ["XONSH_COLOR_STYLE"] = "default"
        XSH.ctx["_class"] = cls
        XSH.ctx["_lockdown"] = service_provider
        XSH.ctx["_auto_cd"] = auto_cd
        if service is not None:
            XSH.ctx["_service"] = service
        else:
            XSH.ctx["_service"] = AfcService(service_provider, service_name=service_name)

        try:
            logging.getLogger("parso.python.diff").disabled = True
            logging.getLogger("parso.cache").disabled = True
            xonsh_main(args)
        except SystemExit:
            pass

    def __init__(self, lockdown: LockdownServiceProvider, service: AfcService):
        """
        Initialize the AFC shell.

        Sets up the shell environment, registers commands, and configures the prompt.
        This is called internally by the create() class method.

        :param lockdown: Lockdown service provider for device communication
        :param service: AFC service instance for file operations
        """
        self.lockdown = lockdown
        self.afc = service
        XSH.ctx["_shell"] = self
        self.cwd = XSH.ctx.get("_auto_cd", "/")
        self._commands = {}
        self._orig_aliases = {}
        self._orig_prompt = XSH.env["PROMPT"]
        self._setup_shell_commands()

        print_color("""
        {BOLD_WHITE}Welcome to xonsh-afc shell! 👋{RESET}
        Use {CYAN}show-help{RESET} to view a list of all available special commands.
            These special commands will replace all already existing commands.
        """)

    def _register_arg_parse_alias(self, name: str, handler: Union[Callable, str]):
        """
        Register a command with argument parsing support.

        :param name: Command name
        :param handler: Command handler function or string
        """
        handler = ArgParserAlias(func=handler, has_args=True, prog=name)
        self._commands[name] = handler
        if XSH.aliases.get(name):
            self._orig_aliases[name] = XSH.aliases[name]
        XSH.aliases[name] = handler

    def _register_rpc_command(self, name, handler):
        """
        Register a simple command without argument parsing.

        :param name: Command name
        :param handler: Command handler function or executable path
        """
        self._commands[name] = handler
        if XSH.aliases.get(name):
            self._orig_aliases[name] = XSH.aliases[name]
        XSH.aliases[name] = handler

    def _setup_shell_commands(self):
        """
        Initialize all shell commands and configure the shell environment.

        Clears the PATH to prevent host command execution (except for specific
        utilities), registers AFC-specific commands, and sets up the custom prompt.
        """
        # clear all host commands except for some useful ones
        XSH.env["PATH"].clear()
        # adding "file" just to fix xonsh errors
        for cmd in ["wc", "grep", "egrep", "sed", "awk", "print", "yes", "cat"]:
            executable = shutil.which(cmd)
            if executable is not None:
                self._register_rpc_command(cmd, executable)

        self._register_rpc_command("ls", self.do_ls)
        self._register_arg_parse_alias("pwd", self._do_pwd)
        self._register_arg_parse_alias("link", self._do_link)
        self._register_arg_parse_alias("cd", self._do_cd)
        self._register_arg_parse_alias("cat", self._do_cat)
        self._register_arg_parse_alias("rm", self._do_rm)
        self._register_arg_parse_alias("pull", self._do_pull)
        self._register_arg_parse_alias("push", self._do_push)
        self._register_arg_parse_alias("walk", self._do_walk)
        self._register_arg_parse_alias("head", self._do_head)
        self._register_arg_parse_alias("hexdump", self._do_hexdump)
        self._register_arg_parse_alias("mkdir", self._do_mkdir)
        self._register_arg_parse_alias("info", self._do_info)
        self._register_arg_parse_alias("mv", self._do_mv)
        self._register_arg_parse_alias("stat", self._do_stat)
        self._register_arg_parse_alias("show-help", self._do_show_help)

        XSH.env["PROMPT"] = f"[{{BOLD_CYAN}}{self.afc.service_name}:{{afc_cwd}}{{RESET}}]{{prompt_end}} "
        XSH.env["PROMPT_FIELDS"]["afc_cwd"] = self._afc_cwd
        XSH.env["PROMPT_FIELDS"]["prompt_end"] = self._prompt

    def _prompt(self) -> str:
        """
        Generate the prompt suffix based on the last command's exit status.

        :return: Green '$' for success, red '$' for failure
        """
        if len(XSH.history) == 0 or XSH.history[-1].rtn == 0:
            return "{BOLD_GREEN}${RESET}"
        return "{BOLD_RED}${RESET}"

    def _afc_cwd(self) -> str:
        """
        Get the current working directory for prompt display.

        :return: Current working directory path
        """
        return self.cwd

    def _relative_path(self, filename: str) -> str:
        """
        Convert a relative path to an absolute path based on cwd.

        :param filename: Relative or absolute path
        :return: Absolute path
        """
        return posixpath.join(self.cwd, filename)

    def _do_show_help(self):
        """Display a list of all available shell commands."""
        buf = ""
        for k, _v in self._commands.items():
            buf += f"👾 {k}\n"
        print(buf)

    def _do_pwd(self) -> None:
        """Print the current working directory."""
        print(self.cwd)

    def _do_link(self, target: str, source: str) -> None:
        """
        Create a symbolic link on the device.

        :param target: Target path that the link will point to
        :param source: Path where the link will be created
        """
        self.afc.link(self.relative_path(target), self.relative_path(source), afc_link_type_t.SYMLINK)

    def _do_cd(self, directory: Annotated[str, Arg(completer=dir_completer)]) -> None:
        """
        Change the current working directory.

        :param directory: Directory path to change to (relative or absolute)
        """
        directory = self.relative_path(directory)
        directory = posixpath.normpath(directory)
        if self.afc.exists(directory):
            self.cwd = directory
            self._update_prompt()
        else:
            print(f"[ERROR] {directory} does not exist")

    def do_ls(self, args, stdin, stdout, stderr):
        """
        List directory contents with Unix ls-like formatting.

        Supports various ls options for formatting and filtering.
        """
        try:
            with ls_cli.make_context("ls", args) as ctx:
                files = list(map(self._relative_path, ctx.params.pop("files")))
                files = files if files else [self.cwd]
                Ls(AfcLsStub(self, stdout))(*files, **ctx.params)
        except Exit:
            pass

    def _do_walk(self, directory: Annotated[str, Arg(completer=dir_completer)]):
        """
        Recursively walk a directory tree and print all paths.

        :param directory: Root directory to walk
        """
        for root, dirs, files in self.afc.walk(self.relative_path(directory)):
            for name in files:
                print(posixpath.join(root, name))
            for name in dirs:
                print(posixpath.join(root, name))

    def _do_cat(self, filename: str):
        """
        Display the contents of a file.

        :param filename: Path to the file to display
        """
        print(try_decode(self.afc.get_file_contents(self.relative_path(filename))))

    def _do_rm(self, file: Annotated[list[str], Arg(nargs="+", completer=path_completer)]):
        """
        Remove one or more files or directories.

        :param file: List of file/directory paths to remove
        """
        for filename in file:
            self.afc.rm(self.relative_path(filename))

    def _do_pull(
        self,
        remote_path: Annotated[str, Arg(completer=path_completer)],
        local_path: str,
        ignore_errors: bool = False,
        progress_bar: bool = False,
    ) -> None:
        """
        Pull a file or directory from device to local machine.

        Parameters
        ----------
        remote_path : str
            Path on the device to pull from
        local_path : str
            Local destination path
        ignore_errors : bool, optional
            Ignore errors and continue (--ignore-errors flag)
        progress_bar : bool, optional
            Show progress bar for large files (--progress_bar flag)
        """

        def log(src, dst):
            print(f"{src} --> {dst}")

        self.afc.pull(
            remote_path,
            local_path,
            callback=log,
            src_dir=self.cwd,
            ignore_errors=ignore_errors,
            progress_bar=progress_bar,
        )

    def _do_push(self, local_path: str, remote_path: Annotated[str, Arg(completer=path_completer)]):
        """
        Push a file or directory from local machine to device.

        :param local_path: Local source path
        :param remote_path: Destination path on the device
        """

        def log(src, dst):
            print(f"{src} --> {dst}")

        self.afc.push(local_path, self.relative_path(remote_path), callback=log)

    def _do_head(self, filename: Annotated[str, Arg(completer=path_completer)]):
        """
        Display the first 32 bytes of a file.

        :param filename: Path to the file
        """
        print(try_decode(self.afc.get_file_contents(self.relative_path(filename))[:32]))

    def _do_hexdump(self, filename: Annotated[str, Arg(completer=path_completer)]):
        """
        Display a hexadecimal dump of a file's contents.

        :param filename: Path to the file
        """
        print(hexdump.hexdump(self.afc.get_file_contents(self.relative_path(filename)), result="return"))

    def _do_mkdir(self, filename: Annotated[str, Arg(completer=path_completer)]):
        """
        Create a directory on the device.

        :param filename: Path of the directory to create
        """
        self.afc.makedirs(self.relative_path(filename))

    def _do_info(self):
        """Display device file system information."""
        for k, v in self.afc.get_device_info().items():
            print(f"{k}: {v}")

    def _do_mv(
        self, source: Annotated[str, Arg(completer=path_completer)], dest: Annotated[str, Arg(completer=path_completer)]
    ):
        """
        Move or rename a file or directory.

        :param source: Source path
        :param dest: Destination path
        """
        return self.afc.rename(self.relative_path(source), self.relative_path(dest))

    def _do_stat(self, filename: Annotated[str, Arg(completer=path_completer)]):
        """
        Display detailed file or directory statistics.

        :param filename: Path to the file or directory
        """
        for k, v in self.afc.stat(self.relative_path(filename)).items():
            print(f"{k}: {v}")

    def relative_path(self, filename: str) -> str:
        """
        Convert a relative path to an absolute path based on cwd.

        :param filename: Relative or absolute path
        :return: Absolute path
        """
        return posixpath.join(self.cwd, filename)

    def _update_prompt(self) -> None:
        """Update the shell prompt with syntax highlighting."""
        self.prompt = highlight(
            f"[{self.afc.service_name}:{self.cwd}]$ ",
            lexers.BashSessionLexer(),
            formatters.Terminal256Formatter(style="solarized-dark"),
        ).strip()

    def _complete(self, text, line, begidx, endidx):
        """
        Provide path completion for commands (internal method).

        :param text: Current text being completed
        :param line: Full command line
        :param begidx: Beginning index of text
        :param endidx: Ending index of text
        :return: List of completion options
        """
        curdir_diff = posixpath.dirname(text)
        dirname = posixpath.join(self.cwd, curdir_diff)
        prefix = posixpath.basename(text)
        return [
            str(posixpath.join(curdir_diff, filename))
            for filename in self.afc.listdir(dirname)
            if filename.startswith(prefix)
        ]

    def _complete_first_arg(self, text, line, begidx, endidx):
        """
        Complete only the first argument of a command.

        :return: Completion options for first arg, empty list otherwise
        """
        if self._count_completion_parts(line, begidx) > 1:
            return []
        return self._complete(text, line, begidx, endidx)

    def _complete_push_arg(self, text, line, begidx, endidx):
        """
        Completion for push command (local path, then remote path).

        :return: Local completions for first arg, remote for second
        """
        count = self._count_completion_parts(line, begidx)
        if count == 1:
            return self._complete_local(text)
        elif count == 2:
            return self._complete(text, line, begidx, endidx)
        else:
            return []

    def _complete_pull_arg(self, text, line, begidx, endidx):
        """
        Completion for pull command (remote path, then local path).

        :return: Remote completions for first arg, local for second
        """
        count = self._count_completion_parts(line, begidx)
        if count == 1:
            return self._complete(text, line, begidx, endidx)
        elif count == 2:
            return self._complete_local(text)
        else:
            return []

    @staticmethod
    def _complete_local(text: str):
        """
        Provide local file system path completions.

        :param text: Current text being completed
        :return: List of local path completions
        """
        path = pathlib.Path(text)
        path_iter = path.iterdir() if text.endswith(os.path.sep) else path.parent.iterdir()
        return [str(p) for p in path_iter if str(p).startswith(text)]

    @staticmethod
    def _count_completion_parts(line, begidx):
        """
        Count the number of space-separated parts in a command line.

        :param line: Command line text
        :param begidx: Index to count parts up to
        :return: Number of parts
        """
        # Strip the " for paths including spaces.
        return len(shlex.split(line[:begidx].rstrip('"')))


if __name__ == str(pathlib.Path(__file__).absolute()):
    """
    Entry point for xonsh RC script.

    This block is executed when the file is loaded as an xonsh RC script,
    initializing the AFC shell with the context provided by AfcShell.create().
    """
    rc = XSH.ctx["_class"](XSH.ctx["_lockdown"], XSH.ctx["_service"])
    # fix fzf conflicts
    XSH.env["fzf_history_binding"] = ""  # Ctrl+R
    XSH.env["fzf_ssh_binding"] = ""  # Ctrl+S
    XSH.env["fzf_file_binding"] = ""  # Ctrl+T
    XSH.env["fzf_dir_binding"] = ""  # Ctrl+G
