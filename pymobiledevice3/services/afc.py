#!/usr/bin/env python3

import logging
import os
import pathlib
import posixpath
import shlex
import shutil
import stat as stat_module
import struct
import sys
from collections import namedtuple
from datetime import datetime
from typing import Callable, List, Optional, Union

import hexdump
from click.exceptions import Exit
from construct import Const, Container, CString, Enum, GreedyRange, Int64ul, Struct, Tell
from parameter_decorators import path_to_str
from pygments import formatters, highlight, lexers
from pygnuutils.cli.ls import ls as ls_cli
from pygnuutils.ls import Ls, LsStub
from xonsh.built_ins import XSH
from xonsh.cli_utils import Annotated, Arg, ArgParserAlias
from xonsh.main import main as xonsh_main
from xonsh.tools import print_color

from pymobiledevice3.exceptions import AfcException, AfcFileNotFoundError, ArgumentError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import try_decode

MAXIMUM_READ_SIZE = 4 * 1024 ** 2  # 4 MB
MODE_MASK = 0o0000777

StatResult = namedtuple('StatResult',
                        ['st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_atime',
                         'st_mtime', 'st_ctime', 'st_blocks', 'st_blksize', 'st_birthtime'])

afc_opcode_t = Enum(Int64ul,
                    STATUS=0x00000001,
                    DATA=0x00000002,  # Data */
                    READ_DIR=0x00000003,  # ReadDir */
                    READ_FILE=0x00000004,  # ReadFile */
                    WRITE_FILE=0x00000005,  # WriteFile */
                    WRITE_PART=0x00000006,  # WritePart */
                    TRUNCATE=0x00000007,  # TruncateFile */
                    REMOVE_PATH=0x00000008,  # RemovePath */
                    MAKE_DIR=0x00000009,  # MakeDir */
                    GET_FILE_INFO=0x0000000a,  # GetFileInfo */
                    GET_DEVINFO=0x0000000b,  # GetDeviceInfo */
                    WRITE_FILE_ATOM=0x0000000c,  # WriteFileAtomic (tmp file+rename) */
                    FILE_OPEN=0x0000000d,  # FileRefOpen */
                    FILE_OPEN_RES=0x0000000e,  # FileRefOpenResult */
                    READ=0x0000000f,  # FileRefRead */
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

afc_error_t = Enum(Int64ul,
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

afc_link_type_t = Enum(Int64ul,
                       HARDLINK=1,
                       SYMLINK=2,
                       )

afc_fopen_mode_t = Enum(Int64ul,
                        RDONLY=0x00000001,  # /**< r   O_RDONLY */
                        RW=0x00000002,  # /**< r+  O_RDWR   | O_CREAT */
                        WRONLY=0x00000003,  # /**< w   O_WRONLY | O_CREAT  | O_TRUNC */
                        WR=0x00000004,  # /**< w+  O_RDWR   | O_CREAT  | O_TRUNC */
                        APPEND=0x00000005,  # /**< a   O_WRONLY | O_APPEND | O_CREAT */
                        RDAPPEND=0x00000006,  # /**< a+  O_RDWR   | O_APPEND | O_CREAT */
                        )

AFC_FOPEN_TEXTUAL_MODES = {
    'r': afc_fopen_mode_t.RDONLY,
    'r+': afc_fopen_mode_t.RW,
    'w': afc_fopen_mode_t.WRONLY,
    'w+': afc_fopen_mode_t.WR,
    'a': afc_fopen_mode_t.APPEND,
    'a+': afc_fopen_mode_t.RDAPPEND,
}

AFC_LOCK_SH = 1 | 4  # /**< shared lock */
AFC_LOCK_EX = 2 | 4  # /**< exclusive lock */
AFC_LOCK_UN = 8 | 4  # /**< unlock */

MAXIMUM_WRITE_SIZE = 1 << 30

AFCMAGIC = b'CFA6LPAA'

afc_header_t = Struct(
    'magic' / Const(AFCMAGIC),
    'entire_length' / Int64ul,
    'this_length' / Int64ul,
    'packet_num' / Int64ul,
    'operation' / afc_opcode_t,
    '_data_offset' / Tell,
)

afc_read_dir_req_t = Struct(
    'filename' / CString('utf8'),
)

afc_read_dir_resp_t = Struct(
    'filenames' / GreedyRange(CString('utf8')),
)

afc_mkdir_req_t = Struct(
    'filename' / CString('utf8'),
)

afc_stat_t = Struct(
    'filename' / CString('utf8'),
)

afc_make_link_req_t = Struct(
    'type' / afc_link_type_t,
    'target' / CString('utf8'),
    'source' / CString('utf8'),
)

afc_fopen_req_t = Struct(
    'mode' / afc_fopen_mode_t,
    'filename' / CString('utf8'),
)

afc_fopen_resp_t = Struct(
    'handle' / Int64ul,
)

afc_fclose_req_t = Struct(
    'handle' / Int64ul,
)

afc_rm_req_t = Struct(
    'filename' / CString('utf8'),
)

afc_rename_req_t = Struct(
    'source' / CString('utf8'),
    'target' / CString('utf8'),
)

afc_fread_req_t = Struct(
    'handle' / Int64ul,
    'size' / Int64ul,
)

afc_lock_t = Struct(
    'handle' / Int64ul,
    'op' / Int64ul,
)


def list_to_dict(d):
    d = d.decode('utf-8')
    t = d.split('\x00')
    t = t[:-1]

    assert len(t) % 2 == 0
    res = {}
    for i in range(int(len(t) / 2)):
        res[t[i * 2]] = t[i * 2 + 1]
    return res


class AfcService(LockdownService):
    SERVICE_NAME = 'com.apple.afc'
    RSD_SERVICE_NAME = 'com.apple.afc.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider, service_name: str = None):
        if service_name is None:
            if isinstance(lockdown, LockdownClient):
                service_name = self.SERVICE_NAME
            else:
                service_name = self.RSD_SERVICE_NAME
        super().__init__(lockdown, service_name)
        self.packet_num = 0

    def pull(self, relative_src, dst, callback=None, src_dir=''):
        src = posixpath.join(src_dir, relative_src)
        if callback is not None:
            callback(src, dst)

        src = self.resolve_path(src)

        if not self.isdir(src):
            # normal file
            if os.path.isdir(dst):
                dst = os.path.join(dst, os.path.basename(relative_src))
            with open(dst, 'wb') as f:
                f.write(self.get_file_contents(src))
        else:
            # directory
            dst_path = pathlib.Path(dst) / os.path.basename(relative_src)
            dst_path.mkdir(parents=True, exist_ok=True)

            for filename in self.listdir(src):
                src_filename = posixpath.join(src, filename)
                dst_filename = dst_path / filename

                src_filename = self.resolve_path(src_filename)

                if self.isdir(src_filename):
                    dst_filename.mkdir(exist_ok=True)
                    self.pull(src_filename, str(dst_path), callback=callback)
                    continue

                self.pull(src_filename, str(dst_path), callback=callback)

    @path_to_str()
    def exists(self, filename):
        try:
            self.stat(filename)
            return True
        except AfcFileNotFoundError:
            return False

    @path_to_str()
    def wait_exists(self, filename):
        while not self.exists(filename):
            pass

    @path_to_str()
    def _push_internal(self, local_path, remote_path, callback=None):
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
            with open(local_path, 'rb') as f:
                self.set_file_contents(remote_path, f.read())
        else:
            # directory
            if not self.exists(remote_path):
                self.makedirs(remote_path)

            for filename in os.listdir(local_path):
                local_filename = os.path.join(local_path, filename)
                remote_filename = posixpath.join(remote_path, filename).removeprefix('/')

                if os.path.isdir(local_filename):
                    if not self.exists(remote_filename):
                        self.makedirs(remote_filename)
                    self._push_internal(local_filename, remote_filename, callback=callback)
                    continue

                self._push_internal(local_filename, remote_filename, callback=callback)

    @path_to_str()
    def push(self, local_path, remote_path, callback=None):
        if os.path.isdir(local_path):
            remote_path = posixpath.join(remote_path, os.path.basename(local_path))
        self._push_internal(local_path, remote_path, callback)

    @path_to_str()
    def _rm_single(self, filename: str, force: bool = False) -> bool:
        """ remove single file or directory

         return if succeed or raise exception depending on force parameter.

        :param filename: path to directory or a file
        :param force: True for ignore exception and return False
        :return: if succeed
        :rtype: bool
        """
        try:
            self._do_operation(afc_opcode_t.REMOVE_PATH, afc_rm_req_t.build({'filename': filename}))
            return True
        except AfcException:
            if force:
                return False
            raise

    @path_to_str()
    def rm(self, filename: str, force: bool = False) -> List[str]:
        """ recursive removal of a directory or a file

        if did not succeed, return list of undeleted filenames or raise exception depending on force parameter.

        :param filename: path to directory or a file
        :param force: True for ignore exception and return list of undeleted paths
        :return: list of undeleted paths
        :rtype: list[str]
        """
        if not self.exists(filename):
            if not self._rm_single(filename, force=force):
                return [filename]

        # single file
        if not self.isdir(filename):
            if self._rm_single(filename, force=force):
                return []
            return [filename]

        # directory content
        undeleted_items = []
        for entry in self.listdir(filename):
            current_filename = posixpath.join(filename, entry)
            if self.isdir(current_filename):
                ret_undeleted_items = self.rm(current_filename, force=True)
                undeleted_items.extend(ret_undeleted_items)
            else:
                if not self._rm_single(current_filename, force=True):
                    undeleted_items.append(current_filename)

        # directory path
        try:
            if not self._rm_single(filename, force=force):
                undeleted_items.append(filename)
                return undeleted_items
        except AfcException:
            if undeleted_items:
                undeleted_items.append(filename)
            else:
                raise

        if undeleted_items:
            raise AfcException(f'Failed to delete paths: {undeleted_items}', None)

        return []

    def get_device_info(self):
        return list_to_dict(self._do_operation(afc_opcode_t.GET_DEVINFO))

    @path_to_str()
    def listdir(self, filename: str):
        data = self._do_operation(afc_opcode_t.READ_DIR, afc_read_dir_req_t.build({'filename': filename}))
        return afc_read_dir_resp_t.parse(data).filenames[2:]  # skip the . and ..

    @path_to_str()
    def makedirs(self, filename: str):
        return self._do_operation(afc_opcode_t.MAKE_DIR, afc_mkdir_req_t.build({'filename': filename}))

    @path_to_str()
    def isdir(self, filename: str) -> bool:
        stat = self.stat(filename)
        return stat.get('st_ifmt') == 'S_IFDIR'

    @path_to_str()
    def stat(self, filename: str):
        try:
            stat = list_to_dict(
                self._do_operation(afc_opcode_t.GET_FILE_INFO, afc_stat_t.build({'filename': filename})))
        except AfcException as e:
            if e.status != afc_error_t.READ_ERROR:
                raise
            raise AfcFileNotFoundError(e.args[0], e.status) from e

        stat['st_size'] = int(stat['st_size'])
        stat['st_blocks'] = int(stat['st_blocks'])
        stat['st_mtime'] = int(stat['st_mtime'])
        stat['st_birthtime'] = int(stat['st_birthtime'])
        stat['st_nlink'] = int(stat['st_nlink'])
        stat['st_mtime'] = datetime.fromtimestamp(stat['st_mtime'] / (10 ** 9))
        stat['st_birthtime'] = datetime.fromtimestamp(stat['st_birthtime'] / (10 ** 9))
        return stat

    @path_to_str()
    def os_stat(self, path: str):
        stat = self.stat(path)
        mode = 0
        for s_mode in ['S_IFDIR', 'S_IFCHR', 'S_IFBLK', 'S_IFREG', 'S_IFIFO', 'S_IFLNK', 'S_IFSOCK']:
            if stat['st_ifmt'] == s_mode:
                mode = getattr(stat_module, s_mode)
        return StatResult(
            mode, hash(posixpath.normpath(path)), 0, stat['st_nlink'], 0, 0, stat['st_size'],
            stat['st_mtime'].timestamp(), stat['st_mtime'].timestamp(), stat['st_birthtime'].timestamp(),
            stat['st_blocks'], 4096, stat['st_birthtime'].timestamp(),
        )

    @path_to_str()
    def link(self, target: str, source: str, type_=afc_link_type_t.SYMLINK):
        return self._do_operation(afc_opcode_t.MAKE_LINK,
                                  afc_make_link_req_t.build({'type': type_, 'target': target, 'source': source}))

    @path_to_str()
    def fopen(self, filename: str, mode='r'):
        if mode not in AFC_FOPEN_TEXTUAL_MODES:
            raise ArgumentError(f'mode can be only one of: {AFC_FOPEN_TEXTUAL_MODES.keys()}')

        data = self._do_operation(afc_opcode_t.FILE_OPEN,
                                  afc_fopen_req_t.build({'mode': AFC_FOPEN_TEXTUAL_MODES[mode], 'filename': filename}))
        return afc_fopen_resp_t.parse(data).handle

    def fclose(self, handle):
        return self._do_operation(afc_opcode_t.FILE_CLOSE, afc_fclose_req_t.build({'handle': handle}))

    @path_to_str()
    def rename(self, source: str, target: str):
        try:
            return self._do_operation(afc_opcode_t.RENAME_PATH,
                                      afc_rename_req_t.build({'source': source, 'target': target}))
        except AfcException as e:
            if self.exists(source):
                raise
            raise AfcFileNotFoundError(e.args[0], e.status) from e

    def fread(self, handle, sz):
        data = b''
        while sz > 0:
            if sz > MAXIMUM_READ_SIZE:
                to_read = MAXIMUM_READ_SIZE
            else:
                to_read = sz
            self._dispatch_packet(afc_opcode_t.READ, afc_fread_req_t.build({'handle': handle, 'size': to_read}))
            status, chunk = self._receive_data()
            if status != afc_error_t.SUCCESS:
                raise AfcException('fread error', status)
            sz -= to_read
            data += chunk
        return data

    def fwrite(self, handle, data, chunk_size=MAXIMUM_WRITE_SIZE):
        file_handle = struct.pack('<Q', handle)
        chunks_count = len(data) // chunk_size
        b = b''
        for i in range(chunks_count):
            chunk = data[i * chunk_size:(i + 1) * chunk_size]
            self._dispatch_packet(afc_opcode_t.WRITE,
                                  file_handle + chunk,
                                  this_length=48)
            b += chunk

            status, response = self._receive_data()
            if status != afc_error_t.SUCCESS:
                raise AfcException(f'failed to write chunk: {status}', status)

        if len(data) % chunk_size:
            chunk = data[chunks_count * chunk_size:]
            self._dispatch_packet(afc_opcode_t.WRITE,
                                  file_handle + chunk,
                                  this_length=48)

            b += chunk

            status, response = self._receive_data()
            if status != afc_error_t.SUCCESS:
                raise AfcException(f'failed to write last chunk: {status}', status)

    @path_to_str()
    def resolve_path(self, filename: str):
        info = self.stat(filename)
        if info['st_ifmt'] == 'S_IFLNK':
            target = info['LinkTarget']
            if not target.startswith('/'):
                # relative path
                filename = posixpath.join(posixpath.dirname(filename), target)
            else:
                filename = target
        return filename

    @path_to_str()
    def get_file_contents(self, filename):
        filename = self.resolve_path(filename)
        info = self.stat(filename)

        if info['st_ifmt'] != 'S_IFREG':
            raise AfcException(f'{filename} isn\'t a file', afc_error_t.INVALID_ARG)

        h = self.fopen(filename)
        if not h:
            return
        d = self.fread(h, int(info['st_size']))
        self.fclose(h)
        return d

    @path_to_str()
    def set_file_contents(self, filename: str, data: bytes) -> None:
        h = self.fopen(filename, 'w')
        self.fwrite(h, data)
        self.fclose(h)

    @path_to_str()
    def walk(self, dirname: str):
        dirs = []
        files = []
        for fd in self.listdir(dirname):
            if fd in ('.', '..', ''):
                continue
            infos = self.stat(posixpath.join(dirname, fd))
            if infos and infos.get('st_ifmt') == 'S_IFDIR':
                dirs.append(fd)
            else:
                files.append(fd)

        yield dirname, dirs, files

        if dirs:
            for d in dirs:
                yield from self.walk(posixpath.join(dirname, d))

    @path_to_str()
    def dirlist(self, root, depth=-1):
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
        return self._do_operation(afc_opcode_t.FILE_LOCK, afc_lock_t.build({'handle': handle, 'op': operation}))

    def _dispatch_packet(self, operation, data, this_length=0):
        afcpack = Container(magic=AFCMAGIC,
                            entire_length=afc_header_t.sizeof() + len(data),
                            this_length=afc_header_t.sizeof() + len(data),
                            packet_num=self.packet_num,
                            operation=operation)
        if this_length:
            afcpack.this_length = this_length
        header = afc_header_t.build(afcpack)
        self.packet_num += 1
        self.service.sendall(header + data)

    def _receive_data(self):
        res = self.service.recvall(afc_header_t.sizeof())
        status = afc_error_t.SUCCESS
        data = ''
        if res:
            res = afc_header_t.parse(res)
            assert res['entire_length'] >= afc_header_t.sizeof()
            length = res['entire_length'] - afc_header_t.sizeof()
            data = self.service.recvall(length)
            if res.operation == afc_opcode_t.STATUS:
                if length != 8:
                    self.logger.error('Status length != 8')
                status = afc_error_t.parse(data)
            elif res.operation != afc_opcode_t.DATA:
                pass
        return status, data

    def _do_operation(self, opcode: afc_opcode_t, data: bytes = b''):
        self._dispatch_packet(opcode, data)
        status, data = self._receive_data()

        exception = AfcException
        if status != afc_error_t.SUCCESS:
            if status == afc_error_t.OBJECT_NOT_FOUND:
                exception = AfcFileNotFoundError

            raise exception(f'opcode: {opcode} failed with status: {status}', status)

        return data


class AfcLsStub(LsStub):
    def __init__(self, afc_shell, stdout):
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
        return '-'

    def getuser(self, st_uid):
        return '-'

    def now(self):
        return self.afc_shell.lockdown.date

    def listdir(self, path='.'):
        return self.afc_shell.afc.listdir(path)

    def system(self):
        return 'Darwin'

    def getenv(self, key, default=None):
        return ''

    def print(self, *objects, sep=' ', end='\n', file=sys.stdout, flush=False):
        print(objects[0], end=end)

    def get_tty_width(self):
        return os.get_terminal_size().columns


def path_completer(xsh, action, completer, alias, command):
    shell: AfcShell = XSH.ctx['_shell']
    pwd = shell.cwd
    is_absolute = command.prefix.startswith('/')
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
                result.append(f'{completion_option}/')
            else:
                result.append(completion_option)
        except AfcException:
            result.append(completion_option)
    return result


def dir_completer(xsh, action, completer, alias, command):
    shell: AfcShell = XSH.ctx['_shell']
    pwd = shell.cwd
    is_absolute = command.prefix.startswith('/')
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
                result.append(f'{completion_option}/')
        except AfcException:
            result.append(completion_option)
    return result


class AfcShell:
    @classmethod
    def create(cls, service_provider: LockdownServiceProvider, service_name: Optional[str] = None,
               service: Optional[LockdownService] = None, auto_cd: Optional[str] = '/'):
        args = ['--rc']
        home_rc = pathlib.Path('~/.xonshrc').expanduser()
        if home_rc.exists():
            args.append(str(home_rc.expanduser().absolute()))
        args.append(str(pathlib.Path(__file__).absolute()))
        XSH.ctx['_class'] = cls
        XSH.ctx['_lockdown'] = service_provider
        XSH.ctx['_auto_cd'] = auto_cd
        if service is not None:
            XSH.ctx['_service'] = service
        else:
            XSH.ctx['_service'] = AfcService(service_provider, service_name=service_name)

        try:
            logging.getLogger('parso.python.diff').disabled = True
            logging.getLogger('parso.cache').disabled = True
            xonsh_main(args)
        except SystemExit:
            pass

    def __init__(self, lockdown: LockdownServiceProvider, service: AfcService):
        self.lockdown = lockdown
        self.afc = service
        XSH.ctx['_shell'] = self
        self.cwd = XSH.ctx.get('_auto_cd', '/')
        self._commands = {}
        self._orig_aliases = {}
        self._orig_prompt = XSH.env['PROMPT']
        self._setup_shell_commands()

        print_color('''
        {BOLD_WHITE}Welcome to xonsh-afc shell! 👋{RESET}
        Use {CYAN}show-help{RESET} to view a list of all available special commands.
            These special commands will replace all already existing commands.
        ''')

    def _register_arg_parse_alias(self, name: str, handler: Union[Callable, str]):
        handler = ArgParserAlias(func=handler, has_args=True, prog=name)
        self._commands[name] = handler
        if XSH.aliases.get(name):
            self._orig_aliases[name] = XSH.aliases[name]
        XSH.aliases[name] = handler

    def _register_rpc_command(self, name, handler):
        self._commands[name] = handler
        if XSH.aliases.get(name):
            self._orig_aliases[name] = XSH.aliases[name]
        XSH.aliases[name] = handler

    def _setup_shell_commands(self):
        # clear all host commands except for some useful ones
        XSH.env['PATH'].clear()
        # adding "file" just to fix xonsh errors
        for cmd in ['wc', 'grep', 'egrep', 'sed', 'awk', 'print', 'yes', 'cat', 'file']:
            executable = shutil.which(cmd)
            if executable is not None:
                self._register_rpc_command(cmd, executable)

        self._register_rpc_command('ls', self.do_ls)
        self._register_arg_parse_alias('pwd', self._do_pwd)
        self._register_arg_parse_alias('link', self._do_link)
        self._register_arg_parse_alias('cd', self._do_cd)
        self._register_arg_parse_alias('cat', self._do_cat)
        self._register_arg_parse_alias('rm', self._do_rm)
        self._register_arg_parse_alias('pull', self._do_pull)
        self._register_arg_parse_alias('push', self._do_push)
        self._register_arg_parse_alias('walk', self._do_walk)
        self._register_arg_parse_alias('head', self._do_head)
        self._register_arg_parse_alias('hexdump', self._do_hexdump)
        self._register_arg_parse_alias('mkdir', self._do_mkdir)
        self._register_arg_parse_alias('info', self._do_info)
        self._register_arg_parse_alias('mv', self._do_mv)
        self._register_arg_parse_alias('stat', self._do_stat)
        self._register_arg_parse_alias('show-help', self._do_show_help)

        XSH.env['PROMPT'] = f'[{{BOLD_CYAN}}{self.afc.service_name}:{{afc_cwd}}{{RESET}}]{{prompt_end}} '
        XSH.env['PROMPT_FIELDS']['afc_cwd'] = self._afc_cwd
        XSH.env['PROMPT_FIELDS']['prompt_end'] = self._prompt

    def _prompt(self) -> str:
        if len(XSH.history) == 0 or XSH.history[-1].rtn == 0:
            return '{BOLD_GREEN}${RESET}'
        return '{BOLD_RED}${RESET}'

    def _afc_cwd(self) -> str:
        return self.cwd

    def _relative_path(self, filename: str) -> str:
        return posixpath.join(self.cwd, filename)

    def _do_show_help(self):
        """
        list all rpc commands
        """
        buf = ''
        for k, v in self._commands.items():
            buf += f'👾 {k}\n'
        print(buf)

    def _do_pwd(self) -> None:
        print(self.cwd)

    def _do_link(self, target: str, source: str) -> None:
        self.afc.link(self.relative_path(target), self.relative_path(source), afc_link_type_t.SYMLINK)

    def _do_cd(self, directory: Annotated[str, Arg(completer=dir_completer)]) -> None:
        directory = self.relative_path(directory)
        directory = posixpath.normpath(directory)
        if self.afc.exists(directory):
            self.cwd = directory
            self._update_prompt()
        else:
            print(f'[ERROR] {directory} does not exist')

    def do_ls(self, args, stdin, stdout, stderr):
        """ list files """
        try:
            with ls_cli.make_context('ls', args) as ctx:
                files = list(map(self._relative_path, ctx.params.pop('files')))
                files = files if files else [self.cwd]
                Ls(AfcLsStub(self, stdout))(*files, **ctx.params)
        except Exit:
            pass

    def _do_walk(self, directory: Annotated[str, Arg(completer=dir_completer)]):
        for root, dirs, files in self.afc.walk(self.relative_path(directory)):
            for name in files:
                print(posixpath.join(root, name))
            for name in dirs:
                print(posixpath.join(root, name))

    def _do_cat(self, filename: str):
        print(try_decode(self.afc.get_file_contents(self.relative_path(filename))))

    def _do_rm(self, file: Annotated[List[str], Arg(nargs='+', completer=path_completer)]):
        for filename in file:
            self.afc.rm(self.relative_path(filename))

    def _do_pull(self, remote_path: Annotated[str, Arg(completer=path_completer)], local_path: str):
        def log(src, dst):
            print(f'{src} --> {dst}')

        self.afc.pull(remote_path, local_path, callback=log, src_dir=self.cwd)

    def _do_push(self, local_path: str, remote_path: Annotated[str, Arg(completer=path_completer)]):
        def log(src, dst):
            print(f'{src} --> {dst}')

        self.afc.push(local_path, self.relative_path(remote_path), callback=log)

    def _do_head(self, filename: Annotated[str, Arg(completer=path_completer)]):
        print(try_decode(self.afc.get_file_contents(self.relative_path(filename))[:32]))

    def _do_hexdump(self, filename: Annotated[str, Arg(completer=path_completer)]):
        print(hexdump.hexdump(self.afc.get_file_contents(self.relative_path(filename)), result='return'))

    def _do_mkdir(self, filename: Annotated[str, Arg(completer=path_completer)]):
        self.afc.makedirs(self.relative_path(filename))

    def _do_info(self):
        for k, v in self.afc.get_device_info().items():
            print(f'{k}: {v}')

    def _do_mv(self, source: Annotated[str, Arg(completer=path_completer)],
               dest: Annotated[str, Arg(completer=path_completer)]):
        return self.afc.rename(self.relative_path(source), self.relative_path(dest))

    def _do_stat(self, filename: Annotated[str, Arg(completer=path_completer)]):
        for k, v in self.afc.stat(self.relative_path(filename)).items():
            print(f'{k}: {v}')

    def relative_path(self, filename: str) -> str:
        return posixpath.join(self.cwd, filename)

    def _update_prompt(self) -> None:
        self.prompt = highlight(f'[{self.afc.service_name}:{self.cwd}]$ ', lexers.BashSessionLexer(),
                                formatters.TerminalTrueColorFormatter(style='solarized-dark')).strip()

    def _complete(self, text, line, begidx, endidx):
        curdir_diff = posixpath.dirname(text)
        dirname = posixpath.join(self.cwd, curdir_diff)
        prefix = posixpath.basename(text)
        return [
            str(posixpath.join(curdir_diff, filename)) for filename in self.afc.listdir(dirname)
            if filename.startswith(prefix)
        ]

    def _complete_first_arg(self, text, line, begidx, endidx):
        if self._count_completion_parts(line, begidx) > 1:
            return []
        return self._complete(text, line, begidx, endidx)

    def _complete_push_arg(self, text, line, begidx, endidx):
        count = self._count_completion_parts(line, begidx)
        if count == 1:
            return self._complete_local(text)
        elif count == 2:
            return self._complete(text, line, begidx, endidx)
        else:
            return []

    def _complete_pull_arg(self, text, line, begidx, endidx):
        count = self._count_completion_parts(line, begidx)
        if count == 1:
            return self._complete(text, line, begidx, endidx)
        elif count == 2:
            return self._complete_local(text)
        else:
            return []

    @staticmethod
    def _complete_local(text: str):
        path = pathlib.Path(text)
        path_iter = path.iterdir() if text.endswith(os.path.sep) else path.parent.iterdir()
        return [str(p) for p in path_iter if str(p).startswith(text)]

    @staticmethod
    def _count_completion_parts(line, begidx):
        # Strip the " for paths including spaces.
        return len(shlex.split(line[:begidx].rstrip('"')))


if __name__ == str(pathlib.Path(__file__).absolute()):
    rc = XSH.ctx['_class'](XSH.ctx['_lockdown'], XSH.ctx['_service'])
    # fix fzf conflicts
    XSH.env['fzf_history_binding'] = ""  # Ctrl+R
    XSH.env['fzf_ssh_binding'] = ""  # Ctrl+S
    XSH.env['fzf_file_binding'] = ""  # Ctrl+T
    XSH.env['fzf_dir_binding'] = ""  # Ctrl+G
