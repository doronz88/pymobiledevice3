#!/usr/bin/env python3

import logging
import os
import pathlib
import plistlib
import posixpath
import shlex
import struct
from cmd import Cmd
from pprint import pprint

import hexdump
from construct import Struct, Const, Int64ul, Container, Enum, Tell, CString, GreedyRange
from pygments import highlight, lexers, formatters

from pymobiledevice3.exceptions import AfcException, AfcFileNotFoundError, ArgumentError
from pymobiledevice3.lockdown import LockdownClient

MAXIMUM_READ_SIZE = 1 << 16
MODE_MASK = 0o0000777

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

# not really necessary
MAXIMUM_WRITE_SIZE = 1 << 32

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


class AfcService:
    def __init__(self, lockdown: LockdownClient, service_name='com.apple.afc'):
        self.logger = logging.getLogger(__name__)
        self.service_name = service_name
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.service_name)
        self.packet_num = 0

    def pull(self, src, dst, callback=None):
        if callback is not None:
            callback(src, dst)

        if not self.isdir(src):
            # normal file
            with open(dst, 'wb') as f:
                f.write(self.get_file_contents(src))
        else:
            # directory
            if not os.path.exists(dst):
                dst = os.path.join(dst, os.path.basename(src))
                os.makedirs(dst)

            for filename in self.listdir(src):
                src_filename = posixpath.join(src, filename)
                dst_filename = os.path.join(dst, filename)

                if self.isdir(src_filename):
                    if not os.path.exists(dst_filename):
                        os.makedirs(dst_filename)
                    self.pull(src_filename, dst_filename, callback=callback)
                    continue

                self.pull(src_filename, dst_filename, callback=callback)

    def exists(self, filename):
        try:
            self.stat(filename)
            return True
        except AfcFileNotFoundError:
            return False

    def makedirs(self, filename):
        filename = filename.removeprefix('/')
        temp = '.'
        for sub_entry in pathlib.PosixPath(filename).parts:
            temp = posixpath.join(temp, sub_entry)
            if not self.exists(temp):
                self.mkdir(temp)

    def push(self, local_path, remote_path, callback=None):
        if callback is not None:
            callback(local_path, remote_path)

        if not os.path.isdir(local_path):
            # normal file
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
                    self.push(local_filename, remote_filename, callback=callback)
                    continue

                self.push(local_filename, remote_filename, callback=callback)

    def _rm_single(self, filename, force=False):
        try:
            self._do_operation(afc_opcode_t.REMOVE_PATH, afc_rm_req_t.build({'filename': filename}))
        except AfcException as e:
            if not force:
                raise e

    def rm(self, filename, force=False):
        if not self.isdir(filename):
            # single file
            self._rm_single(filename, force=force)
            return

        # directory
        for entry in self.listdir(filename):
            current_filename = posixpath.join(filename, entry)
            if self.isdir(current_filename):
                self.rm(current_filename, force=force)
            else:
                self._rm_single(current_filename, force=force)
        return self._rm_single(filename, force=force)

    def get_device_info(self):
        return list_to_dict(self._do_operation(afc_opcode_t.GET_DEVINFO))

    def listdir(self, filename):
        data = self._do_operation(afc_opcode_t.READ_DIR, afc_read_dir_req_t.build({'filename': filename}))
        return afc_read_dir_resp_t.parse(data).filenames[2:]  # skip the . and ..

    def mkdir(self, filename):
        return self._do_operation(afc_opcode_t.MAKE_DIR, afc_mkdir_req_t.build({'filename': filename}))

    def isdir(self, filename) -> bool:
        stat = self.stat(filename)
        return stat.get('st_ifmt') == 'S_IFDIR'

    def stat(self, filename):
        return list_to_dict(
            self._do_operation(afc_opcode_t.GET_FILE_INFO, afc_stat_t.build({'filename': filename})))

    def link(self, target, source, type_=afc_link_type_t.SYMLINK):
        source = source.encode('utf-8')
        return self._do_operation(afc_opcode_t.MAKE_LINK,
                                  afc_make_link_req_t.build({'type': type_, 'target': target, 'source': source}))

    def fopen(self, filename, mode='r'):
        # filename = filename.removeprefix('/')
        if mode not in AFC_FOPEN_TEXTUAL_MODES:
            raise ArgumentError(f'mode can be only one of: {AFC_FOPEN_TEXTUAL_MODES.keys()}')

        data = self._do_operation(afc_opcode_t.FILE_OPEN,
                                  afc_fopen_req_t.build({'mode': AFC_FOPEN_TEXTUAL_MODES[mode], 'filename': filename}))
        return afc_fopen_resp_t.parse(data).handle

    def fclose(self, handle):
        return self._do_operation(afc_opcode_t.FILE_CLOSE, afc_fclose_req_t.build({'handle': handle}))

    def rename(self, source, target):
        return self._do_operation(afc_opcode_t.RENAME_PATH,
                                  afc_rename_req_t.build({'source': source, 'target': target}))

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
                raise IOError(f'failed to write chunk: {status}')

        if len(data) % chunk_size:
            chunk = data[chunks_count * chunk_size:]
            self._dispatch_packet(afc_opcode_t.WRITE,
                                  file_handle + chunk,
                                  this_length=48)

            b += chunk

            status, response = self._receive_data()
            if status != afc_error_t.SUCCESS:
                raise IOError(f'failed to write last chunk: {status}')

    def get_file_contents(self, filename):
        info = self.stat(filename)
        if info:
            if info['st_ifmt'] == 'S_IFLNK':
                filename = info['LinkTarget']

            if info['st_ifmt'] == 'S_IFDIR':
                raise AfcException(f'{filename} is a directory', afc_error_t.OBJECT_IS_DIR)

            h = self.fopen(filename)
            if not h:
                return
            d = self.fread(h, int(info['st_size']))
            self.fclose(h)
            return d
        return

    def set_file_contents(self, filename, data):
        h = self.fopen(filename, 'w')
        self.fwrite(h, data)
        self.fclose(h)

    def walk(self, dirname):
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
                for walk_result in self.walk(posixpath.join(dirname, d)):
                    yield walk_result

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


def safe_cmd(f):
    def safe_f(self, *args, **kwargs):
        try:
            f(self, *args, **kwargs)
        except AfcException as e:
            logging.error(f'{e}')
        except KeyboardInterrupt:
            # reconnect to service
            self.afc = AfcService(self.lockdown, service_name=self.service_name)
            logging.warning('user aborted')

    return safe_f


class AfcShell(Cmd):
    def __init__(self, lockdown: LockdownClient, service_name='com.apple.afc', completekey='tab'):
        Cmd.__init__(self, completekey=completekey)
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service_name = service_name
        self.afc = AfcService(self.lockdown, service_name=service_name)
        self.curdir = '/'
        self.complete_cat = self._complete
        self.complete_ls = self._complete
        self._update_prompt()

    def do_exit(self, args):
        return True

    def do_quit(self, args):
        return True

    def do_pwd(self, args):
        print(self.curdir)

    @safe_cmd
    def do_link(self, args):
        z = args.split()
        self.afc.link(afc_link_type_t.SYMLINK, z[0], z[1])

    @safe_cmd
    def do_cd(self, args):
        if not args.startswith('/'):
            new = posixpath.join(self.curdir, args)
        else:
            new = args

        new = posixpath.normpath(new)
        if self.afc.listdir(new):
            self.curdir = new
            self._update_prompt()
        else:
            self.logger.error('%s does not exist', new)

    @safe_cmd
    def do_ls(self, args):
        filename = posixpath.join(self.curdir, args)
        if self.curdir.endswith('/'):
            filename = posixpath.join(self.curdir, args)
        filenames = self.afc.listdir(filename)
        if filenames:
            for filename in filenames:
                print(filename)

    @safe_cmd
    def do_walk(self, args):
        dirname = posixpath.join(self.curdir, args)
        for filename in self.afc.listdir(dirname):
            filename = posixpath.join(dirname, filename)
            print(filename)
            if self.afc.isdir(filename):
                self.do_walk(filename)

    @safe_cmd
    def do_cat(self, args):
        data = self.afc.get_file_contents(posixpath.join(self.curdir, args))
        if data and args.endswith('.plist'):
            pprint(plistlib.loads(data))
        else:
            print(data)

    @safe_cmd
    def do_rm(self, args):
        for filename in shlex.split(args):
            self.afc.rm(filename)

    @safe_cmd
    def do_pull(self, args):
        def log(src, dst):
            logging.info(f'{src} --> {dst}')

        args = shlex.split(args)
        if len(args) != 2:
            logging.error('pull expects <src> <dst>')
            return
        else:
            remote_path = args[0]
            local_path = args[1]

        remote_path = posixpath.normpath(posixpath.join(self.curdir, remote_path))
        self.afc.pull(remote_path, local_path, callback=log)

    @safe_cmd
    def do_push(self, args):
        def log(src, dst):
            logging.info(f'{src} --> {dst}')

        args = shlex.split(args)
        if len(args) != 2:
            logging.error('push expects <src> <dst>')
            return
        else:
            local_path = args[0]
            remote_path = args[1]

        remote_path = posixpath.normpath(posixpath.join(self.curdir, remote_path))
        self.afc.push(local_path, remote_path, callback=log)

    @safe_cmd
    def do_head(self, args):
        print(self.afc.get_file_contents(posixpath.join(self.curdir, args))[:32])

    @safe_cmd
    def do_hexdump(self, args):
        args = posixpath.join(self.curdir, args)
        print(hexdump.hexdump(self.afc.get_file_contents(args)))

    @safe_cmd
    def do_mkdir(self, args):
        self.afc.mkdir(args)

    @safe_cmd
    def do_info(self, args):
        for k, v in self.afc.get_device_info().items():
            print(k, '\t:\t', v)

    @safe_cmd
    def do_mv(self, args):
        t = args.split()
        return self.afc.rename(t[0], t[1])

    @safe_cmd
    def do_stat(self, args):
        args = posixpath.join(self.curdir, args)
        pprint(self.afc.stat(args))

    def _update_prompt(self):
        self.prompt = highlight(f'[AFC:{self.curdir}]$ ', lexers.BashSessionLexer(),
                                formatters.TerminalTrueColorFormatter(style='solarized-dark')).strip()

    def _complete(self, text, line, begidx, endidx):
        dirname = posixpath.join(self.curdir, posixpath.dirname(text))
        prefix = posixpath.basename(text)
        return [filename for filename in self.afc.listdir(dirname) if filename.startswith(prefix)]
