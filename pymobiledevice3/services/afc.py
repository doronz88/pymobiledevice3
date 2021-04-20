#!/usr/bin/env python3

import logging
import os
import plistlib
import posixpath
import struct
from cmd import Cmd
from pprint import pprint

import hexdump
from construct import Struct, Const, Int64ul, Container, Enum, Tell, CString, GreedyRange

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


def list_to_dict(d):
    d = d.decode('utf-8')
    t = d.split('\x00')
    t = t[:-1]

    assert len(t) % 2 == 0
    res = {}
    for i in range(int(len(t) / 2)):
        res[t[i * 2]] = t[i * 2 + 1]
    return res


class AfcService(object):
    def __init__(self, lockdown: LockdownClient, service_name='com.apple.afc'):
        self.logger = logging.getLogger(__name__)
        self.service_name = service_name
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.service_name)
        self.packet_num = 0

    def get_device_info(self):
        return list_to_dict(self._do_operation(afc_opcode_t.GET_DEVINFO))

    def listdir(self, filename):
        data = self._do_operation(afc_opcode_t.READ_DIR, afc_read_dir_req_t.build({'filename': filename}))
        return afc_read_dir_resp_t.parse(data).filenames

    def mkdir(self, filename):
        return self._do_operation(afc_opcode_t.MAKE_DIR, afc_mkdir_req_t.build({'filename': filename}))

    def rmdir(self, filename):
        stat = self.stat(filename)
        if not stat or stat.get('st_ifmt') != 'S_IFDIR':
            raise AfcException(f'{filename} is not a directory')

        for d in self.listdir(filename):
            if d in ('.', '..'):
                continue

            current_filename = posixpath.join(filename, d)
            stat = self.stat(current_filename)
            if stat.get('st_ifmt') == 'S_IFDIR':
                self.rmdir(current_filename)
            else:
                self.rm(current_filename)
        assert len(self.listdir(filename)) == 2  # .. et .
        return self.rm(filename)

    def stat(self, filename):
        return list_to_dict(
            self._do_operation(afc_opcode_t.GET_FILE_INFO, afc_stat_t.build({'filename': filename})))

    def link(self, target, source, type_=afc_link_type_t.SYMLINK):
        source = source.encode('utf-8')
        return self._do_operation(afc_opcode_t.MAKE_LINK,
                                  afc_make_link_req_t.build({'type': type_, 'target': target, 'source': source}))

    def fopen(self, filename, mode='r'):
        if mode not in AFC_FOPEN_TEXTUAL_MODES:
            raise ArgumentError(f'mode can be only one of: {AFC_FOPEN_TEXTUAL_MODES.keys()}')

        data = self._do_operation(afc_opcode_t.FILE_OPEN,
                                  afc_fopen_req_t.build({'mode': AFC_FOPEN_TEXTUAL_MODES[mode], 'filename': filename}))
        return afc_fopen_resp_t.parse(data).handle

    def fclose(self, handle):
        return self._do_operation(afc_opcode_t.FILE_CLOSE, afc_fclose_req_t.build({'handle': handle}))

    def rm(self, filename):
        return self._do_operation(afc_opcode_t.REMOVE_PATH, afc_rm_req_t.build({'filename': filename}))

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
                raise AfcException('fread error')
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
                raise AfcException(f'{filename} is a directory')

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
            fd = fd.decode('utf-8')
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

            raise exception(f'opcode: {opcode} failed with status: {status}')

        return data


class AfcShell(Cmd):
    def __init__(self, lockdown: LockdownClient, afcname='com.apple.afc', completekey='tab'):
        Cmd.__init__(self, completekey=completekey)
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.afc = AfcService(self.lockdown, service_name=afcname)
        self.curdir = '/'
        self.prompt = 'AFC$ ' + self.curdir + ' '
        self.complete_cat = self._complete
        self.complete_ls = self._complete

    def do_exit(self, p):
        return True

    def do_quit(self, p):
        return True

    def do_pwd(self, p):
        print(self.curdir)

    def do_link(self, p):
        z = p.split()
        self.afc.link(afc_link_type_t.SYMLINK, z[0], z[1])

    def do_cd(self, p):
        if not p.startswith('/'):
            new = posixpath.join(self.curdir, p)
        else:
            new = p

        new = os.path.normpath(new).replace('\\', '/').replace('//', '/')
        if self.afc.listdir(new):
            self.curdir = new
            self.prompt = 'AFC$ %s ' % new
        else:
            self.logger.error('%s does not exist', new)

    def _complete(self, text, line, begidx, endidx):
        filename = text.split('/')[-1]
        dirname = '/'.join(text.split('/')[:-1])
        return [dirname + '/' + x for x in self.afc.listdir(self.curdir + '/' + dirname) if
                x.startswith(filename)]

    def do_ls(self, p):
        filename = posixpath.join(self.curdir, p)
        if self.curdir.endswith('/'):
            filename = self.curdir + p
        filenames = self.afc.listdir(filename)
        if filenames:
            for filename in filenames:
                print(filename)

    def do_cat(self, p):
        data = self.afc.get_file_contents(posixpath.join(self.curdir, p))
        if data and p.endswith('.plist'):
            pprint(plistlib.loads(data))
        else:
            print(data)

    def do_rm(self, p):
        f = self.afc.stat(posixpath.join(self.curdir, p))
        if f['st_ifmt'] == 'S_IFDIR':
            self.afc.rmdir(posixpath.join(self.curdir, p))
        else:
            self.afc.rm(posixpath.join(self.curdir, p))

    def do_pull(self, user_args):
        args = user_args.split()
        if len(args) != 2:
            local_path = '..'
            remote_path = user_args
        else:
            local_path = args[1]
            remote_path = args[0]

        remote_file_info = self.afc.stat(posixpath.join(self.curdir, remote_path))
        if not remote_file_info:
            logging.error('remote file does not exist')
            return

        out_path = posixpath.join(local_path, remote_path)
        if remote_file_info['st_ifmt'] == 'S_IFDIR':
            if not os.path.isdir(out_path):
                os.makedirs(out_path, MODE_MASK)

            for d in self.afc.listdir(remote_path):
                if d == '.' or d == '..' or d == '':
                    continue
                self.do_pull(remote_path + '/' + d + ' ' + local_path)
        else:
            contents = self.afc.get_file_contents(posixpath.join(self.curdir, remote_path))
            out_dir = os.path.dirname(out_path)
            if not os.path.exists(out_dir):
                os.makedirs(out_dir, MODE_MASK)
            with open(out_path, 'wb') as remote_file_info:
                remote_file_info.write(contents)

    def do_push(self, p):
        src_dst = p.split()
        if len(src_dst) != 2:
            self.logger.error('USAGE: push <src> <dst>')
            return
        src = src_dst[0]
        dst = src_dst[1]

        src = os.path.expanduser(src)
        dst = os.path.expanduser(dst)

        logging.info(f'from {src} to {dst}')
        if os.path.isdir(src):
            self.afc.mkdir(os.path.join(dst))
            for x in os.listdir(src):
                if x.startswith('.'):
                    continue
                path = os.path.join(src, x)
                dst = os.path.join(dst + '/' + path)
                self.do_push(path + ' ' + dst)
        else:
            data = open(src, 'rb').read()
            self.afc.set_file_contents(posixpath.join(self.curdir, dst), data)

    def do_head(self, p):
        print(self.afc.get_file_contents(posixpath.join(self.curdir, p))[:32])

    def do_hexdump(self, filename):
        filename = posixpath.join(self.curdir, filename)
        print(hexdump.hexdump(self.afc.get_file_contents(filename)))

    def do_mkdir(self, p):
        print(self.afc.mkdir(p))

    def do_rmdir(self, p):
        return self.afc.rmdir(p)

    def do_info(self, p):
        for k, v in self.afc.get_device_info().items():
            print(k, '\t:\t', v)

    def do_mv(self, p):
        t = p.split()
        return self.afc.rename(t[0], t[1])

    def do_stat(self, filename):
        filename = posixpath.join(self.curdir, filename)
        pprint(self.afc.stat(filename))
