from dataclasses import dataclass
import errno
import enum
from typing import List
from functools import partial

from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import DgbFuncQual, ProcessData


class BscOpenFlags(enum.Enum):
    O_RDONLY = 0x0000
    O_WRONLY = 0x0001
    O_RDWR = 0x0002
    O_ACCMODE = 0x0003
    O_NONBLOCK = 0x0004
    O_APPEND = 0x0008
    O_SHLOCK = 0x0010
    O_EXLOCK = 0x0020
    O_ASYNC = 0x0040
    O_NOFOLLOW = 0x0100
    O_CREAT = 0x0200
    O_TRUNC = 0x0400
    O_EXCL = 0x0800
    O_EVTONLY = 0x8000
    O_SYMLINK = 0x200000
    O_CLOEXEC = 0x1000000


S_IFMT = 0o170000


class StatFlags(enum.Flag):
    S_IXOTH = 0o1
    S_IWOTH = 0o2
    S_IROTH = 0o4
    S_IXGRP = 0o10
    S_IWGRP = 0o20
    S_IRGRP = 0o40
    S_IXUSR = 0o100
    S_IWUSR = 0o200
    S_IRUSR = 0o400
    S_ISTXT = 0o1000
    S_ISGID = 0o2000
    S_ISUID = 0o4000
    S_IFIFO = 0o10000
    S_IFCHR = 0o20000
    S_IFDIR = 0o40000
    S_IFBLK = 0o60000
    S_IFREG = 0o100000
    S_IFLNK = 0o120000
    S_IFSOCK = 0o140000


def serialize_open_flags(flags: int) -> List[BscOpenFlags]:
    call_flags = []
    for flag in (BscOpenFlags.O_RDWR, BscOpenFlags.O_WRONLY):
        if flags & flag.value:
            call_flags.append(flag)
            break
    else:  # No break.
        call_flags.append(BscOpenFlags.O_RDONLY)

    for flag in (
            BscOpenFlags.O_CREAT, BscOpenFlags.O_APPEND, BscOpenFlags.O_TRUNC, BscOpenFlags.O_EXCL,
            BscOpenFlags.O_NONBLOCK, BscOpenFlags.O_SHLOCK, BscOpenFlags.O_EXLOCK, BscOpenFlags.O_NOFOLLOW,
            BscOpenFlags.O_SYMLINK, BscOpenFlags.O_EVTONLY, BscOpenFlags.O_CLOEXEC):
        if flags & flag.value:
            call_flags.append(flag)
    return call_flags


def serialize_stat_flags(flags: int) -> List[StatFlags]:
    stat_flags = []
    for flag in list(StatFlags):
        if flag.value & S_IFMT:
            if flags & S_IFMT == flag.value:
                stat_flags.append(flag)
        elif flag.value & flags:
            stat_flags.append(flag)
    return stat_flags


def serialize_result(end_event, success_name='') -> str:
    error_code = end_event.values[0]
    res = end_event.values[1]
    if error_code in errno.errorcode:
        err = f'errno: {errno.errorcode[error_code]}({error_code})'
    else:
        err = f'errno: {error_code}'
    success = f'{success_name}: {res}' if success_name else ''
    return success if not error_code else f'errno: {err}'


@dataclass
class VfsLookup:
    ktraces: List
    vnode_id: int
    path: str

    def __str__(self):
        return f'lookup("{self.path}"), vnode id: {self.vnode_id}'


@dataclass
class BscOpen:
    ktraces: List
    path: str
    flags: List
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'''open{no_cancel}("{self.path}", {' | '.join(map(lambda f: f.name, self.flags))}), {self.result}'''


@dataclass
class BscOpenat:
    ktraces: List
    dirfd: int
    path: str
    flags: List
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return (f'''openat{no_cancel}({self.dirfd}, "{self.path}", '''
                f'''{' | '.join(map(lambda f: f.name, self.flags))}), {self.result}''')


@dataclass
class BscRead:
    ktraces: List
    fd: int
    address: int
    size: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'read{no_cancel}({self.fd}, {hex(self.address)}, {self.size}), {self.result}'


@dataclass
class BscWrite:
    ktraces: List
    fd: int
    address: int
    size: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'write{no_cancel}({self.fd}, {hex(self.address)}, {self.size}), {self.result}'


@dataclass
class BscPread:
    ktraces: List
    fd: int
    address: int
    size: int
    offset: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'pread{no_cancel}({self.fd}, {hex(self.address)}, {self.size}, {hex(self.offset)}), {self.result}'


@dataclass
class BscPwrite:
    ktraces: List
    fd: int
    address: int
    size: int
    offset: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'pwrite{no_cancel}({self.fd}, {hex(self.address)}, {self.size}, {hex(self.offset)}), {self.result}'


@dataclass
class BscSysFstat64:
    ktraces: List
    fd: int
    result: str

    def __str__(self):
        rep = f'fstat64({self.fd})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscLstat64:
    ktraces: List
    path: str
    result: str

    def __str__(self):
        rep = f'lstat64("{self.path}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscBsdthreadCreate:
    ktraces: List
    pid: int

    def __str__(self):
        return f'thread_create()'


@dataclass
class BscSysClose:
    ktraces: List
    fd: str
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'close{no_cancel}({self.fd})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscLink:
    ktraces: List
    oldpath: str
    newpath: str
    result: str

    def __str__(self):
        rep = f'link("{self.oldpath}", "{self.newpath}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscUnlink:
    ktraces: List
    pathname: str
    result: str

    def __str__(self):
        rep = f'unlink("{self.pathname}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChdir:
    ktraces: List
    path: str
    result: str

    def __str__(self):
        rep = f'chdir("{self.path}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFchdir:
    ktraces: List
    fd: int
    result: str

    def __str__(self):
        rep = f'fchdir({self.fd})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMknod:
    ktraces: List
    pathname: str
    mode: int
    dev: int
    result: str

    def __str__(self):
        rep = f'mknod("{self.pathname}", {self.mode}, {self.dev})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChmod:
    ktraces: List
    pathname: str
    mode: List
    result: str

    def __str__(self):
        rep = f'''chmod("{self.pathname}", {' | '.join(map(lambda f: f.name, self.mode))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChown:
    ktraces: List
    pathname: str
    owner: int
    group: int
    result: str

    def __str__(self):
        rep = f'''chown("{self.pathname}", {self.owner}, {self.group})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class MachStackHandoff:
    ktraces: List

    def __str__(self):
        return 'stack_handoff()'


@dataclass
class TraceDataNewthread:
    ktraces: List
    tid: int
    pid: int
    is_exec_copy: int
    uniqueid: int

    def __str__(self):
        return f'New thread {self.tid} of parent: {self.pid}'


@dataclass
class TraceStringNewthread:
    ktraces: List
    name: List

    def __str__(self):
        return f'New thread of parent: {self.name}'


@dataclass
class TraceDataExec:
    ktraces: List
    pid: int
    fsid: int
    fileid: int

    def __str__(self):
        return f'New process pid: {self.pid}'


@dataclass
class TraceStringExec:
    ktraces: List
    name: List

    def __str__(self):
        return f'New process name: {self.name}'


class KdebugEventsParser:
    def __init__(self, event_callback, trace_codes_map, thread_map):
        self.event_callback = event_callback
        self.trace_codes = trace_codes_map
        self.on_going_events = {}
        self.thread_map = thread_map
        self.trace_handlers = {
            'TRACE_DATA_NEWTHREAD': self.handle_trace_data_newthread,
            'TRACE_DATA_EXEC': self.handle_trace_data_exec,
            'TRACE_STRING_NEWTHREAD': self.handle_trace_string_newthread,
            'TRACE_STRING_EXEC': self.handle_trace_string_exec,
        }
        self.last_data_newthread = None
        self.last_data_exec = None
        self.handlers = {
            'User_SVC64_Exc_ARM': self.handle_syscall,
            'VFS_LOOKUP': self.handle_vfs_lookup,
            'BSC_read': self.handle_bsc_read,
            'BSC_write': self.handle_bsc_write,
            'BSC_open': self.handle_bsc_open,
            'BSC_sys_close': self.handle_bsc_sys_close,
            'BSC_link': self.handle_bsc_link,
            'BSC_unlink': self.handle_bsc_unlink,
            'BSC_chdir': self.handle_bsc_chdir,
            'BSC_fchdir': self.handle_bsc_fchdir,
            'BSC_mknod': self.handle_bsc_mknod,
            'BSC_chmod': self.handle_bsc_chmod,
            'BSC_chown': self.handle_bsc_chown,
            'BSC_pread': self.handle_bsc_pread,
            'BSC_pwrite': self.handle_bsc_pwrite,
            'BSC_sys_fstat64': self.handle_bsc_sys_fstat64,
            'BSC_lstat64': self.handle_bsc_lstat64,
            'BSC_bsdthread_create': self.handle_bsc_bsdthread_create,
            'BSC_read_nocancel': partial(self.handle_bsc_read, no_cancel=True),
            'BSC_write_nocancel': partial(self.handle_bsc_write, no_cancel=True),
            'BSC_open_nocancel': partial(self.handle_bsc_open, no_cancel=True),
            'BSC_sys_close_nocancel': partial(self.handle_bsc_sys_close, no_cancel=True),
            'BSC_pread_nocancel': partial(self.handle_bsc_pread, no_cancel=True),
            'BSC_pwrite_nocancel': partial(self.handle_bsc_pwrite, no_cancel=True),
            'BSC_openat': self.handle_bsc_openat,
            'BSC_openat_nocancel': partial(self.handle_bsc_openat, no_cancel=True),
        }

    def feed(self, event):
        if event.eventid in self.trace_codes:
            trace_name = self.trace_codes[event.eventid]
            if trace_name in self.trace_handlers:
                self.trace_handlers[trace_name]([event])
                return

        if event.func_qualifier == DgbFuncQual.DBG_FUNC_START.value:
            if event.tid not in self.on_going_events:
                self.on_going_events[event.tid] = [event]
            else:
                self.on_going_events[event.tid].append(event)
        elif event.func_qualifier == DgbFuncQual.DBG_FUNC_END.value:
            if event.tid not in self.on_going_events:
                # Event end without start.
                return
            if event.eventid != self.on_going_events[event.tid][0].eventid:
                self.on_going_events[event.tid].append(event)
                return
            events = self.on_going_events.pop(event.tid)
            events.append(event)
            self.publish(self.parse_event_list(events))
        else:
            if event.tid in self.on_going_events:
                self.on_going_events[event.tid].append(event)
            else:
                self.publish(self.parse_event_list([event]))

    def parse_event_list(self, events):
        if events[0].eventid not in self.trace_codes:
            return None
        trace_name = self.trace_codes[events[0].eventid]
        if trace_name not in self.handlers:
            return None
        return self.handlers[trace_name](events)

    @staticmethod
    def handle_vfs_lookup(events):
        path = b''
        vnodeid = 0
        lookup_events = []
        for event in events:
            lookup_events.append(event)
            if event.func_qualifier & DgbFuncQual.DBG_FUNC_START.value:
                vnodeid = event.values[0]
                path += event.data[8:]
            else:
                path += event.data

            if event.func_qualifier & DgbFuncQual.DBG_FUNC_END.value:
                break

        return VfsLookup(lookup_events, vnodeid, path.replace(b'\x00', b'').decode())

    def handle_bsc_open(self, events, no_cancel=False):
        vnode = self.parse_vnode(events)
        call_flags = serialize_open_flags(events[0].values[1])
        return BscOpen(events, vnode.path, call_flags, serialize_result(events[-1], 'fd'), no_cancel)

    def handle_bsc_openat(self, events, no_cancel=False):
        vnode = self.parse_vnode(events)
        call_flags = serialize_open_flags(events[0].values[2])
        return BscOpenat(events, events[0].values[0], vnode.path, call_flags, serialize_result(events[-1], 'fd'),
                         no_cancel)

    def handle_syscall(self, events):
        return self.parse_event_list(events[1:-1]) if len(events) > 2 else None

    def handle_mach_stkhandoff(self, events):
        return MachStackHandoff(events)

    def handle_bsc_read(self, events, no_cancel=False):
        result = serialize_result(events[-1], 'count')
        args = events[0].values
        return BscRead(events, args[0], args[1], args[2], result, no_cancel)

    def handle_bsc_write(self, events, no_cancel=False):
        result = serialize_result(events[-1], 'count')
        args = events[0].values
        return BscWrite(events, args[0], args[1], args[2], result, no_cancel)

    def handle_bsc_link(self, events):
        old_vnode = self.parse_vnode(events)
        new_vnode = self.parse_vnode([e for e in events if e not in old_vnode.ktraces])
        return BscLink(events, old_vnode.path, new_vnode.path, serialize_result(events[-1]))

    def handle_bsc_unlink(self, events):
        vnode = self.parse_vnode(events)
        return BscUnlink(events, vnode.path, serialize_result(events[-1]))

    def handle_bsc_chdir(self, events):
        vnode = self.parse_vnode(events)
        return BscChdir(events, vnode.path, serialize_result(events[-1]))

    def handle_bsc_fchdir(self, events):
        return BscFchdir(events, events[0].values[0], serialize_result(events[-1]))

    def handle_bsc_mknod(self, events):
        vnode = self.parse_vnode(events)
        return BscMknod(events, vnode.path, events[0].values[1], events[0].values[2], serialize_result(events[-1]))

    def handle_bsc_chmod(self, events):
        vnode = self.parse_vnode(events)
        return BscChmod(events, vnode.path, serialize_stat_flags(events[0].values[1]), serialize_result(events[-1]))

    def handle_bsc_chown(self, events):
        vnode = self.parse_vnode(events)
        return BscChown(events, vnode.path, events[0].values[1], events[0].values[2], serialize_result(events[-1]))

    def handle_bsc_pread(self, events, no_cancel=False):
        result = serialize_result(events[-1], 'count')
        args = events[0].values
        return BscPread(events, args[0], args[1], args[2], args[3], result, no_cancel)

    def handle_bsc_pwrite(self, events, no_cancel=False):
        result = serialize_result(events[-1], 'count')
        args = events[0].values
        return BscPwrite(events, args[0], args[1], args[2], args[3], result, no_cancel)

    def handle_bsc_sys_fstat64(self, events):
        return BscSysFstat64(events, events[0].values[0], serialize_result(events[-1]))

    def handle_bsc_lstat64(self, events):
        return BscLstat64(events, self.parse_vnode(events).path, serialize_result(events[-1]))

    def handle_bsc_bsdthread_create(self, events):
        return BscBsdthreadCreate(events, events[-1].values[3])

    def handle_bsc_sys_close(self, events, no_cancel=False):
        return BscSysClose(events, events[0].values[0], serialize_result(events[-1]), no_cancel)

    def parse_vnode(self, events):
        return self.handle_vfs_lookup([e for e in events if self.trace_codes.get(e.eventid) == 'VFS_LOOKUP'])

    def handle_trace_data_newthread(self, events):
        result = events[0].values
        self.last_data_newthread = TraceDataNewthread(events, result[0], result[1], result[2], result[3])
        return self.last_data_newthread

    def handle_trace_string_newthread(self, events):
        event = TraceStringNewthread(events, events[0].data.replace(b'\x00', b'').decode())
        self.thread_map[self.last_data_newthread.tid] = ProcessData(self.last_data_newthread.pid, event.name)
        return event

    def handle_trace_data_exec(self, events):
        result = events[0].values
        self.last_data_exec = TraceDataExec(events, result[0], result[1], result[2])
        return self.last_data_exec

    def handle_trace_string_exec(self, events):
        event = TraceStringExec(events, events[0].data.replace(b'\x00', b'').decode())
        self.thread_map[events[0].tid] = ProcessData(self.last_data_exec.pid, event.name)
        return event

    def publish(self, event):
        if event is not None:
            self.event_callback(event)
