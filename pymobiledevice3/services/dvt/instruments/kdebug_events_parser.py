from dataclasses import dataclass
import errno
import enum
from signal import Signals
from typing import List
from functools import partial

from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import DgbFuncQual, ProcessData

IOC_REQUEST_PARAMS = {
    0x20000000: 'IOC_VOID',
    0x40000000: 'IOC_OUT',
    0x80000000: 'IOC_IN',
    0xc0000000: 'IOC_IN | IOC_OUT',
    0xe0000000: 'IOC_DIRMASK'
}


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


class SocketMsgFlags(enum.Enum):
    MSG_OOB = 0x1
    MSG_PEEK = 0x2
    MSG_DONTROUTE = 0x4
    MSG_EOR = 0x8
    MSG_TRUNC = 0x10
    MSG_CTRUNC = 0x20
    MSG_WAITALL = 0x40
    MSG_DONTWAIT = 0x80
    MSG_EOF = 0x100
    MSG_WAITSTREAM = 0x200
    MSG_FLUSH = 0x400
    MSG_HOLD = 0x800
    MSG_SEND = 0x1000
    MSG_HAVEMORE = 0x2000
    MSG_RCVMORE = 0x4000
    MSG_COMPAT = 0x8000
    MSG_NEEDSA = 0x10000
    MSG_NBIO = 0x20000
    MSG_SKIPCFIL = 0x40000
    MSG_USEUPCALL = 0x80000000


class BscAccessFlags(enum.Enum):
    F_OK = 0x0
    X_OK = 0x1
    W_OK = 0x2
    R_OK = 0x4


class BscChangeableFlags(enum.Enum):
    UF_NODUMP = 0x1
    UF_IMMUTABLE = 0x2
    UF_APPEND = 0x4
    UF_OPAQUE = 0x8
    UF_HIDDEN = 0x8000
    SF_ARCHIVED = 0x10000
    SF_IMMUTABLE = 0x20000
    SF_APPEND = 0x40000


class SigprocmaskFlags(enum.Enum):
    SIG_BLOCK = 1
    SIG_UNBLOCK = 2
    SIG_SETMASK = 3


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
    return success if not error_code else err


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
        return 'thread_create()'


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
class BscGetpid:
    ktraces: List
    pid: int

    def __str__(self):
        return f'getpid(), pid: {self.pid}'


@dataclass
class BscSetuid:
    ktraces: List
    uid: int
    result: str

    def __str__(self):
        rep = f'setuid({self.uid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetuid:
    ktraces: List
    uid: int

    def __str__(self):
        return f'getuid(), uid: {self.uid}'


@dataclass
class BscGeteuid:
    ktraces: List
    uid: int

    def __str__(self):
        return f'geteuid(), uid: {self.uid}'


@dataclass
class BscRecvmsg:
    ktraces: List
    socket: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'recvmsg{no_cancel}({self.socket}), {self.result}'


@dataclass
class BscSendmsg:
    ktraces: List
    socket: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'sendmsg{no_cancel}({self.socket}), {self.result}'


@dataclass
class BscRecvfrom:
    ktraces: List
    socket: int
    buffer: int
    length: int
    flags: List
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return (f'''recvfrom{no_cancel}({self.socket}, {hex(self.buffer)}, {self.length}, '''
                f'''{' | '.join(map(lambda f: f.name, self.flags)) if self.flags else '0'}), {self.result}''')


@dataclass
class BscAccept:
    ktraces: List
    socket: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'accept{no_cancel}({self.socket}), {self.result}'


@dataclass
class BscGetpeername:
    ktraces: List
    socket: int
    address: int
    address_len: int
    result: str

    def __str__(self):
        rep = f'getpeername({self.socket}, {hex(self.address)}, {hex(self.address_len)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetsockname:
    ktraces: List
    socket: int
    address: int
    address_len: int
    result: str

    def __str__(self):
        rep = f'getsockname({self.socket}, {hex(self.address)}, {hex(self.address_len)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAccess:
    ktraces: List
    path: str
    amode: List
    result: str

    def __str__(self):
        rep = f'''access("{self.path}", {' | '.join(map(lambda f: f.name, self.amode))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChflags:
    ktraces: List
    path: str
    flags: List
    result: str

    def __str__(self):
        rep = f'''chflags("{self.path}", {' | '.join(map(lambda f: f.name, self.flags))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFchflags:
    ktraces: List
    fd: int
    flags: List
    result: str

    def __str__(self):
        rep = f'''fchflags({self.fd}, {' | '.join(map(lambda f: f.name, self.flags))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSync:
    ktraces: List

    def __str__(self):
        return 'sync()'


@dataclass
class BscKill:
    ktraces: List
    pid: int
    sig: int
    result: str

    def __str__(self):
        rep = f'kill({self.pid}, {self.sig})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetppid:
    ktraces: List
    pid: int

    def __str__(self):
        return f'getppid(), pid: {self.pid}'


@dataclass
class BscSysDup:
    ktraces: List
    fildes: int
    result: str

    def __str__(self):
        return f'dup({self.fildes}), {self.result}'


@dataclass
class BscPipe:
    ktraces: List
    result: str

    def __str__(self):
        return f'pipe(), {self.result}'


@dataclass
class BscGetegid:
    ktraces: List
    gid: int

    def __str__(self):
        return f'getegid(), gid: {self.gid}'


@dataclass
class BscSigaction:
    ktraces: List
    sig: Signals
    act: int
    oact: int
    result: str

    def __str__(self):
        rep = f'sigaction({self.sig.name}, {hex(self.act)}, {hex(self.oact)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetgid:
    ktraces: List
    gid: int

    def __str__(self):
        return f'getgid(), gid: {self.gid}'


@dataclass
class BscSigprocmap:
    ktraces: List
    how: SigprocmaskFlags
    set: int
    oset: int
    result: str

    def __str__(self):
        rep = f'sigprocmask({self.how.name}, {hex(self.set)}, {hex(self.oset)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetlogin:
    ktraces: List
    address: int

    def __str__(self):
        return f'getlogin(), address: {hex(self.address)}'


@dataclass
class BscSetlogin:
    ktraces: List
    address: int
    result: str

    def __str__(self):
        rep = f'setlogin({hex(self.address)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAcct:
    ktraces: List
    file: str
    result: str

    def __str__(self):
        rep = f'acct("{self.file}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSigpending:
    ktraces: List
    set: int
    result: str

    def __str__(self):
        rep = f'sigpending({hex(self.set)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSigaltstack:
    ktraces: List
    ss_address: int
    oss_address: int
    result: str

    def __str__(self):
        rep = f'sigaltstack({hex(self.ss_address)}, {hex(self.oss_address)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscIoctl:
    ktraces: List
    fildes: int
    request: int
    arg: int
    result: str

    def __str__(self):
        params = IOC_REQUEST_PARAMS[self.request & 0xf0000000]
        group = chr((self.request >> 8) & 0xff)
        number = self.request & 0xff
        length = (self.request >> 16) & 0x1fff
        ioc = f'''_IOC({params}, '{group}', {number}, {length})'''
        rep = f'ioctl({self.fildes}, {hex(self.request)} /* {ioc} */, {hex(self.arg)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscReboot:
    ktraces: List
    howto: int
    result: str

    def __str__(self):
        rep = f'reboot({self.howto})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscObsKillpg:
    ktraces: List
    pgrp: int
    sig: int
    result: str

    def __str__(self):
        rep = f'killpg({self.pgrp}, {self.sig})'
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
            'BSC_getpid': self.handle_bsc_getpid,
            'BSC_setuid': self.handle_bsc_setuid,
            'BSC_getuid': self.handle_bsc_getuid,
            'BSC_geteuid': self.handle_bsc_geteuid,
            'BSC_recvmsg': self.handle_bsc_recvmsg,
            'BSC_sendmsg': self.handle_bsc_sendmsg,
            'BSC_recvfrom': self.handle_bsc_recvfrom,
            'BSC_accept': self.handle_bsc_accept,
            'BSC_getpeername': self.handle_bsc_getpeername,
            'BSC_getsockname': self.handle_bsc_getsockname,
            'BSC_access': self.handle_bsc_access,
            'BSC_chflags': self.handle_bsc_chflags,
            'BSC_fchflags': self.handle_bsc_fchflags,
            'BSC_sync': self.handle_bsc_sync,
            'BSC_kill': self.handle_bsc_kill,
            'BSC_getppid': self.handle_bsc_getppid,
            'BSC_sys_dup': self.handle_bsc_sys_dup,
            'BSC_pipe': self.handle_bsc_pipe,
            'BSC_getegid': self.handle_bsc_getegid,
            'BSC_sigaction': self.handle_bsc_sigaction,
            'BSC_getgid': self.handle_bsc_getgid,
            'BSC_sigprocmask': self.handle_bsc_sigprocmask,
            'BSC_getlogin': self.handle_bsc_getlogin,
            'BSC_setlogin': self.handle_bsc_setlogin,
            'BSC_acct': self.handle_bsc_acct,
            'BSC_sigpending': self.handle_bsc_sigpending,
            'BSC_sigaltstack': self.handle_bsc_sigaltstack,
            'BSC_ioctl': self.handle_bsc_ioctl,
            'BSC_reboot': self.handle_bsc_reboot,
            'BSC_pread': self.handle_bsc_pread,
            'BSC_pwrite': self.handle_bsc_pwrite,
            'BSC_sys_fstat64': self.handle_bsc_sys_fstat64,
            'BSC_lstat64': self.handle_bsc_lstat64,
            'BSC_bsdthread_create': self.handle_bsc_bsdthread_create,
            'BSC_read_nocancel': partial(self.handle_bsc_read, no_cancel=True),
            'BSC_write_nocancel': partial(self.handle_bsc_write, no_cancel=True),
            'BSC_open_nocancel': partial(self.handle_bsc_open, no_cancel=True),
            'BSC_sys_close_nocancel': partial(self.handle_bsc_sys_close, no_cancel=True),
            'BSC_recvmsg_nocancel': partial(self.handle_bsc_recvmsg, no_cancel=True),
            'BSC_sendmsg_nocancel': partial(self.handle_bsc_sendmsg, no_cancel=True),
            'BSC_recvfrom_nocancel': partial(self.handle_bsc_recvfrom, no_cancel=True),
            'BSC_accept_nocancel': partial(self.handle_bsc_accept, no_cancel=True),
            'BSC_obs_killpg': self.handle_obs_killpg,
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

    def handle_bsc_getpid(self, events):
        return BscGetpid(events, events[-1].values[1])

    def handle_bsc_setuid(self, events):
        return BscSetuid(events, events[0].values[0], serialize_result(events[-1]))

    def handle_bsc_getuid(self, events):
        return BscGetuid(events, events[-1].values[1])

    def handle_bsc_geteuid(self, events):
        return BscGeteuid(events, events[-1].values[1])

    def handle_bsc_recvmsg(self, events, no_cancel=False):
        return BscRecvmsg(events, events[0].values[0], serialize_result(events[-1], 'count'), no_cancel)

    def handle_bsc_sendmsg(self, events, no_cancel=False):
        return BscSendmsg(events, events[0].values[0], serialize_result(events[-1], 'count'), no_cancel)

    def handle_bsc_recvfrom(self, events, no_cancel=False):
        args = events[0].values
        flags = [flag for flag in SocketMsgFlags if flag.value & args[3]]
        return BscRecvfrom(events, args[0], args[1], args[2], flags, serialize_result(events[-1], 'count'), no_cancel)

    def handle_bsc_accept(self, events, no_cancel=False):
        return BscAccept(events, events[0].values[0], serialize_result(events[-1], 'fd'), no_cancel)

    def handle_bsc_getpeername(self, events):
        args = events[0].values
        return BscGetpeername(events, args[0], args[1], args[2], serialize_result(events[-1]))

    def handle_bsc_getsockname(self, events):
        args = events[0].values
        return BscGetsockname(events, args[0], args[1], args[2], serialize_result(events[-1]))

    def handle_bsc_access(self, events):
        vnode = self.parse_vnode(events)
        amode = [flag for flag in BscAccessFlags if flag.value & events[0].values[1]]
        if not amode:
            amode = [BscAccessFlags.F_OK]
        return BscAccess(events, vnode.path, amode, serialize_result(events[-1]))

    def handle_bsc_chflags(self, events):
        vnode = self.parse_vnode(events)
        flags = [flag for flag in BscChangeableFlags if flag.value & events[0].values[1]]
        return BscChflags(events, vnode.path, flags, serialize_result(events[-1]))

    def handle_bsc_fchflags(self, events):
        flags = [flag for flag in BscChangeableFlags if flag.value & events[0].values[1]]
        return BscFchflags(events, events[0].values[0], flags, serialize_result(events[-1]))

    def handle_bsc_sync(self, events):
        return BscSync(events)

    def handle_bsc_kill(self, events):
        return BscKill(events, events[0].values[0], events[0].values[1], serialize_result(events[-1]))

    def handle_bsc_getppid(self, events):
        return BscGetppid(events, events[-1].values[1])

    def handle_bsc_sys_dup(self, events):
        return BscSysDup(events, events[0].values[0], serialize_result(events[-1], 'fd'))

    def handle_bsc_pipe(self, events):
        error_code = events[-1].values[0]
        if error_code:
            if error_code in errno.errorcode:
                result = f'errno: {errno.errorcode[error_code]}({error_code})'
            else:
                result = f'errno: {error_code}'
        else:
            result = f'read_fd: {events[-1].values[1]}, write_fd: {events[-1].values[2]}'
        return BscPipe(events, result)

    def handle_bsc_getegid(self, events):
        return BscGetegid(events, events[-1].values[1])

    def handle_bsc_sigaction(self, events):
        args = events[0].values
        return BscSigaction(events, Signals(args[0]), args[1], args[2], serialize_result(events[-1]))

    def handle_bsc_getgid(self, events):
        return BscGetgid(events, events[-1].values[1])

    def handle_bsc_sigprocmask(self, events):
        args = events[0].values
        return BscSigprocmap(events, SigprocmaskFlags(args[0]), args[1], args[2], serialize_result(events[-1]))

    def handle_bsc_getlogin(self, events):
        return BscGetlogin(events, events[0].values[0])

    def handle_bsc_setlogin(self, events):
        return BscSetlogin(events, events[0].values[0], serialize_result(events[-1]))

    def handle_bsc_acct(self, events):
        return BscAcct(events, self.parse_vnode(events).path, serialize_result(events[-1]))

    def handle_bsc_sigpending(self, events):
        return BscSigpending(events, events[0].values[0], serialize_result(events[-1]))

    def handle_bsc_sigaltstack(self, events):
        return BscSigaltstack(events, events[0].values[0], events[0].values[1], serialize_result(events[-1]))

    def handle_bsc_ioctl(self, events):
        args = events[0].values
        return BscIoctl(events, args[0], args[1], args[2], serialize_result(events[-1]))

    def handle_bsc_reboot(self, events):
        return BscReboot(events, events[0].values[0], serialize_result(events[-1]))

    def handle_obs_killpg(self, events):
        return BscObsKillpg(events, events[0].values[0], events[0].values[1], serialize_result(events[-1]))

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
