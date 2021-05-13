from queue import Queue
from dataclasses import dataclass
import errno
import enum
from typing import List

from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import DgbFuncQual


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


def serialize_open_result(end_event) -> str:
    error_code = end_event.args.value[0]
    fd = end_event.args.value[1]
    return f'fd: {fd}' if not error_code else f'errno: {errno.errorcode[error_code]}({error_code})'


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

    def __str__(self):
        return f'''open("{self.path}", {' | '.join(map(lambda f: f.name, self.flags))}), {self.result}'''


@dataclass
class BscOpenat:
    ktraces: List
    dirfd: int
    path: str
    flags: List
    result: str

    def __str__(self):
        return (f'''openat({self.dirfd}, "{self.path}", '''
                f'''{' | '.join(map(lambda f: f.name, self.flags))}), {self.result}''')


class KdebugEventsParser:
    def __init__(self, trace_codes_map):
        self.trace_codes = trace_codes_map
        self.parsed_events = Queue()
        self.on_going_events = {}
        self.handlers = {
            'VFS_LOOKUP': self.handle_vfs_lookup,
            'BSC_open': self.handle_bsc_open,
            'BSC_openat': self.handle_bsc_openat,
            'User_SVC64_Exc_ARM': self.handle_syscall
        }

    def feed(self, event):
        if event.func_qualifier == DgbFuncQual.DBG_FUNC_START.value:
            if event.tid not in self.on_going_events:
                self.on_going_events[event.tid] = [event]
            else:
                self.on_going_events[event.tid].append(event)
        elif event.func_qualifier == DgbFuncQual.DBG_FUNC_NONE.value:
            if event.tid in self.on_going_events:
                self.on_going_events[event.tid].append(event)
            else:
                self.parsed_events.put(self.parse_event_list([event]))
        elif event.func_qualifier == DgbFuncQual.DBG_FUNC_END.value:
            if event.tid not in self.on_going_events:
                # Event end without start.
                return
            if event.eventid != self.on_going_events[event.tid][0].eventid:
                self.on_going_events[event.tid].append(event)
                return
            events = self.on_going_events.pop(event.tid)
            events.append(event)
            self.parsed_events.put(self.parse_event_list(events))
        elif event.func_qualifier == DgbFuncQual.DBG_FUNC_ALL.value:
            self.parsed_events.put(self.parse_event_list([event]))

    def parse_event_list(self, events):
        if events[0].eventid not in self.trace_codes:
            return None
        trace_name = self.trace_codes[events[0].eventid]
        if trace_name not in self.handlers:
            return None
        return self.handlers[trace_name](events)

    def fetch(self):
        return None if self.parsed_events.empty() else self.parsed_events.get()

    @staticmethod
    def handle_vfs_lookup(events):
        path = b''
        vnodeid = 0
        for event in events:
            if event.func_qualifier & DgbFuncQual.DBG_FUNC_START.value:
                vnodeid = event.args.value[0]
                path += event.args.data[8:]
            else:
                path += event.args.data

        return VfsLookup(events, vnodeid, path.decode())

    def handle_bsc_open(self, events):
        vnode = self.handle_vfs_lookup([e for e in events if self.trace_codes.get(e.eventid) == 'VFS_LOOKUP'])
        call_flags = serialize_open_flags(events[0].args.value[1])
        return BscOpen(events, vnode.path, call_flags, serialize_open_result(events[-1]))

    def handle_bsc_openat(self, events):
        vnode = self.handle_vfs_lookup([e for e in events if self.trace_codes.get(e.eventid) == 'VFS_LOOKUP'])
        call_flags = serialize_open_flags(events[0].args.value[2])
        return BscOpenat(events, events[0].args.value[0], vnode.path, call_flags, serialize_open_result(events[-1]))

    def handle_syscall(self, events):
        return self.parse_event_list(events[1:-1]) if len(events) > 2 else None
