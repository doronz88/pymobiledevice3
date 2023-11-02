import asyncio
import platform
import socket
import traceback
from functools import wraps
from typing import Callable

from construct import Int8ul, Int16ul, Int32ul, Int64ul, Select

DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3

_DARWIN_TCP_KEEPALIVE = 0x10
_DARWIN_TCP_KEEPINTVL = 0x101
_DARWIN_TCP_KEEPCNT = 0x102


def plist_access_path(d, path: tuple, type_=None, required=False):
    for component in path:
        d = d.get(component)
        if d is None:
            break

    if type_ == bool and isinstance(d, str):
        if d.lower() not in ('true', 'false'):
            raise ValueError()
        d = 'true' == d.lower()
    elif type_ is not None and not isinstance(d, type_):
        # wrong type
        d = None

    if d is None and required:
        raise KeyError(f'path: {path} doesn\'t exist in given plist object')

    return d


def bytes_to_uint(b: bytes):
    return Select(u64=Int64ul, u32=Int32ul, u16=Int16ul, u8=Int8ul).parse(b)


def try_decode(s: bytes):
    try:
        return s.decode('utf8')
    except UnicodeDecodeError:
        return s


def asyncio_print_traceback(f: Callable):
    @wraps(f)
    async def wrapper(*args, **kwargs):
        try:
            return await f(*args, **kwargs)
        except Exception as e:  # noqa: E72
            if not isinstance(e, asyncio.CancelledError):
                traceback.print_exc()
            raise

    return wrapper


def set_keepalive(sock: socket.socket, after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
                  interval_sec: int = DEFAULT_INTERVAL_SEC, max_fails: int = DEFAULT_MAX_FAILS) -> None:
    """
    set keep-alive parameters on a given socket

    :param sock: socket to operate on
    :param after_idle_sec: idle time used when SO_KEEPALIVE is enabled
    :param interval_sec: interval between keepalives
    :param max_fails: number of keepalives before close

    """
    plat = platform.system()
    if plat == 'Linux':
        return _set_keepalive_linux(sock, after_idle_sec, interval_sec, max_fails)
    if plat == 'Darwin':
        return _set_keepalive_darwin(sock, after_idle_sec, interval_sec, max_fails)
    if plat == 'Windows':
        return _set_keepalive_win(sock, after_idle_sec, interval_sec)
    raise RuntimeError(f'Unsupported platform {plat}')


def _set_keepalive_linux(sock: socket.socket, after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
                         interval_sec: int = DEFAULT_INTERVAL_SEC, max_fails: int = DEFAULT_MAX_FAILS) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)


def _set_keepalive_darwin(sock: socket.socket, after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
                          interval_sec: int = DEFAULT_INTERVAL_SEC, max_fails: int = DEFAULT_MAX_FAILS) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPALIVE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPCNT, max_fails)


def _set_keepalive_win(sock: socket.socket, after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
                       interval_sec: int = DEFAULT_INTERVAL_SEC) -> None:
    sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, after_idle_sec * 1000, interval_sec * 1000))
