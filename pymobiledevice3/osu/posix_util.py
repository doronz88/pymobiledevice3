import datetime
import os
import signal
import socket
import struct
from pathlib import Path

from ifaddr import get_adapters

from pymobiledevice3.osu.os_utils import DEFAULT_AFTER_IDLE_SEC, DEFAULT_INTERVAL_SEC, DEFAULT_MAX_FAILS, OsUtils
from pymobiledevice3.usbmux import MuxConnection

_DARWIN_TCP_KEEPALIVE = 0x10
_DARWIN_TCP_KEEPINTVL = 0x101
_DARWIN_TCP_KEEPCNT = 0x102


class Posix(OsUtils):
    @property
    def is_admin(self) -> bool:
        return os.geteuid() == 0

    @property
    def usbmux_address(self) -> tuple[str, int]:
        return MuxConnection.USBMUXD_PIPE, socket.AF_UNIX

    @property
    def bonjour_timeout(self) -> int:
        return 1

    @property
    def access_denied_error(self) -> str:
        return 'This command requires root privileges. Consider retrying with "sudo".'

    def get_ipv6_ips(self) -> list[str]:
        return [f'{adapter.ips[0].ip[0]}%{adapter.nice_name}' for adapter in get_adapters() if
                adapter.ips[0].is_IPv6 and not adapter.nice_name.startswith('tun')]

    def chown_to_non_sudo_if_needed(self, path: Path) -> None:
        if os.getenv('SUDO_UID') is None:
            return
        os.chown(path, int(os.getenv('SUDO_UID')), int(os.getenv('SUDO_GID')))

    def parse_timestamp(self, time_stamp) -> datetime:
        return datetime.datetime.fromtimestamp(time_stamp)

    def wait_return(self):
        print("Press Ctrl+C to send a SIGINT or use 'kill' command to send a SIGTERM")
        signal.sigwait([signal.SIGINT, signal.SIGTERM])


class Darwin(Posix):
    @property
    def pair_record_path(self) -> Path:
        return Path('/var/db/lockdown/')

    @property
    def loopback_header(self) -> bytes:
        return struct.pack('>I', socket.AF_INET6)

    def set_keepalive(self, sock: socket.socket, after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
                      interval_sec: int = DEFAULT_INTERVAL_SEC, max_fails: int = DEFAULT_MAX_FAILS) -> None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPALIVE, after_idle_sec)
        sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPINTVL, interval_sec)
        sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPCNT, max_fails)


class Linux(Posix):
    @property
    def pair_record_path(self) -> Path:
        return Path('/var/lib/lockdown/')

    @property
    def loopback_header(self) -> bytes:
        return b'\x00\x00\x86\xdd'

    def set_keepalive(self, sock: socket.socket, after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
                      interval_sec: int = DEFAULT_INTERVAL_SEC, max_fails: int = DEFAULT_MAX_FAILS) -> None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)

    def get_homedir(self) -> Path:
        return Path('~' + os.environ.get('SUDO_USER', '')).expanduser()


class Cygwin(Posix):
    @property
    def usbmux_address(self) -> tuple[str, int]:
        return MuxConnection.ITUNES_HOST, socket.AF_INET
