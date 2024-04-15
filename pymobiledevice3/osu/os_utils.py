import inspect
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from pymobiledevice3.exceptions import FeatureNotSupportedError, OSNotSupportedError

DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3


class OsUtils:
    _instance = None
    _os_name = None

    @classmethod
    def create(cls) -> 'OsUtils':
        if cls._instance is None:
            cls._os_name = sys.platform
            if cls._os_name == 'win32':
                from pymobiledevice3.osu.win_util import Win32
                cls._instance = Win32()
            elif cls._os_name == 'darwin':
                from pymobiledevice3.osu.posix_util import Darwin
                cls._instance = Darwin()
            elif cls._os_name == 'linux':
                from pymobiledevice3.osu.posix_util import Linux
                cls._instance = Linux()
            elif cls._os_name == 'cygwin':
                from pymobiledevice3.osu.posix_util import Cygwin
                cls._instance = Cygwin()
            else:
                raise OSNotSupportedError(cls._os_name)
        return cls._instance

    @property
    def is_admin(self) -> bool:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    @property
    def usbmux_address(self) -> Tuple[str, int]:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    @property
    def bonjour_timeout(self) -> int:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    @property
    def loopback_header(self) -> bytes:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    @property
    def access_denied_error(self) -> str:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    @property
    def pair_record_path(self) -> Path:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    def get_ipv6_ips(self) -> List[str]:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    def set_keepalive(self, sock: socket.socket, after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
                      interval_sec: int = DEFAULT_INTERVAL_SEC, max_fails: int = DEFAULT_MAX_FAILS) -> None:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    def parse_timestamp(self, time_stamp) -> datetime:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    def chown_to_non_sudo_if_needed(self, path: Path) -> None:
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)

    def wait_return(self):
        raise FeatureNotSupportedError(self._os_name, inspect.currentframe().f_code.co_name)


def get_os_utils() -> OsUtils:
    return OsUtils.create()
