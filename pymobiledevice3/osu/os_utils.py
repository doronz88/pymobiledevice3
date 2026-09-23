import inspect
import socket
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from pymobiledevice3.exceptions import FeatureNotSupportedError, OSNotSupportedError


@dataclass
class UsbmuxDaemon:
    """Which usbmux daemon is serving this host, and whether it finds devices over Wi-Fi.

    ``discovers_over_wifi`` is ``None`` when the implementation could not be identified -- a
    listed device whose connection type is ``Network`` is the only *proof*; this is the
    explanation for when none is attached.
    """

    name: str
    path: Optional[Path] = None
    discovers_over_wifi: Optional[bool] = None
    note: Optional[str] = None

    def __repr__(self) -> str:
        parts = [self.name]
        if self.path is not None:
            parts.append(f"({self.path})")
        return " ".join(parts)


@dataclass
class HostUsbDevice:
    """An Apple device the host itself sees on USB, whatever usbmux makes of it."""

    name: str
    serial: str

    def __repr__(self) -> str:
        return f"{self.name} ({self.serial})"


DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3


def is_wsl() -> bool:
    try:
        with open("/proc/version") as f:
            version_info = f.read()
            return "Microsoft" in version_info or "WSL" in version_info
    except FileNotFoundError:
        return False


def _calling_function_name() -> str:
    frame = inspect.currentframe()
    assert frame is not None
    caller = frame.f_back
    assert caller is not None
    return caller.f_code.co_name


class OsUtils:
    _instance = None
    _os_name = None

    @classmethod
    def create(cls) -> "OsUtils":
        if cls._instance is None:
            cls._os_name = sys.platform
            if cls._os_name == "win32":
                from pymobiledevice3.osu.win_util import Win32

                cls._instance = Win32()
            elif cls._os_name == "darwin":
                from pymobiledevice3.osu.posix_util import Darwin

                cls._instance = Darwin()
            elif cls._os_name == "linux":
                from pymobiledevice3.osu.posix_util import Linux, Wsl

                cls._instance = Wsl() if is_wsl() else Linux()
            elif cls._os_name == "cygwin":
                from pymobiledevice3.osu.posix_util import Cygwin

                cls._instance = Cygwin()
            else:
                raise OSNotSupportedError(cls._os_name)
        return cls._instance

    @property
    def is_admin(self) -> bool:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    @property
    def usbmux_address(self) -> tuple[Union[str, tuple[str, int]], int]:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    @property
    def bonjour_timeout(self) -> int:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    @property
    def loopback_header(self) -> bytes:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    @property
    def supports_unix_sockets(self) -> bool:
        """Whether AF_UNIX stream sockets (and asyncio's unix stream APIs) exist on this platform."""
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    @property
    def access_denied_error(self) -> str:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    @property
    def pair_record_path(self) -> Path:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    def get_ipv6_ips(self) -> list[str]:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    def set_keepalive(
        self,
        sock: socket.socket,
        after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
        interval_sec: int = DEFAULT_INTERVAL_SEC,
        max_fails: int = DEFAULT_MAX_FAILS,
    ) -> None:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    def parse_timestamp(self, time_stamp: float) -> datetime:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    def chown_to_non_sudo_if_needed(self, path: Path) -> None:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    def wait_return(self) -> None:
        raise FeatureNotSupportedError(self._os_name, _calling_function_name())

    def get_homedir(self) -> Path:
        return Path.home()

    def get_home_folder_path(self) -> Path:
        return self.get_homedir() / ".pymobiledevice3"

    def usbmux_daemon(self) -> Optional[UsbmuxDaemon]:
        """Identify the usbmux daemon serving this host, when the platform allows it.

        Used to explain a missing Wi-Fi device when none is attached to prove the answer either
        way. ``None`` means the platform offers no way to tell.
        """
        return None

    def usb_devices_seen_by_host(self) -> Optional[list[HostUsbDevice]]:
        """The Apple devices attached to this host's USB, asked of the OS rather than of usbmux.

        Lets "nothing is plugged in" be told apart from "usbmuxd is not listing what is plugged
        in". ``None`` means the platform offers no way to ask.
        """
        return None


def get_os_utils() -> OsUtils:
    return OsUtils.create()
