import datetime
import logging
import os
import socket
import winreg
from contextlib import suppress
from pathlib import Path
from typing import Any, Optional, cast

import win32security  # pyright: ignore[reportMissingModuleSource]
from ifaddr import get_adapters

from pymobiledevice3.osu.os_utils import (
    DEFAULT_AFTER_IDLE_SEC,
    DEFAULT_INTERVAL_SEC,
    DEFAULT_MAX_FAILS,
    OsUtils,
    UsbmuxDaemon,
    service_binary,
)
from pymobiledevice3.usbmux import MuxConnection

# The service registers its binary here, readable without elevation -- unlike the process, which
# runs as SYSTEM and whose path an ordinary user cannot always read.
_AMDS_REGISTRY_KEY = r"SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service"
# Apple's Microsoft Store "Apple Devices" app installs under WindowsApps. Its service does not
# discover devices over Wi-Fi: reported in pymobiledevice3#1968 on Windows 11, where `usbmux list`
# stayed empty for a device `bonjour mobdev2` could see and the app's own UI could not reach
# either, with `lockdown wifi-connections` confirming the toggle was on. The classic iTunes
# package installs under Common Files and does discover them.
_STORE_APP_MARKER = "windowsapps"


class Win32(OsUtils):
    def usbmux_daemon(self) -> Optional[UsbmuxDaemon]:
        """Identify the Apple Mobile Device Service from the path the service registry records.

        The Store "Apple Devices" app and the classic iTunes package install services with the same
        role but different Wi-Fi behavior, and only the path tells them apart.
        """
        image_path: Optional[str] = None
        # winreg is Windows-only stdlib, unresolvable when pyright checks from another platform.
        with suppress(OSError), winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _AMDS_REGISTRY_KEY) as key:  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType, reportUnknownVariableType]
            image_path = cast(str, winreg.QueryValueEx(key, "ImagePath")[0])  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
        if image_path is None:
            return None
        path = Path(service_binary(image_path))
        if _STORE_APP_MARKER in image_path.lower():
            return UsbmuxDaemon(
                name='Apple Mobile Device Service (Microsoft Store "Apple Devices")',
                path=path,
                discovers_over_wifi=False,
            )
        return UsbmuxDaemon(
            name="Apple Mobile Device Service (iTunes)",
            path=path,
            discovers_over_wifi=True,
        )

    @property
    def is_admin(self) -> bool:
        """Check if the current OS user is an Administrator or root.
        See: https://github.com/Preston-Landers/pyuac/blob/master/pyuac/admin.py
        :return: True if the current user is an 'Administrator', otherwise False.
        """
        try:
            admin_sid = cast(Any, win32security).CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            # pywin32 accepts None for TokenHandle (current thread token); the stub only allows int.
            return cast(Any, win32security).CheckTokenMembership(None, admin_sid)
        except Exception:
            return False

    @property
    def supports_unix_sockets(self) -> bool:
        # CPython on Windows exposes neither socket.AF_UNIX nor asyncio's unix stream APIs.
        return False

    @property
    def usbmux_address(self) -> tuple[tuple[str, int], int]:
        return MuxConnection.ITUNES_HOST, socket.AF_INET

    @property
    def bonjour_timeout(self) -> int:
        return 2

    @property
    def loopback_header(self) -> bytes:
        return b"\x00\x00\x86\xdd"

    @property
    def access_denied_error(self) -> str:
        return 'This command requires admin privileges. Consider retrying with "run-as administrator".'

    @property
    def pair_record_path(self) -> Path:
        return Path(os.environ.get("ALLUSERSPROFILE", ""), "Apple", "Lockdown")

    def get_ipv6_ips(self) -> list[str]:
        return [
            f"{adapter.ips[0].ip[0]}%{adapter.ips[0].ip[2]}" for adapter in get_adapters() if adapter.ips[0].is_IPv6
        ]

    def set_keepalive(
        self,
        sock: socket.socket,
        after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
        interval_sec: int = DEFAULT_INTERVAL_SEC,
        max_fails: int = DEFAULT_MAX_FAILS,
    ) -> None:
        ioctl_socket: Any = sock
        if not hasattr(ioctl_socket, "ioctl"):
            # asyncio may return a wrapper (e.g. TransportSocket) that does not expose ioctl().
            ioctl_socket = getattr(sock, "_sock", sock)

        if hasattr(ioctl_socket, "ioctl"):
            # SIO_KEEPALIVE_VALS only exists in the socket module on Windows.
            sio_keepalive_vals = cast(Any, socket).SIO_KEEPALIVE_VALS
            ioctl_socket.ioctl(sio_keepalive_vals, (1, after_idle_sec * 1000, interval_sec * 1000))
            return

        # Fallback for wrappers that do not expose ioctl; keepalive timings remain OS defaults.
        logging.getLogger(__name__).debug("Socket does not expose ioctl(); enabling SO_KEEPALIVE fallback")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    def parse_timestamp(self, time_stamp: float) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(time_stamp / 1000)

    def chown_to_non_sudo_if_needed(self, path: Path) -> None:
        return

    def wait_return(self):
        input("Press ENTER to exit>")
