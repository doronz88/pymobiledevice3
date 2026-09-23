import datetime
import os
import signal
import socket
import string
import struct
import sys
from pathlib import Path
from typing import Any, Optional, Union, cast

import psutil
from ifaddr import get_adapters

if sys.platform == "darwin":
    # IOKit, so macOS-only -- and this module is imported on every posix platform.
    from ioregistry.ioentry import get_io_services_by_type
else:
    get_io_services_by_type = None

from pymobiledevice3.osu.os_utils import (
    DEFAULT_AFTER_IDLE_SEC,
    DEFAULT_INTERVAL_SEC,
    DEFAULT_MAX_FAILS,
    HostUsbDevice,
    OsUtils,
    UsbmuxDaemon,
)
from pymobiledevice3.usbmux import MuxConnection

# usbmuxd2 links Avahi to announce and find devices over Wi-Fi; stock libimobiledevice usbmuxd
# has no network discovery at all, and both binaries are called "usbmuxd".
_LINUX_MDNS_LIBRARY = b"libavahi"
# usbmuxd2 installs under either name depending on how it was built.
_USBMUXD_PROCESS_NAMES = ("usbmuxd", "usbmuxd2")

# IOKit reports the serial without the separator modern UDIDs carry: 00008030000215140A9A802E
# against usbmux's 00008030-000215140A9A802E. Older 40-character UDIDs have no separator at all.
_MODERN_UDID_LENGTH = 24
_MODERN_UDID_PREFIX_LENGTH = 8
# 24 hex characters on modern devices, 40 on everything before the iPhone XS era.
_UDID_LENGTHS = (_MODERN_UDID_LENGTH, 40)

# Apple's USB vendor id, as sysfs spells it.
_APPLE_USB_VENDOR_ID = "05ac"
# What `lsusb` itself reads. Going to sysfs directly avoids depending on usbutils being installed
# and avoids parsing another tool's output; every file here is world-readable, so no root either.
_LINUX_USB_DEVICES = Path("/sys/bus/usb/devices")

_DARWIN_TCP_KEEPALIVE = 0x10
_DARWIN_TCP_KEEPINTVL = 0x101
_DARWIN_TCP_KEEPCNT = 0x102


def _links_mdns(path: Path) -> Optional[bool]:
    """Does this mapping list, or this binary, reference Avahi? ``None`` when it cannot be read."""
    try:
        return _LINUX_MDNS_LIBRARY in path.read_bytes()
    except OSError:
        return None


def _read_sysfs(path: Path) -> Optional[str]:
    """One sysfs attribute, or ``None`` when the node does not carry it."""
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _looks_like_udid(serial: str) -> bool:
    """Is this an iOS device's UDID, rather than some other Apple peripheral's serial?

    Apple's vendor id also covers keyboards, trackpads and displays, none of which usbmux ever
    lists -- reporting those as "usbmux is blind" would be a false alarm with the wrong fix. A
    device in recovery reports a ``CPID:… ECID:…`` descriptor instead, which is also not a UDID.
    """
    bare = serial.replace("-", "")
    return len(bare) in _UDID_LENGTHS and all(character in string.hexdigits for character in bare)


def _with_udid_separator(serial: str) -> str:
    """Render an IOKit serial the way usbmux spells the same UDID."""
    if len(serial) == _MODERN_UDID_LENGTH and "-" not in serial:
        return f"{serial[:_MODERN_UDID_PREFIX_LENGTH]}-{serial[_MODERN_UDID_PREFIX_LENGTH:]}"
    return serial


class Posix(OsUtils):
    @property
    def is_admin(self) -> bool:
        return os.geteuid() == 0

    @property
    def supports_unix_sockets(self) -> bool:
        return True

    @property
    def usbmux_address(self) -> tuple[Union[str, tuple[str, int]], int]:
        return MuxConnection.USBMUXD_PIPE, socket.AF_UNIX

    @property
    def bonjour_timeout(self) -> int:
        return 3

    @property
    def access_denied_error(self) -> str:
        return 'This command requires root privileges. Consider retrying with "sudo".'

    def get_ipv6_ips(self) -> list[str]:
        return [
            f"{ip.ip[0]}%{adapter.nice_name}"
            for adapter in get_adapters()
            if not adapter.nice_name.startswith("tun")
            for ip in (next((i for i in adapter.ips if i.is_IPv6), None),)
            if ip
        ]

    def chown_to_non_sudo_if_needed(self, path: Path) -> None:
        sudo_uid = os.getenv("SUDO_UID")
        if sudo_uid is None:
            return
        sudo_gid = os.getenv("SUDO_GID")
        assert sudo_gid is not None
        os.chown(path, int(sudo_uid), int(sudo_gid))

    def parse_timestamp(self, time_stamp: float) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(time_stamp)

    def wait_return(self):
        print("Press Ctrl+C to send a SIGINT or use 'kill' command to send a SIGTERM")
        signal.sigwait([signal.SIGINT, signal.SIGTERM])


class Darwin(Posix):
    @property
    def pair_record_path(self) -> Path:
        return Path("/var/db/lockdown/")

    def usbmux_daemon(self) -> Optional[UsbmuxDaemon]:
        # Apple's own usbmuxd, launchd-activated. It has always done Wi-Fi discovery, and there is
        # no alternative implementation to tell it apart from.
        return UsbmuxDaemon(name="Apple usbmuxd", discovers_over_wifi=True)

    def usb_devices_seen_by_host(self) -> Optional[list[HostUsbDevice]]:
        """Ask IOKit which Apple devices are on USB, bypassing usbmux entirely."""
        if get_io_services_by_type is None:
            return None
        devices: list[HostUsbDevice] = []
        for entry in get_io_services_by_type("IOUSBHostDevice"):
            properties = entry.properties
            if properties.get("USB Vendor Name") != "Apple Inc.":
                continue
            serial = cast(Optional[str], properties.get("USB Serial Number"))
            if serial is None or not _looks_like_udid(serial):
                continue
            devices.append(
                HostUsbDevice(
                    name=cast(str, properties.get("USB Product Name", "Apple device")),
                    serial=_with_udid_separator(serial),
                )
            )
        return devices

    @property
    def loopback_header(self) -> bytes:
        return struct.pack(">I", socket.AF_INET6)

    def set_keepalive(
        self,
        sock: socket.socket,
        after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
        interval_sec: int = DEFAULT_INTERVAL_SEC,
        max_fails: int = DEFAULT_MAX_FAILS,
    ) -> None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPALIVE, after_idle_sec)
        sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPINTVL, interval_sec)
        sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPCNT, max_fails)


class Linux(Posix):
    @property
    def pair_record_path(self) -> Path:
        return Path("/var/lib/lockdown/")

    def usbmux_daemon(self) -> Optional[UsbmuxDaemon]:
        """Tell stock ``usbmuxd`` apart from ``usbmuxd2`` by whether it links Avahi.

        Both install as ``usbmuxd``, so the name settles nothing; only ``usbmuxd2`` pulls in Avahi,
        which its Wi-Fi discovery is built on. The daemon runs as root, so its ``/proc`` entries are
        unreadable for an ordinary user -- fall back to the binary on disk, which is world-readable
        and answers the same question.
        """
        for process in psutil.process_iter(["name", "exe"]):
            if process.info["name"] not in _USBMUXD_PROCESS_NAMES:
                continue
            path = Path(cast(str, process.info["exe"])) if process.info["exe"] else None
            links_mdns = _links_mdns(Path(f"/proc/{process.pid}/maps"))
            if links_mdns is None and path is not None:
                links_mdns = _links_mdns(path)
            if links_mdns is None:
                return UsbmuxDaemon(name="usbmuxd", path=path, note="its Avahi linkage is unreadable")
            if links_mdns:
                return UsbmuxDaemon(name="usbmuxd2", path=path, discovers_over_wifi=True)
            return UsbmuxDaemon(name="usbmuxd (libimobiledevice)", path=path, discovers_over_wifi=False)
        return None

    def usb_devices_seen_by_host(self) -> Optional[list[HostUsbDevice]]:
        """Ask the kernel which Apple devices are on USB, bypassing usbmux entirely."""
        if not _LINUX_USB_DEVICES.is_dir():
            return None
        devices: list[HostUsbDevice] = []
        for entry in sorted(_LINUX_USB_DEVICES.iterdir()):
            if _read_sysfs(entry / "idVendor") != _APPLE_USB_VENDOR_ID:
                continue
            serial = _read_sysfs(entry / "serial")
            if serial is None or not _looks_like_udid(serial):
                # An interface node, another Apple peripheral, or a device in recovery.
                continue
            devices.append(
                HostUsbDevice(
                    name=_read_sysfs(entry / "product") or "Apple device",
                    serial=_with_udid_separator(serial),
                )
            )
        return devices

    @property
    def loopback_header(self) -> bytes:
        return b"\x00\x00\x86\xdd"

    def set_keepalive(
        self,
        sock: socket.socket,
        after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
        interval_sec: int = DEFAULT_INTERVAL_SEC,
        max_fails: int = DEFAULT_MAX_FAILS,
    ) -> None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # TCP_KEEPIDLE is Linux-only; this class is only instantiated on Linux.
        tcp_keepidle = cast(Any, socket).TCP_KEEPIDLE
        sock.setsockopt(socket.IPPROTO_TCP, tcp_keepidle, after_idle_sec)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)

    def get_homedir(self) -> Path:
        return Path("~" + os.environ.get("SUDO_USER", "")).expanduser()

    def get_home_folder_path(self) -> Path:
        # Existing installations keep ~/.pymobiledevice3; fresh ones follow the XDG Base Directory
        # Specification: $XDG_DATA_HOME/pymobiledevice3 (~/.local/share/pymobiledevice3 by default).
        legacy = super().get_home_folder_path()
        if legacy.is_dir():
            return legacy
        xdg_data_home = Path(os.environ.get("XDG_DATA_HOME", ""))
        if not xdg_data_home.is_absolute():
            # The spec requires ignoring relative (or unset) paths
            xdg_data_home = self.get_homedir() / ".local" / "share"
        return xdg_data_home / "pymobiledevice3"


class Cygwin(Posix):
    @property
    def usbmux_address(self) -> tuple[tuple[str, int], int]:
        return MuxConnection.ITUNES_HOST, socket.AF_INET


class Wsl(Linux):
    @property
    def usbmux_address(self) -> tuple[tuple[str, int], int]:
        return MuxConnection.ITUNES_HOST, socket.AF_INET
