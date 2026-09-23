"""Host-side checks explaining what this machine can reach a device with, and why not.

Everything here inspects the *host*: the usbmux daemon, whether mDNS can leave the machine, which
tunnel transports are usable. No device is required -- which is the point, since a missing device
is usually the thing being explained.

Checks prefer proving a capability over inferring it. A device listed over Wi-Fi proves the daemon
discovers them; a successful ``Connect`` proves it can serve a connection. Daemon identity is only
consulted to explain a capability that could not be exercised.
"""

import asyncio
import os
import platform
import sys
from collections.abc import Awaitable
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, cast

import typer
from packaging.version import Version

from pymobiledevice3 import usbmux
from pymobiledevice3.bonjour import (
    MOBDEV2_SERVICE_NAME,
    QTYPE_PTR,
    _DatagramProtocol,
    _open_mdns_sockets,
    _send_query_all,
    build_query,
)
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import MuxException, PyMobileDevice3Exception, TunneldConnectionError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.pair_records import iter_remote_pair_records
from pymobiledevice3.services.mobile_image_mounter import (
    DeveloperDiskImageMounter,
    MobileImageMounterService,
    PersonalizedImageMounter,
)
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, get_tunneld_tunnels

OSUTILS = get_os_utils()

# lockdownd's well-known port. Connecting and closing immediately is what every command already
# does, and it is the cheapest way to prove the daemon implements `Connect`.
LOCKDOWN_PORT = 62078
# usbmuxd2 shipped without `Connect` until 0.64; listing worked while every service connection
# failed, which is the most confusing way this can break (pymobiledevice3#1147).
USBMUXD2_CONNECT_FIX_VERSION = "0.64"
# A refused send is reported through the protocol's error_received callback rather than raised by
# sendto(), so the errors need a turn of the loop to land before they can be counted.
MDNS_ERROR_SETTLE_SECONDS = 0.3
# usbmux performs no timeout of its own, and a device listed over Wi-Fi may simply be asleep.
CONNECT_PROBE_TIMEOUT = 5.0
# Widest title shipped, so every line in a section starts its detail at the same column.
TITLE_COLUMN = 20


class Status(Enum):
    """How a single check came out."""

    OK = "OK"
    WARNING = "WARN"
    PROBLEM = "FAIL"
    NOT_APPLICABLE = "n/a"
    UNKNOWN = "?"

    @property
    def color(self) -> str:
        return {
            Status.OK: "green",
            Status.WARNING: "yellow",
            Status.PROBLEM: "red",
            Status.NOT_APPLICABLE: "bright_black",
            Status.UNKNOWN: "yellow",
        }[self]


@dataclass
class Check:
    """One capability in the reader's terms: what was observed, what it costs, how to fix it."""

    title: str
    status: Status
    detail: str
    impact: Optional[str] = None
    hint: Optional[str] = None

    def __repr__(self) -> str:
        # Styled here rather than in the CLI so every caller renders a check the same way. Colors
        # are dropped automatically when the output is not a terminal (``typer.echo``).
        title = typer.style(f"{self.title:<{TITLE_COLUMN}}", fg=self.status.color, bold=True)
        lines = [f"  {title} {self.detail}"]
        if self.impact is not None:
            lines.append(typer.style(f"      so:  {self.impact}", fg="yellow"))
        if self.hint is not None:
            lines.append(typer.style(f"      fix: {self.hint}", fg="cyan"))
        return "\n".join(lines)


@dataclass
class Report:
    """Every check, grouped by what it means for the reader rather than by the order it ran."""

    environment: str
    checks: list[Check] = field(default_factory=list[Check])

    def _of(self, *statuses: Status) -> list[Check]:
        return [check for check in self.checks if check.status in statuses]

    @property
    def problems(self) -> list[Check]:
        return self._of(Status.PROBLEM)

    def __repr__(self) -> str:
        sections = [
            ("This works", "green", self._of(Status.OK)),
            ("This does not", "red", self._of(Status.PROBLEM)),
            ("Worth knowing", "yellow", self._of(Status.WARNING, Status.UNKNOWN)),
            ("Not available here", "bright_black", self._of(Status.NOT_APPLICABLE)),
        ]
        blocks = [typer.style(self.environment, dim=True)]
        for heading, color, checks in sections:
            if not checks:
                continue
            blocks.append(
                typer.style(f"{heading}:", fg=color, bold=True) + "\n" + "\n".join(repr(check) for check in checks)
            )
        if not self.problems:
            blocks.append(typer.style("Nothing here is blocking a device connection.", fg="green", bold=True))
        return "\n\n".join(blocks)


def _environment() -> str:
    try:
        from pymobiledevice3._version import __version__
    except ImportError:
        __version__ = "unknown (not installed)"
    return f"pymobiledevice3 {__version__} on {platform.platform()}, python {platform.python_version()}"


def _host_usb_check(devices: list[usbmux.MuxDevice]) -> Optional[Check]:
    """Ask the OS what is plugged in, so "nothing attached" and "usbmuxd is blind" read differently."""
    seen_by_host = OSUTILS.usb_devices_seen_by_host()
    if seen_by_host is None:
        return None
    if not seen_by_host:
        return Check(
            "Device plugged in",
            Status.NOT_APPLICABLE,
            "the host sees no Apple device on USB",
            impact="USB commands have nothing to talk to (Wi-Fi may still work)",
            hint="plug the device in and unlock it, or use Wi-Fi",
        )
    listed = [device for device in devices if device.is_usb]
    unlisted = [seen for seen in seen_by_host if not any(device.matches_udid(seen.serial) for device in listed)]
    if not unlisted:
        return Check(
            "Device plugged in",
            Status.OK,
            ", ".join(repr(device) for device in seen_by_host) + ", and usbmux lists it",
        )
    return Check(
        "Device plugged in",
        Status.PROBLEM,
        ", ".join(repr(device) for device in unlisted) + " -- the host sees it, usbmux does not",
        impact='every command fails with "device not found" although the cable is fine',
        hint="restart the usbmux daemon, and make sure the device is unlocked and trusted",
    )


async def _usbmux_checks() -> list[Check]:
    """Reach usbmux, then exercise what it is actually asked to do."""
    try:
        devices = await usbmux.list_devices()
    except (PyMobileDevice3Exception, OSError) as e:
        # OSError covers what the socket layer does not convert: no permission on the socket,
        # an unresolvable USBMUXD_SOCKET_ADDRESS, a daemon that died mid-handshake.
        daemon = OSUTILS.usbmux_daemon()
        return [
            Check(
                "usbmux daemon",
                Status.PROBLEM,
                f"not reachable ({type(e).__name__}: {e})",
                impact="no device can be reached over USB, and Wi-Fi discovery through usbmux is gone too",
                hint="start usbmuxd" if daemon is None else f"{daemon} is installed but not serving",
            )
        ]

    checks: list[Check] = []
    host_usb = _host_usb_check(devices)
    if host_usb is not None:
        checks.append(host_usb)
    checks.append(
        Check(
            "usbmux daemon",
            Status.OK,
            f"reachable, {len(devices)} device(s): "
            + (", ".join(f"{device.serial} over {device.connection_type}" for device in devices) or "none listed"),
        )
    )
    checks.append(await _wifi_discovery_check(devices))
    checks.append(await _connect_check(devices))
    return checks


async def _wifi_discovery_check(devices: list[usbmux.MuxDevice]) -> Check:
    """Prove Wi-Fi discovery from a listed device; fall back to naming the daemon."""
    if any(device.is_network for device in devices):
        return Check("Wi-Fi devices", Status.OK, "a device is listed over the network")

    daemon = OSUTILS.usbmux_daemon()
    if daemon is None:
        return Check(
            "Wi-Fi devices",
            Status.UNKNOWN,
            "no device is listed over the network and the daemon could not be identified",
            hint="attach a device over Wi-Fi to settle it: `pymobiledevice3 usbmux list`",
        )
    if daemon.discovers_over_wifi is False:
        return Check(
            "Wi-Fi devices",
            Status.WARNING,
            f"{daemon} does not discover devices over Wi-Fi",
            impact="a device with no cable will not appear in `usbmux list`",
            hint="install a daemon that does, or reach the device with `--mobdev2`",
        )
    if daemon.discovers_over_wifi is None:
        return Check("Wi-Fi devices", Status.UNKNOWN, f"{daemon}: {daemon.note}")
    return Check(
        "Wi-Fi devices",
        Status.OK,
        f"{daemon} supports it (no device is currently listed over the network)",
        hint="not seeing a Wi-Fi device? run `pymobiledevice3 lockdown wifi-connections on` once over USB",
    )


async def _connect_check(devices: list[usbmux.MuxDevice]) -> Check:
    """Open and drop one lockdown connection -- the message usbmuxd2 used to be missing."""
    if not devices:
        return Check("Service access", Status.NOT_APPLICABLE, "no device to connect to")
    # The daemon's `Connect` support is a USB-side story, and a device listed over Wi-Fi may be
    # asleep -- usbmux has no timeout of its own, so probing that one could hang the whole command.
    device = next((candidate for candidate in devices if candidate.is_usb), devices[0])
    try:
        sock = await asyncio.wait_for(device.connect(LOCKDOWN_PORT), timeout=CONNECT_PROBE_TIMEOUT)
    except asyncio.TimeoutError:
        return Check(
            "Service access",
            Status.PROBLEM,
            f"connecting to {device.serial} over {device.connection_type} timed out",
            impact="commands that reach this device will hang rather than fail",
            hint="the device may be asleep or off the network; wake it, or attach it over USB",
        )
    except MuxException as e:
        return Check(
            "Service access",
            Status.PROBLEM,
            f"listing works but connecting to {device.serial} failed ({e})",
            impact="the device is listed, yet every command that talks to it fails",
            hint="a daemon that lists devices but cannot connect is usually usbmuxd2 older than "
            f"{USBMUXD2_CONNECT_FIX_VERSION}, which shipped without the `Connect` message",
        )
    sock.close()
    return Check("Service access", Status.OK, f"opened a lockdown connection to {device.serial}")


async def _device_checks(devices: list[usbmux.MuxDevice]) -> list[Check]:
    """What the attached device is, and whether it is ready for developer work.

    Host facts alone do not explain a command that fails on one device and works on another. The
    OS version decides which transports even apply, and developer mode plus a mounted developer
    image are the two most common reasons a `developer` command fails with the tunnel working
    perfectly.

    Never pairs: an unpaired device is a fact to report, not a trust dialog to provoke.
    """
    if not devices:
        return []
    device = next((candidate for candidate in devices if candidate.is_usb), devices[0])
    lockdown = await create_using_usbmux(serial=device.serial, autopair=False)
    try:
        identity = f"{lockdown.product_type} running {lockdown.product_version}"
        if not lockdown.paired:
            return [
                Check(
                    "Device",
                    Status.WARNING,
                    f"{identity}, not paired with this host",
                    impact="anything beyond listing the device will be refused",
                    hint="run any command with the device unlocked and accept the trust prompt",
                )
            ]
        checks = [Check("Device", Status.OK, f"{identity}, paired")]
        version = Version(lockdown.product_version)
        checks.append(await _developer_mode_check(lockdown, version))
        checks.append(await _developer_image_check(lockdown, version))
        return checks
    finally:
        await lockdown.close()


async def _developer_mode_check(lockdown: LockdownClient, version: Version) -> Check:
    """Developer mode gates every developer service, and iOS 16 is where it appeared."""
    if version.major < 16:
        return Check("Developer mode", Status.NOT_APPLICABLE, "iOS 16 and later only")
    if await lockdown.get_developer_mode_status():
        return Check("Developer mode", Status.OK, "enabled")
    return Check(
        "Developer mode",
        Status.WARNING,
        "disabled",
        impact="no developer image can be mounted and every `developer` command will be refused",
        hint="pymobiledevice3 amfi enable-developer-mode (the device reboots and must be unlocked)",
    )


async def _developer_image_check(lockdown: LockdownClient, version: Version) -> Check:
    """Is a developer disk image mounted? iOS 17 personalizes it; older releases do not."""
    image_type = PersonalizedImageMounter.IMAGE_TYPE if version.major >= 17 else DeveloperDiskImageMounter.IMAGE_TYPE
    async with MobileImageMounterService(lockdown=lockdown) as mounter:
        mounted = await mounter.is_image_mounted(image_type)
    if mounted:
        return Check("Developer image", Status.OK, f"a {image_type} image is mounted")
    return Check(
        "Developer image",
        Status.WARNING,
        f"no {image_type} image is mounted",
        impact="`developer` commands will fail even with a working tunnel",
        hint="pymobiledevice3 mounter auto-mount",
    )


async def _mdns_check() -> Check:
    """Can an mDNS query leave this host at all? (macOS Local Network permission, firewalls)

    Mirrors what :func:`~pymobiledevice3.bonjour._warn_if_multicast_blocked` reports during a real
    browse: every send failing is the signal, and those failures surface asynchronously.
    """
    try:
        transports, _ = await _open_mdns_sockets()
    except OSError as e:
        return Check(
            "Bonjour discovery",
            Status.PROBLEM,
            f"no socket could be opened for mDNS ({type(e).__name__}: {e})",
            impact="`bonjour` commands and --mobdev2 find nothing",
            hint="another process may hold UDP/5353, or IPv6 may be disabled on this host",
        )
    try:
        sent = await _send_query_all(transports, build_query(MOBDEV2_SERVICE_NAME, QTYPE_PTR, unicast=False))
        await asyncio.sleep(MDNS_ERROR_SETTLE_SECONDS)
        errors = [
            error
            for transport, _ in transports
            for error in cast(_DatagramProtocol, transport.get_protocol()).send_errors
        ]
    finally:
        for transport, _ in transports:
            transport.close()

    if not sent:
        return Check("Bonjour discovery", Status.PROBLEM, "no interface could be opened for mDNS at all")
    if len(errors) >= sent:
        return Check(
            "Bonjour discovery",
            Status.PROBLEM,
            f"every query was refused on all {sent} interface(s) ({errors[0]})",
            impact="`bonjour` commands and --mobdev2 find nothing, and `remote` Wi-Fi flows cannot start",
            hint="on macOS allow the app running this command (e.g. your terminal) under System Settings > "
            "Privacy & Security > Local Network, then restart it; elsewhere check the firewall",
        )
    return Check(
        "Bonjour discovery", Status.OK, f"queries left the host on {sent - len(errors)} of {sent} interface(s)"
    )


async def _native_tunnel_check() -> Check:
    """macOS only: can we piggyback Apple's remotepairingd, no root needed?"""
    if sys.platform != "darwin":
        return Check("Tunnel (native)", Status.NOT_APPLICABLE, "macOS only")
    from pymobiledevice3.remote.native_tunnel import browse_native_devices

    try:
        found = await browse_native_devices()
    except PyMobileDevice3Exception as e:
        return Check("Tunnel (native)", Status.WARNING, f"remotepairingd is not usable ({type(e).__name__}: {e})")
    except Exception as e:
        return Check("Tunnel (native)", Status.UNKNOWN, f"unexpected failure probing remotepairingd ({e!r})")
    return Check("Tunnel (native)", Status.OK, f"remotepairingd answered, {len(found)} device(s)")


async def _tunneld_check() -> Check:
    """Ask whether tunneld is up. Connecting to its devices would be a device check, not a host one."""
    try:
        tunnels = await get_tunneld_tunnels()
    except TunneldConnectionError:
        return Check(
            "Tunnel (tunneld)",
            Status.NOT_APPLICABLE,
            f"not running on {TUNNELD_DEFAULT_ADDRESS[0]}:{TUNNELD_DEFAULT_ADDRESS[1]}",
        )
    return Check("Tunnel (tunneld)", Status.OK, f"running with {len(tunnels)} tunnel(s)")


async def _userspace_check() -> Check:
    try:
        import pmd_pytcp
    except ImportError:
        return Check(
            "Tunnel (userspace)",
            Status.PROBLEM,
            "pmd-pytcp is not installed",
            impact="--userspace cannot establish a tunnel",
            hint="pip install pmd-pytcp",
        )
    return Check("Tunnel (userspace)", Status.OK, f"pmd-pytcp {getattr(pmd_pytcp, '__version__', 'unknown')}")


async def _pair_records_check() -> Check:
    """Count what we can read. The system store is root-only on macOS, which is not the same as empty."""
    system_store = OSUTILS.pair_record_path
    if not system_store.is_dir():
        system = "no system store"
    elif not os.access(system_store, os.R_OK):
        system = f"system store {system_store} not readable (needs root)"
    else:
        system = f"{len(list(system_store.glob('*.plist')))} in {system_store}"
    # RemotePairing records share this folder, under a remote_ prefix; count them once.
    own = len([path for path in get_home_folder().glob("*.plist") if not path.name.startswith("remote_")])
    remote = len(list(iter_remote_pair_records()))
    return Check("Pairing", Status.OK, f"{own} own, {remote} RemotePairing, {system}")


async def _guarded_many(title: str, produce: Callable[[], Awaitable[list[Check]]]) -> list[Check]:
    """Never let one check take the report down with it.

    This command runs on hosts already broken in ways nobody predicted, so an unexpected exception
    has to become a line in the report rather than a traceback that costs every later check too.
    """
    try:
        return await produce()
    except Exception as e:
        return [Check(title, Status.UNKNOWN, f"could not be checked ({type(e).__name__}: {e})")]


async def _guarded(title: str, produce: Callable[[], Awaitable[Check]]) -> Check:
    return (await _guarded_many(title, lambda: _as_list(produce)))[0]


async def _as_list(produce: Callable[[], Awaitable[Check]]) -> list[Check]:
    return [await produce()]


async def _guarded_devices() -> list[usbmux.MuxDevice]:
    """The device list again, for the device section; its absence is already reported above."""
    try:
        return await usbmux.list_devices()
    except Exception:
        return []


async def run_checks() -> Report:
    """Run every host check, in the order a failure would cascade."""
    checks = await _guarded_many("usbmux daemon", _usbmux_checks)
    devices = await _guarded_devices()
    checks += await _guarded_many("Device", lambda: _device_checks(devices))
    for title, check in (
        ("Bonjour discovery", _mdns_check),
        ("Tunnel (native)", _native_tunnel_check),
        ("Tunnel (tunneld)", _tunneld_check),
        ("Tunnel (userspace)", _userspace_check),
        ("Pairing", _pair_records_check),
    ):
        checks.append(await _guarded(title, check))
    return Report(_environment(), checks)
