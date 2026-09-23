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
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, cast

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
from pymobiledevice3.exceptions import MuxException, PyMobileDevice3Exception
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.pair_records import iter_remote_pair_records
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, get_tunneld_devices

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


class Status(Enum):
    """How a single check came out."""

    OK = "OK"
    WARNING = "WARN"
    PROBLEM = "FAIL"
    NOT_APPLICABLE = "n/a"
    UNKNOWN = "?"


@dataclass
class Check:
    """One host capability, what was observed, and what to do when it is wrong."""

    title: str
    status: Status
    detail: str
    hint: Optional[str] = None

    def __repr__(self) -> str:
        lines = [f"{self.status.value:>4}  {self.title}: {self.detail}"]
        if self.hint is not None:
            lines.append(f"      -> {self.hint}")
        return "\n".join(lines)


@dataclass
class Report:
    """Every check, in the order they ran."""

    checks: list[Check] = field(default_factory=list[Check])

    @property
    def problems(self) -> list[Check]:
        return [check for check in self.checks if check.status is Status.PROBLEM]

    def __repr__(self) -> str:
        return "\n".join(repr(check) for check in self.checks)


def _environment() -> Check:
    try:
        from pymobiledevice3._version import __version__
    except ImportError:
        __version__ = "unknown (not installed)"
    return Check(
        "environment",
        Status.OK,
        f"pymobiledevice3 {__version__} on {platform.platform()}, python {platform.python_version()}",
    )


async def _usbmux_checks() -> list[Check]:
    """Reach usbmux, then exercise what it is actually asked to do."""
    try:
        devices = await usbmux.list_devices()
    except PyMobileDevice3Exception as e:
        daemon = OSUTILS.usbmux_daemon()
        detail = f"not reachable ({type(e).__name__})"
        hint = "start usbmuxd" if daemon is None else f"{daemon} is installed but not serving"
        return [Check("usbmuxd", Status.PROBLEM, detail, hint)]

    checks = [
        Check(
            "usbmuxd",
            Status.OK,
            f"reachable, {len(devices)} device(s): "
            + (", ".join(f"{device.serial} over {device.connection_type}" for device in devices) or "none listed"),
        )
    ]
    checks.append(await _wifi_discovery_check(devices))
    checks.append(await _connect_check(devices))
    return checks


async def _wifi_discovery_check(devices: list[usbmux.MuxDevice]) -> Check:
    """Prove Wi-Fi discovery from a listed device; fall back to naming the daemon."""
    if any(device.is_network for device in devices):
        return Check("usbmux Wi-Fi discovery", Status.OK, "a device is listed over the network")

    daemon = OSUTILS.usbmux_daemon()
    if daemon is None:
        return Check(
            "usbmux Wi-Fi discovery",
            Status.UNKNOWN,
            "no device is listed over the network and the daemon could not be identified",
            "attach a device over Wi-Fi to settle it: `pymobiledevice3 usbmux list`",
        )
    if daemon.discovers_over_wifi is False:
        return Check(
            "usbmux Wi-Fi discovery",
            Status.WARNING,
            f"{daemon} does not discover devices over Wi-Fi",
            "install a daemon that does, or reach the device with `--mobdev2`",
        )
    if daemon.discovers_over_wifi is None:
        return Check("usbmux Wi-Fi discovery", Status.UNKNOWN, f"{daemon}: {daemon.note}")
    return Check(
        "usbmux Wi-Fi discovery",
        Status.OK,
        f"{daemon} supports it (no device is currently listed over the network)",
        "not seeing a Wi-Fi device? run `pymobiledevice3 lockdown wifi-connections on` once over USB",
    )


async def _connect_check(devices: list[usbmux.MuxDevice]) -> Check:
    """Open and drop one lockdown connection -- the message usbmuxd2 used to be missing."""
    if not devices:
        return Check("usbmux connect", Status.NOT_APPLICABLE, "no device to connect to")
    device = devices[0]
    try:
        sock = await device.connect(LOCKDOWN_PORT)
    except MuxException as e:
        return Check(
            "usbmux connect",
            Status.PROBLEM,
            f"listing works but connecting to {device.serial} failed ({e})",
            "a daemon that lists devices but cannot connect is usually usbmuxd2 older than "
            f"{USBMUXD2_CONNECT_FIX_VERSION}, which shipped without the `Connect` message",
        )
    sock.close()
    return Check("usbmux connect", Status.OK, f"opened a lockdown connection to {device.serial}")


async def _mdns_check() -> Check:
    """Can an mDNS query leave this host at all? (macOS Local Network permission, firewalls)

    Mirrors what :func:`~pymobiledevice3.bonjour._warn_if_multicast_blocked` reports during a real
    browse: every send failing is the signal, and those failures surface asynchronously.
    """
    transports, _ = await _open_mdns_sockets()
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
        return Check("mDNS", Status.PROBLEM, "no interface could be opened for mDNS at all")
    if len(errors) >= sent:
        return Check(
            "mDNS",
            Status.PROBLEM,
            f"every query was refused on all {sent} interface(s) ({errors[0]}), so bonjour cannot work",
            "on macOS allow the app running this command (e.g. your terminal) under System Settings > "
            "Privacy & Security > Local Network, then restart it; elsewhere check the firewall",
        )
    return Check("mDNS", Status.OK, f"queries left the host on {sent - len(errors)} of {sent} interface(s)")


async def _native_tunnel_check() -> Check:
    """macOS only: can we piggyback Apple's remotepairingd, no root needed?"""
    if sys.platform != "darwin":
        return Check("native tunnel", Status.NOT_APPLICABLE, "macOS only")
    from pymobiledevice3.remote.native_tunnel import browse_native_devices

    try:
        found = await browse_native_devices()
    except PyMobileDevice3Exception as e:
        return Check("native tunnel", Status.WARNING, f"remotepairingd is not usable ({type(e).__name__}: {e})")
    except Exception as e:
        return Check("native tunnel", Status.UNKNOWN, f"unexpected failure probing remotepairingd ({e!r})")
    return Check("native tunnel", Status.OK, f"remotepairingd answered, {len(found)} device(s)")


async def _tunneld_check() -> Check:
    try:
        rsds = await get_tunneld_devices()
    except Exception:
        return Check(
            "tunneld",
            Status.NOT_APPLICABLE,
            f"not running on {TUNNELD_DEFAULT_ADDRESS[0]}:{TUNNELD_DEFAULT_ADDRESS[1]}",
        )
    for rsd in rsds:
        with suppress(Exception):
            await rsd.close()
    return Check("tunneld", Status.OK, f"running with {len(rsds)} tunnel(s)")


def _userspace_check() -> Check:
    try:
        import pmd_pytcp
    except ImportError:
        return Check(
            "userspace tunnel",
            Status.PROBLEM,
            "pmd-pytcp is not installed, so --userspace cannot work",
            "pip install pmd-pytcp",
        )
    return Check("userspace tunnel", Status.OK, f"pmd-pytcp {getattr(pmd_pytcp, '__version__', 'unknown')}")


def _pair_records_check() -> Check:
    """Count what we can read. The system store is root-only on macOS, which is not the same as empty."""
    system_store = OSUTILS.pair_record_path
    if not system_store.is_dir():
        system = "no system store"
    elif not os.access(system_store, os.R_OK):
        system = f"system store {system_store} not readable (needs root)"
    else:
        system = f"{len(list(system_store.glob('*.plist')))} in {system_store}"
    own = len(list(get_home_folder().glob("*.plist")))
    remote = len(list(iter_remote_pair_records()))
    return Check("pair records", Status.OK, f"{own} own, {remote} RemotePairing, {system}")


async def run_checks() -> Report:
    """Run every host check, in the order a failure would cascade."""
    checks = [_environment()]
    checks += await _usbmux_checks()
    checks.append(await _mdns_check())
    checks.append(await _native_tunnel_check())
    checks.append(await _tunneld_check())
    checks.append(_userspace_check())
    checks.append(_pair_records_check())
    return Report(checks)
