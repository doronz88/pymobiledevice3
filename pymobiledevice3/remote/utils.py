import asyncio
import contextlib
import logging
import platform
import uuid
from collections.abc import Generator
from typing import Optional

import psutil

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, iter_browse_remoted
from pymobiledevice3.exceptions import AccessDeniedError, ConnectionTerminatedError
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import remoted_handshake_uuid

REMOTED_PATH = "/usr/libexec/remoted"
OSUTILS = get_os_utils()
logger = logging.getLogger(__name__)

# remoted's interval while a USB device's RSD link comes up, and how long to wait for it: the old
# bonjour window, so a device that never brings it up costs no more than before.
_USB_LINK_POLL_INTERVAL = 0.2
_USB_LINK_TIMEOUT = 3.0
# The handshake usually takes milliseconds, but right after remoted is suspended the device holds
# about one in ten of them for ~1.1 s, so its budget must clear that.
_USB_HANDSHAKE_TIMEOUT = 3.0
# What failing to reach one RSD endpoint looks like; anything else is a bug and propagates.
_RSD_ENDPOINT_ERRORS = (
    ConnectionTerminatedError,
    asyncio.IncompleteReadError,
    ConnectionResetError,
    asyncio.TimeoutError,
    OSError,
)


async def _get_usb_rsd_addresses(udid: Optional[str]) -> Optional[dict[str, str]]:
    """Each USB device's RSD address (see ``OsUtils.usb_rsd_addresses``), keyed by UDID.

    A device the host already sees on USB whose RSD link is not up yet is still coming up, so it gets
    a bounded wait. ``None`` when the OS cannot tell.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _USB_LINK_TIMEOUT
    while True:
        addresses = OSUTILS.usb_rsd_addresses()
        if addresses is None:
            return None
        if udid is not None:
            addresses = {device: address for device, address in addresses.items() if device == udid}
        coming_up = [
            device.serial
            for device in OSUTILS.usb_devices_seen_by_host() or []
            if device.serial not in addresses and (udid is None or device.serial == udid)
        ]
        if not coming_up or loop.time() >= deadline:
            if coming_up:
                logger.debug("RSD link of %s did not come up within %ss", coming_up, _USB_LINK_TIMEOUT)
            return addresses
        await asyncio.sleep(_USB_LINK_POLL_INTERVAL)


async def _connect_usb_rsds(
    handshake_uuid: Optional[uuid.UUID], peers: dict[str, str]
) -> list[RemoteServiceDiscoveryService]:
    """RSD on each USB device's RSD address (see `_get_usb_rsd_addresses`)."""

    async def connect(address: str) -> Optional[RemoteServiceDiscoveryService]:
        rsd = RemoteServiceDiscoveryService((address, RSD_PORT), handshake_uuid=handshake_uuid)
        try:
            await asyncio.wait_for(rsd.connect(), _USB_HANDSHAKE_TIMEOUT)
        except _RSD_ENDPOINT_ERRORS as e:
            logger.debug("Skipping RSD endpoint %s: %r", address, e)
            await rsd.close()
            return None
        return rsd

    return [rsd for rsd in await asyncio.gather(*map(connect, peers.values())) if rsd is not None]


async def get_rsds(
    bonjour_timeout: float = DEFAULT_BONJOUR_TIMEOUT, udid: Optional[str] = None
) -> list[RemoteServiceDiscoveryService]:
    result: list[RemoteServiceDiscoveryService] = []
    # Finding the devices touches neither RSD nor remoted, so it runs before remoted is suspended.
    peers = await _get_usb_rsd_addresses(udid)
    if peers is not None and not peers:
        # The OS lists every USB device's RSD link and none is up: bonjour could only find the same
        # ones again, and suspending remoted (which needs root) would be for nothing.
        return []
    # The NCM link is remoted's too: identify as remoted (see remoted_handshake_uuid), resolved while
    # remoted can still answer.
    handshake_uuid = await asyncio.to_thread(remoted_handshake_uuid)
    with stop_remoted():
        if peers is not None:
            return await _connect_usb_rsds(handshake_uuid, peers)
        # Asking for one device stops at it; listing them all still takes the whole window.
        answers = iter_browse_remoted(timeout=bonjour_timeout)
        try:
            async for answer in answers:
                for address in answer.addresses:
                    rsd = RemoteServiceDiscoveryService((address.full_ip, RSD_PORT), handshake_uuid=handshake_uuid)
                    try:
                        await rsd.connect()
                    except _RSD_ENDPOINT_ERRORS as e:
                        logger.debug("Skipping RSD endpoint %s: %r", address.full_ip, e)
                        continue
                    if udid is None or rsd.udid == udid:
                        result.append(rsd)
                    else:
                        await rsd.close()
                if udid is not None and result:
                    break
        finally:
            await answers.aclose()
    return result


def get_remoted_process() -> Optional[psutil.Process]:
    for process in psutil.process_iter():
        if process.pid == 0:
            # skip kernel task
            continue
        try:
            if process.exe() == REMOTED_PATH:
                return process
        except (psutil.ZombieProcess, psutil.NoSuchProcess):
            continue
    return None


def stop_remoted_if_required() -> None:
    if platform.system() != "Darwin":
        # only Darwin systems require it
        return

    remoted = get_remoted_process()
    if remoted is None:
        return
    if remoted.status() == "stopped":
        # process already stopped, we don't need to do anything
        return

    # Handshakes on the NCM link identify as remoted, whose UUID `remotectl` can only ask a running
    # remoted for: left for later, each handshake would wait out remotectl's timeout and the device
    # would be skipped.
    remoted_handshake_uuid()

    try:
        remoted.suspend()
    except psutil.AccessDenied as e:
        raise AccessDeniedError() from e


def resume_remoted_if_required() -> None:
    if platform.system() != "Darwin":
        # only Darwin systems require it
        return

    remoted = get_remoted_process()
    if remoted is None:
        return
    if remoted.status() == "running":
        # process already running, we don't need to do anything
        return

    try:
        remoted.resume()
    except psutil.AccessDenied as e:
        raise AccessDeniedError() from e


@contextlib.contextmanager
def stop_remoted() -> Generator[None, None, None]:
    """SIGSTOP macOS ``remoted`` for the duration of an RSD discovery/handshake, then resume it.

    The RSD-over-bonjour path (:func:`get_rsds`, used by ``remote start-tunnel`` and ``tunneld``)
    connects *directly* to the device's RSD RemoteXPC endpoint (``RSD_PORT`` 58783) over the USB
    NCM link. macOS ``remoted`` is the system-wide owner of that link and keeps its own RemoteXPC
    session to the device open at all times. While ``remoted`` is running, the device resets a
    second, independent RSD root channel opened from this process -- observed as an HTTP/2
    ``RST_STREAM`` (``error_code=5``) or a plain connection reset during the check-in handshake --
    so :func:`get_rsds` discovers the device over bonjour but cannot complete the handshake and
    returns nothing usable.

    Suspending ``remoted`` yields the link and the handshake then succeeds reliably (with
    ``remoted`` suspended the device will even accept several concurrent RSD sessions, which shows
    the reset comes from ``remoted`` owning the link, not from a device-side one-session cap).
    Suspending a root-owned daemon needs root -- this is the *second* reason the RSD/kernel-tunnel
    path requires ``sudo`` (the first being ``utun`` creation). ``remoted`` is resumed on exit.

    This competition is unrelated to pairing: it reproduces against an already-paired device with no
    pairing in flight, and completing a pairing does not tear down existing RSD connections. The
    no-root userspace/``CoreDeviceProxy`` path avoids it entirely by reaching RSD over usbmux
    instead of the NCM link, so it never touches ``remoted``.
    """
    stop_remoted_if_required()
    try:
        yield
    finally:
        resume_remoted_if_required()
