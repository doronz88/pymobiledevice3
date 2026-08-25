import asyncio
import contextlib
import logging
import platform
from collections.abc import Generator
from typing import Optional

import psutil

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remoted
from pymobiledevice3.exceptions import AccessDeniedError, ConnectionTerminatedError
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService

REMOTED_PATH = "/usr/libexec/remoted"
logger = logging.getLogger(__name__)


async def get_rsds(
    bonjour_timeout: float = DEFAULT_BONJOUR_TIMEOUT, udid: Optional[str] = None
) -> list[RemoteServiceDiscoveryService]:
    result: list[RemoteServiceDiscoveryService] = []
    with stop_remoted():
        for answer in await browse_remoted(timeout=bonjour_timeout):
            for address in answer.addresses:
                rsd = RemoteServiceDiscoveryService((address.full_ip, RSD_PORT))
                try:
                    await rsd.connect()
                except (
                    ConnectionTerminatedError,
                    asyncio.IncompleteReadError,
                    ConnectionResetError,
                    asyncio.TimeoutError,
                    OSError,
                ) as e:
                    logger.debug("Skipping RSD endpoint %s: %r", address.full_ip, e)
                    continue
                if udid is None or rsd.udid == udid:
                    result.append(rsd)
                else:
                    await rsd.close()
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
