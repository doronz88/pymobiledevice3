import contextlib
import platform
from collections.abc import Generator
from typing import Optional

import psutil

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remoted
from pymobiledevice3.exceptions import AccessDeniedError
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService

REMOTED_PATH = "/usr/libexec/remoted"


async def get_rsds(
    bonjour_timeout: float = DEFAULT_BONJOUR_TIMEOUT, udid: Optional[str] = None
) -> list[RemoteServiceDiscoveryService]:
    result = []
    with stop_remoted():
        for answer in await browse_remoted(timeout=bonjour_timeout):
            for address in answer.addresses:
                rsd = RemoteServiceDiscoveryService((address.full_ip, RSD_PORT))
                try:
                    await rsd.connect()
                except ConnectionRefusedError:
                    continue
                except OSError:
                    continue
                if udid is None or rsd.udid == udid:
                    result.append(rsd)
                else:
                    await rsd.close()
    return result


def get_remoted_process() -> psutil.Process:
    for process in psutil.process_iter():
        if process.pid == 0:
            # skip kernel task
            continue
        try:
            if process.exe() == REMOTED_PATH:
                return process
        except (psutil.ZombieProcess, psutil.NoSuchProcess):
            continue


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
    stop_remoted_if_required()
    try:
        yield
    finally:
        resume_remoted_if_required()
