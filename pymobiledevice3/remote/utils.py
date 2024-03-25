import contextlib
import platform
import sys
from typing import Generator, List

import psutil

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remoted
from pymobiledevice3.exceptions import AccessDeniedError
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService

REMOTED_PATH = '/usr/libexec/remoted'


async def get_rsds(bonjour_timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[RemoteServiceDiscoveryService]:
    result = []
    with stop_remoted():
        for answer in await browse_remoted(timeout=bonjour_timeout):
            for ip in answer.ips:
                rsd = RemoteServiceDiscoveryService((ip, RSD_PORT))
                try:
                    rsd.connect()
                except ConnectionRefusedError:
                    continue
                except OSError:
                    continue
                result.append(rsd)
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
    if platform.system() != 'Darwin':
        # only Darwin systems require it
        return

    remoted = get_remoted_process()
    if remoted is None:
        return
    if remoted.status() == 'stopped':
        # process already stopped, we don't need to do anything
        return

    try:
        remoted.suspend()
    except psutil.AccessDenied:
        raise AccessDeniedError()


def resume_remoted_if_required() -> None:
    if platform.system() != 'Darwin':
        # only Darwin systems require it
        return

    remoted = get_remoted_process()
    if remoted is None:
        return
    if remoted.status() == 'running':
        # process already running, we don't need to do anything
        return

    try:
        remoted.resume()
    except psutil.AccessDenied:
        raise AccessDeniedError()


@contextlib.contextmanager
def stop_remoted() -> Generator[None, None, None]:
    stop_remoted_if_required()
    try:
        yield
    finally:
        resume_remoted_if_required()


def install_driver_if_required() -> None:
    if sys.platform == 'win32':
        import pywintunx_pmd3
        pywintunx_pmd3.install_wetest_driver()
