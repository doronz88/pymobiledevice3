import contextlib
import platform
from typing import Generator, List

import psutil
import requests

from pymobiledevice3.exceptions import AccessDeniedError, TunneldConnectionError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

REMOTED_PATH = '/usr/libexec/remoted'

TUNNELD_DEFAULT_ADDRESS = ('127.0.0.1', 5555)


def get_tunneld_devices(tunneld_address=TUNNELD_DEFAULT_ADDRESS) -> List[RemoteServiceDiscoveryService]:
    try:
        # Get the list of tunnels from the specified address
        resp = requests.get(f'http://{tunneld_address[0]}:{tunneld_address[1]}')
        tunnels = resp.json()
    except requests.exceptions.ConnectionError:
        raise TunneldConnectionError()

    rsds = []
    for tunnel_udid, tunnel_address in tunnels.items():
        rsd = RemoteServiceDiscoveryService(tunnel_address)
        try:
            rsd.connect()
            rsds.append(rsd)
        except (TimeoutError, ConnectionError):
            continue
    return rsds


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
