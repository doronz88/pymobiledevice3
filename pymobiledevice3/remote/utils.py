import contextlib
import platform
from typing import Generator

import psutil

from pymobiledevice3.exceptions import AccessDeniedError

REMOTED_PATH = '/usr/libexec/remoted'


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
