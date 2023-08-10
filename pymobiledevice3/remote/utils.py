import contextlib
import platform
from typing import Generator

import psutil

REMOTED_PATH = '/usr/libexec/remoted'


def _get_remoted_process() -> psutil.Process:
    for process in psutil.process_iter():
        if process.pid == 0:
            # skip kernel task
            continue
        if process.exe() == REMOTED_PATH:
            return process


@contextlib.contextmanager
def stop_remoted() -> Generator[None, None, None]:
    if platform.system() != 'Darwin':
        # only Darwin systems require it
        yield
        return

    remoted = _get_remoted_process()
    if remoted.status() == 'stopped':
        # process already stopped, we don't need to do anything
        yield
        return

    remoted.suspend()
    try:
        yield
    finally:
        remoted.resume()
