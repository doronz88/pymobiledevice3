import time
from pathlib import Path
from ssl import SSLEOFError
from typing import Callable

import pytest

from pymobiledevice3.exceptions import ConnectionFailedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

PASSWORD = "1234"


def ignore_connection_errors(f: Callable):
    """
    The device may become unresponsive for a short while after changing the password settings and reject
    incoming connections at different stages
    """

    def _wrapper(*args, **kwargs):
        while True:
            try:
                f(*args, **kwargs)
                break
            except (
                SSLEOFError,
                ConnectionAbortedError,
                OSError,
                ConnectionFailedError,
            ):
                time.sleep(1)

    return _wrapper


@ignore_connection_errors
def change_password(lockdown, old: str = "", new: str = "") -> None:
    with Mobilebackup2Service(lockdown) as service:
        service.change_password(old=old, new=new)


@ignore_connection_errors
def backup(lockdown: LockdownClient, backup_directory: Path) -> None:
    with Mobilebackup2Service(lockdown) as service:
        service.backup(full=True, backup_directory=backup_directory)


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_backup(lockdown, tmp_path):
    backup(lockdown, tmp_path)


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_encrypted_backup(lockdown, tmp_path):
    change_password(lockdown, new=PASSWORD)
    backup(lockdown, tmp_path)
    change_password(lockdown, old=PASSWORD)
