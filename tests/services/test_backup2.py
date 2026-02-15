import time
from pathlib import Path
from ssl import SSLEOFError

import pytest

from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionTerminatedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

PASSWORD = "1234"


def ignore_connection_errors(f):
    """
    The device may become unresponsive for a short while after changing the password settings and reject
    incoming connections at different stages
    """

    async def _wrapper(*args, **kwargs):
        while True:
            try:
                await f(*args, **kwargs)
                break
            except (
                SSLEOFError,
                ConnectionTerminatedError,
                OSError,
                ConnectionFailedError,
            ):
                time.sleep(1)

    return _wrapper


@ignore_connection_errors
async def change_password(lockdown: LockdownClient, old: str = "", new: str = "") -> None:
    async with Mobilebackup2Service(lockdown) as service:
        await service.change_password(old=old, new=new)


@ignore_connection_errors
async def backup(lockdown: LockdownClient, backup_directory: Path) -> None:
    async with Mobilebackup2Service(lockdown) as service:
        await service.backup(full=True, backup_directory=backup_directory)


@pytest.mark.filterwarnings("ignore::UserWarning")
@pytest.mark.asyncio
async def test_backup(lockdown: LockdownClient, tmp_path: Path) -> None:
    await backup(lockdown, tmp_path)


@pytest.mark.filterwarnings("ignore::UserWarning")
@pytest.mark.asyncio
async def test_encrypted_backup(lockdown: LockdownClient, tmp_path: Path) -> None:
    await change_password(lockdown, new=PASSWORD)
    await backup(lockdown, tmp_path)
    await change_password(lockdown, old=PASSWORD)
