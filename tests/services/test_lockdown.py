import asyncio

import pytest

from pymobiledevice3.lockdown import LockdownClient

LOCKDOWND_SOCKET_SELECT_TIMEOUT = 60


@pytest.mark.asyncio
async def test_lockdown_reconnect(lockdown: LockdownClient) -> None:
    d1 = await lockdown.get_date()

    # add some threshold to make sure lockdownd closed the connection on its end
    await asyncio.sleep(LOCKDOWND_SOCKET_SELECT_TIMEOUT + 5)

    d2 = await lockdown.get_date()

    assert d1 < d2
