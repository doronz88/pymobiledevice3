import asyncio

from pymobiledevice3 import usbmux
from pymobiledevice3.lockdown import LockdownClient


def test_list_devices(lockdown: LockdownClient) -> None:
    assert len(asyncio.run(usbmux.list_devices())) >= 1
