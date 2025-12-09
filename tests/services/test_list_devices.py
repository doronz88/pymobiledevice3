from pymobiledevice3 import usbmux
from pymobiledevice3.lockdown import LockdownClient


def test_list_devices(lockdown: LockdownClient) -> None:
    assert len(usbmux.list_devices()) >= 1
