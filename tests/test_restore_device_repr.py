from types import SimpleNamespace
from typing import cast

from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.device import Device


def test_irecv_device_repr_reports_real_values():
    irecv = cast(IRecv, SimpleNamespace(ecid=0x1234, hardware_model="d23ap", is_image4_supported=0x40))

    assert repr(Device(irecv=irecv)) == "<Device ecid: 4660 hardware_model: d23ap image4-support: True>"


def test_lockdown_device_repr_reports_image4_support_once_resolved():
    lockdown = cast(LockdownClient, SimpleNamespace(ecid=4660, all_values={"HardwareModel": "D23AP"}))
    device = Device(lockdown=lockdown)

    assert repr(device) == "<Device ecid: 4660 hardware_model: d23ap image4-support: unknown>"

    device._is_image4_supported = True
    assert repr(device) == "<Device ecid: 4660 hardware_model: d23ap image4-support: True>"
