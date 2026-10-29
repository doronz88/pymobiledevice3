import sys
from typing import Any

import pytest
from usb.core import USBError

from pymobiledevice3 import usb
from pymobiledevice3.usb import USB_BACKEND_ENV_VAR, UsbError
from pymobiledevice3.usb._pyusb_device import PyUsbDevice


@pytest.mark.parametrize(
    ("platform", "env", "iokit"),
    [
        ("darwin", None, True),
        ("darwin", "libusb", False),
        ("darwin", "iokit", True),
        ("linux", None, False),
        ("win32", "libusb", False),
    ],
)
def test_backend_selection(monkeypatch: pytest.MonkeyPatch, platform: str, env: Any, iokit: bool) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    if env is None:
        monkeypatch.delenv(USB_BACKEND_ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(USB_BACKEND_ENV_VAR, env)
    assert usb.uses_iokit() is iokit


@pytest.mark.parametrize(("platform", "env"), [("linux", "iokit"), ("darwin", "winusb")])
def test_backend_selection_rejects(monkeypatch: pytest.MonkeyPatch, platform: str, env: str) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setenv(USB_BACKEND_ENV_VAR, env)
    with pytest.raises(UsbError, match=USB_BACKEND_ENV_VAR):
        usb.uses_iokit()


class _StallingDevice:
    idVendor = 0x05AC
    idProduct = 0x1281

    def ctrl_transfer(self, *args: Any, **kwargs: Any) -> Any:
        raise USBError("Pipe error", errno=32, error_code=-9)


def test_pyusb_errors_become_usb_errors() -> None:
    device = PyUsbDevice(_StallingDevice())
    with pytest.raises(UsbError, match="0x40/0x00") as excinfo:
        device.control_out(0x40, 0, data=b"reboot\0")
    assert excinfo.value.code == -9
    assert isinstance(excinfo.value.__cause__, USBError)
