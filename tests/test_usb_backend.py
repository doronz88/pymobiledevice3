import sys
from collections.abc import Generator
from typing import Any

import pytest

from pymobiledevice3 import usb
from pymobiledevice3.usb import USB_BACKEND_ENV_VAR, UsbError, _libusb, _libusb_device


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


@pytest.fixture(scope="module")
def libusb() -> Generator[None, None, None]:
    """libusb, exited afterwards: the package keeps its context, and the fds that holds, until the process ends."""
    try:
        library = _libusb.library()
    except UsbError as e:
        pytest.skip(str(e))
    yield
    library.lib.libusb_exit(library.context)
    _libusb._library = None


@pytest.mark.usefixtures("libusb")
def test_libusb_errors_become_usb_errors() -> None:
    with pytest.raises(UsbError, match="0x40/0x00 failed: LIBUSB_ERROR_PIPE") as excinfo:
        _libusb.check("USB control request 0x40/0x00", _libusb.LIBUSB_ERROR_PIPE)
    assert excinfo.value.code == _libusb.LIBUSB_ERROR_PIPE
    assert _libusb.check("anything", 3) == 3


def test_libusb_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_libusb, "_locate", lambda: None)
    # load it anew, without the library
    monkeypatch.setattr(_libusb, "_library", None)
    with pytest.raises(UsbError, match=r"libusb-1\.0 was not found"):
        _libusb.library()


@pytest.mark.usefixtures("libusb")
def test_libusb_lists_devices() -> None:
    devices = _libusb_device.list_devices()
    try:
        for device in devices:
            assert 0 <= device.idVendor <= 0xFFFF
            assert 0 <= device.idProduct <= 0xFFFF
    finally:
        for device in devices:
            device.close()
