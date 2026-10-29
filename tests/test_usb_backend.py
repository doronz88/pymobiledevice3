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


@pytest.mark.parametrize(
    ("platform", "hint"),
    [
        ("linux", "install it with your package manager (e.g. `apt install libusb-1.0-0`)"),
        ("darwin", "install it with `brew install libusb`"),
        ("win32", "put libusb-1.0.dll (from https://libusb.info) next to python.exe or on PATH"),
    ],
)
def test_libusb_missing(monkeypatch: pytest.MonkeyPatch, platform: str, hint: str) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(_libusb, "_locate", lambda: None)
    # load it anew, without the library
    monkeypatch.setattr(_libusb, "_library", None)
    with pytest.raises(UsbError) as excinfo:
        _libusb.library()
    assert str(excinfo.value) == f"libusb-1.0 was not found: {hint}."


@pytest.mark.parametrize(
    ("platform", "code", "hint"),
    [
        (
            "linux",
            _libusb.LIBUSB_ERROR_ACCESS,
            " (no permission to open it: run as root, or add a udev rule giving your user access)",
        ),
        ("darwin", _libusb.LIBUSB_ERROR_ACCESS, ""),
        ("win32", _libusb.LIBUSB_ERROR_ACCESS, ""),
        ("win32", _libusb.LIBUSB_ERROR_NOT_SUPPORTED, " (it needs the WinUSB driver, e.g. installed with Zadig)"),
        ("linux", _libusb.LIBUSB_ERROR_NOT_SUPPORTED, ""),
        ("darwin", _libusb.LIBUSB_ERROR_NOT_SUPPORTED, ""),
        ("linux", _libusb.LIBUSB_ERROR_NO_DEVICE, " (the device is gone: disconnected or re-enumerated)"),
        ("win32", _libusb.LIBUSB_ERROR_NO_DEVICE, " (the device is gone: disconnected or re-enumerated)"),
        ("darwin", _libusb.LIBUSB_ERROR_PIPE, " (the device stalled the request)"),
        ("linux", _libusb.LIBUSB_ERROR_TIMEOUT, ""),
    ],
)
def test_libusb_error_hints(monkeypatch: pytest.MonkeyPatch, platform: str, code: int, hint: str) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    # the name comes from the library, which may be absent here
    monkeypatch.setattr(_libusb, "error_name", lambda code: "LIBUSB_ERROR_X")
    with pytest.raises(UsbError) as excinfo:
        _libusb.check("Opening the device", code)
    assert str(excinfo.value) == f"Opening the device failed: LIBUSB_ERROR_X{hint}"
    assert excinfo.value.code == code


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


def test_libusb_reads_the_languages_once(monkeypatch: pytest.MonkeyPatch) -> None:
    device = _libusb_device.LibUsbDevice.__new__(_libusb_device.LibUsbDevice)
    device._language = None
    requests: list[tuple[int, int]] = []

    def control_in(
        bmRequestType: int, bRequest: int, wValue: int, wIndex: int, length: int, timeout: Any = None
    ) -> bytes:
        requests.append((wValue, wIndex))
        if wValue == 0x300:
            # string descriptor 0: English (US)
            return bytes([4, 3, 0x09, 0x04])
        return bytes([6, 3]) + "ab".encode("utf-16-le")

    monkeypatch.setattr(device, "control_in", control_in)
    assert device.get_string(1) == "ab"
    assert device.get_string(2) == "ab"
    # as pyusb: string descriptor 0 is read for the first string only
    assert requests == [(0x300, 0), (0x301, 0x409), (0x302, 0x409)]
