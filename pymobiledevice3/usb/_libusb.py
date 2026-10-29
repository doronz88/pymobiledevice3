"""
The libusb-1.0 calls needed to reach a device without usbmuxd, from ctypes.

The library is found the way pyusb finds it, and loaded on first use so that importing this module never fails.
"""

import ctypes
import ctypes.util
import os
import platform
import sys
from ctypes import POINTER, Structure, byref, c_char_p, c_int, c_ssize_t, c_ubyte, c_uint, c_uint8, c_uint16, c_void_p
from typing import Any, Optional

from pymobiledevice3.usb.device import UsbError

# names ``ctypes.util.find_library`` knows libusb-1.0 by (the last one is FreeBSD's)
_CANDIDATES = ("usb-1.0", "libusb-1.0", "usb")
# Homebrew's prefix on Apple silicon, which interpreters other than Homebrew's own don't search
_HOMEBREW_LIB = "/opt/homebrew/lib"

LIBUSB_SUCCESS = 0
LIBUSB_ERROR_IO = -1
LIBUSB_ERROR_ACCESS = -3
LIBUSB_ERROR_NO_DEVICE = -4
LIBUSB_ERROR_NOT_FOUND = -5
LIBUSB_ERROR_BUSY = -6
LIBUSB_ERROR_TIMEOUT = -7
LIBUSB_ERROR_PIPE = -9
LIBUSB_ERROR_NOT_SUPPORTED = -12


class DeviceDescriptor(Structure):
    _fields_ = [
        ("bLength", c_uint8),
        ("bDescriptorType", c_uint8),
        ("bcdUSB", c_uint16),
        ("bDeviceClass", c_uint8),
        ("bDeviceSubClass", c_uint8),
        ("bDeviceProtocol", c_uint8),
        ("bMaxPacketSize0", c_uint8),
        ("idVendor", c_uint16),
        ("idProduct", c_uint16),
        ("bcdDevice", c_uint16),
        ("iManufacturer", c_uint8),
        ("iProduct", c_uint8),
        ("iSerialNumber", c_uint8),
        ("bNumConfigurations", c_uint8),
    ]


class EndpointDescriptor(Structure):
    _fields_ = [
        ("bLength", c_uint8),
        ("bDescriptorType", c_uint8),
        ("bEndpointAddress", c_uint8),
        ("bmAttributes", c_uint8),
        ("wMaxPacketSize", c_uint16),
        ("bInterval", c_uint8),
        ("bRefresh", c_uint8),
        ("bSynchAddress", c_uint8),
        ("extra", POINTER(c_ubyte)),
        ("extra_length", c_int),
    ]


class InterfaceDescriptor(Structure):
    _fields_ = [
        ("bLength", c_uint8),
        ("bDescriptorType", c_uint8),
        ("bInterfaceNumber", c_uint8),
        ("bAlternateSetting", c_uint8),
        ("bNumEndpoints", c_uint8),
        ("bInterfaceClass", c_uint8),
        ("bInterfaceSubClass", c_uint8),
        ("bInterfaceProtocol", c_uint8),
        ("iInterface", c_uint8),
        ("endpoint", POINTER(EndpointDescriptor)),
        ("extra", POINTER(c_ubyte)),
        ("extra_length", c_int),
    ]


class Interface(Structure):
    _fields_ = [
        ("altsetting", POINTER(InterfaceDescriptor)),
        ("num_altsetting", c_int),
    ]


class ConfigDescriptor(Structure):
    _fields_ = [
        ("bLength", c_uint8),
        ("bDescriptorType", c_uint8),
        ("wTotalLength", c_uint16),
        ("bNumInterfaces", c_uint8),
        ("bConfigurationValue", c_uint8),
        ("iConfiguration", c_uint8),
        ("bmAttributes", c_uint8),
        ("MaxPower", c_uint8),
        ("interface", POINTER(Interface)),
        ("extra", POINTER(c_ubyte)),
        ("extra_length", c_int),
    ]


def _missing_library_hint() -> str:
    if sys.platform == "win32":
        return "put libusb-1.0.dll (from https://libusb.info) next to python.exe or on PATH"
    if sys.platform == "darwin":
        return "install it with `brew install libusb`"
    return "install it with your package manager (e.g. `apt install libusb-1.0-0`)"


def _locate() -> Optional[str]:
    for candidate in _CANDIDATES:
        if sys.platform == "win32":
            # find_library on Windows wants the file name
            candidate += ".dll"
        path = ctypes.util.find_library(candidate)
        if path:
            return path
        if sys.platform == "darwin" and platform.machine() == "arm64":
            path = os.path.join(_HOMEBREW_LIB, f"{candidate}.dylib")
            if os.path.isfile(path):
                return path
    return None


def _setup_prototypes(lib: Any) -> None:
    lib.libusb_init.argtypes = [POINTER(c_void_p)]
    lib.libusb_error_name.restype = c_char_p
    lib.libusb_error_name.argtypes = [c_int]
    lib.libusb_get_device_list.restype = c_ssize_t
    lib.libusb_get_device_list.argtypes = [c_void_p, POINTER(POINTER(c_void_p))]
    lib.libusb_free_device_list.restype = None
    lib.libusb_free_device_list.argtypes = [POINTER(c_void_p), c_int]
    lib.libusb_ref_device.restype = c_void_p
    lib.libusb_ref_device.argtypes = [c_void_p]
    lib.libusb_unref_device.restype = None
    lib.libusb_unref_device.argtypes = [c_void_p]
    lib.libusb_get_device_descriptor.argtypes = [c_void_p, POINTER(DeviceDescriptor)]
    lib.libusb_get_bus_number.restype = c_uint8
    lib.libusb_get_bus_number.argtypes = [c_void_p]
    lib.libusb_get_device_address.restype = c_uint8
    lib.libusb_get_device_address.argtypes = [c_void_p]
    lib.libusb_get_config_descriptor_by_value.argtypes = [c_void_p, c_uint8, POINTER(POINTER(ConfigDescriptor))]
    lib.libusb_free_config_descriptor.restype = None
    lib.libusb_free_config_descriptor.argtypes = [POINTER(ConfigDescriptor)]
    lib.libusb_open.argtypes = [c_void_p, POINTER(c_void_p)]
    lib.libusb_close.restype = None
    lib.libusb_close.argtypes = [c_void_p]
    lib.libusb_get_configuration.argtypes = [c_void_p, POINTER(c_int)]
    lib.libusb_set_configuration.argtypes = [c_void_p, c_int]
    lib.libusb_claim_interface.argtypes = [c_void_p, c_int]
    lib.libusb_release_interface.argtypes = [c_void_p, c_int]
    lib.libusb_set_interface_alt_setting.argtypes = [c_void_p, c_int, c_int]
    lib.libusb_reset_device.argtypes = [c_void_p]
    lib.libusb_control_transfer.argtypes = [c_void_p, c_uint8, c_uint8, c_uint16, c_uint16, c_void_p, c_uint16, c_uint]
    lib.libusb_bulk_transfer.argtypes = [c_void_p, c_ubyte, c_void_p, c_int, POINTER(c_int), c_uint]
    lib.libusb_interrupt_transfer.argtypes = [c_void_p, c_ubyte, c_void_p, c_int, POINTER(c_int), c_uint]


class _Library:
    """libusb-1.0 and the one context this process uses."""

    def __init__(self) -> None:
        path = _locate()
        if path is None:
            raise UsbError(f"libusb-1.0 was not found: {_missing_library_hint()}.")
        # libusb's calls are stdcall on Windows
        loader = ctypes.WinDLL if sys.platform == "win32" else ctypes.CDLL  # pyright: ignore[reportAttributeAccessIssue]
        try:
            self.lib = loader(path)
            self.lib.libusb_init  # noqa: B018 - FreeBSD's libusb.so may be libusb 0.1 only
        except (OSError, AttributeError) as e:
            raise UsbError(f"libusb-1.0 could not be loaded from {path}: {e}") from e
        _setup_prototypes(self.lib)
        self.context = c_void_p()
        check("Initializing libusb", self.lib.libusb_init(byref(self.context)))


_library: Optional[_Library] = None


def library() -> _Library:
    """libusb-1.0, loaded and initialized on first use; never exited, as the process may use it until it ends."""
    global _library
    if _library is None:
        _library = _Library()
    return _library


def error_name(code: int) -> str:
    name = library().lib.libusb_error_name(code)
    return name.decode() if name else f"libusb error {code}"


def _hint(code: int) -> str:
    if code == LIBUSB_ERROR_ACCESS and sys.platform.startswith("linux"):
        return " (no permission to open it: run as root, or add a udev rule giving your user access)"
    if code == LIBUSB_ERROR_NOT_SUPPORTED and sys.platform == "win32":
        return " (it needs the WinUSB driver, e.g. installed with Zadig)"
    if code == LIBUSB_ERROR_NO_DEVICE:
        return " (the device is gone: disconnected or re-enumerated)"
    if code == LIBUSB_ERROR_PIPE:
        return " (the device stalled the request)"
    return ""


def check(operation: str, code: int) -> int:
    """``code`` if libusb succeeded; a ``UsbError`` carrying it otherwise."""
    if code < 0:
        raise UsbError(f"{operation} failed: {error_name(code)}{_hint(code)}", code)
    return code
