"""
Host-side USB access that does not go through usbmuxd.

``list_devices`` uses IOKit on macOS and libusb elsewhere. ``PYMOBILEDEVICE3_USB_BACKEND=libusb`` forces libusb on
macOS too, e.g. to compare the two.
"""

import os
import sys

from pymobiledevice3.usb.device import UsbDevice, UsbError

__all__ = ["USB_BACKEND_ENV_VAR", "UsbDevice", "UsbError", "list_devices", "uses_iokit"]

USB_BACKEND_ENV_VAR = "PYMOBILEDEVICE3_USB_BACKEND"
_BACKENDS = ("iokit", "libusb")


def uses_iokit() -> bool:
    """Whether ``list_devices`` goes through IOKit (macOS, unless libusb is forced)."""
    backend = os.environ.get(USB_BACKEND_ENV_VAR)
    if backend is None:
        return sys.platform == "darwin"
    if backend not in _BACKENDS:
        raise UsbError(f"{USB_BACKEND_ENV_VAR} must be one of {', '.join(_BACKENDS)}, not {backend!r}.")
    if backend == "iokit" and sys.platform != "darwin":
        raise UsbError(f"{USB_BACKEND_ENV_VAR}=iokit is only available on macOS.")
    return backend == "iokit"


def list_devices() -> list[UsbDevice]:
    """Every USB device on the host. Close each one you are done with, kept or skipped."""
    # IOKit's module loads the framework on import, so only the backend in use is imported
    if uses_iokit():
        from pymobiledevice3.usb import _iokit_device

        return list(_iokit_device.list_devices())
    from pymobiledevice3.usb import _libusb_device

    return list(_libusb_device.list_devices())
