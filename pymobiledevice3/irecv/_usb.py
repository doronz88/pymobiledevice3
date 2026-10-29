"""USB constants and the USB product IDs of Apple's boot modes."""

from enum import Enum
from typing import Optional

from pymobiledevice3.usb import UsbDevice, UsbError, list_devices

# the name this error had when pyusb was the backend
USBError = UsbError

__all__ = [
    "APPLE_VENDOR_ID",
    "KIS_PRODUCT_ID",
    "USB_TIMEOUT",
    "Mode",
    "USBError",
    "UsbDevice",
    "list_devices",
]

APPLE_VENDOR_ID = 0x05AC
USB_TIMEOUT = 10000  # milliseconds
# A16 and later in DFU mode enumerate as a Debug USB ("KIS") device and report their mode through it
KIS_PRODUCT_ID = 0x1881


class Mode(Enum):
    """A boot mode, identified by the USB product ID the device enumerates with in it."""

    RECOVERY_MODE_1 = 0x1280
    RECOVERY_MODE_2 = 0x1281
    RECOVERY_MODE_3 = 0x1282
    RECOVERY_MODE_4 = 0x1283
    WTF_MODE = 0x1222
    DFU_MODE = 0x1227

    @classmethod
    def has_value(cls, value: int) -> bool:
        return any(value == m.value for m in cls)

    @classmethod
    def get_mode_from_value(cls, value: int) -> Optional["Mode"]:
        for m in cls:
            if value == m.value:
                return m
        return None

    @property
    def is_recovery(self) -> bool:
        return self not in (Mode.WTF_MODE, Mode.DFU_MODE)
