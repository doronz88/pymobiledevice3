"""pyusb access, USB constants and the USB product IDs of Apple's boot modes."""

from array import array
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional, Protocol, Union

from usb.core import USBError

if TYPE_CHECKING:
    # pyusb (usb.core / usb.util) ships no type information, so its symbols resolve as
    # partially-unknown. Declare precise signatures for type checking while importing the real
    # implementations at runtime.
    def find(find_all: bool = False, backend: Any = None, custom_match: Any = None, **args: Any) -> Any: ...
    def get_string(dev: "UsbDevice", index: int, langid: Optional[int] = None) -> Optional[str]: ...
    def dispose_resources(device: "UsbDevice") -> None: ...

else:
    from usb.core import find
    from usb.util import dispose_resources, get_string

__all__ = [
    "APPLE_VENDOR_ID",
    "USB_TIMEOUT",
    "Mode",
    "USBError",
    "UsbDevice",
    "dispose_resources",
    "find",
    "get_string",
]

APPLE_VENDOR_ID = 0x05AC
USB_TIMEOUT = 10000  # milliseconds


class UsbConfiguration(Protocol):
    @property
    def bConfigurationValue(self) -> int: ...


class UsbDevice(Protocol):
    """The parts of pyusb's ``usb.core.Device`` used here (pyusb ships no type information)."""

    @property
    def idVendor(self) -> int: ...

    @property
    def idProduct(self) -> int: ...

    @property
    def serial_number(self) -> Optional[str]: ...

    def ctrl_transfer(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data_or_wLength: Union[None, int, bytes] = None,
        timeout: Optional[int] = None,
    ) -> Union["array[int]", int]:
        """Return the bytes read for a device-to-host request, the number of bytes written otherwise."""
        ...

    def write(self, endpoint: int, data: bytes, timeout: Optional[int] = None) -> int: ...

    def reset(self) -> None: ...

    def get_active_configuration(self) -> UsbConfiguration: ...

    def set_configuration(self, configuration: Optional[int] = None) -> None: ...

    def set_interface_altsetting(
        self, interface: Optional[int] = None, alternate_setting: Optional[int] = None
    ) -> None: ...


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
