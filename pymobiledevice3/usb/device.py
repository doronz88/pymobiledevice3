"""What a USB device backend provides, and the error it raises."""

from typing import Optional, Protocol

from pymobiledevice3.exceptions import PyMobileDevice3Exception

# the default timeout pyusb had, used when a call passes ``timeout=None``
DEFAULT_TIMEOUT = 1000  # milliseconds


class UsbError(PyMobileDevice3Exception):
    """A USB operation failed."""

    def __init__(self, message: str, code: Optional[int] = None) -> None:
        super().__init__(message)
        # the backend's own error code (an IOReturn on macOS, a libusb error elsewhere), when there is one
        self.code = code


class UsbDevice(Protocol):
    """One USB device, as found by ``pymobiledevice3.usb.list_devices``.

    It is opened on first use and must be ``close``d; after a ``reset`` it has gone away and is only good for
    ``close``.
    """

    @property
    def idVendor(self) -> int: ...

    @property
    def idProduct(self) -> int: ...

    @property
    def serial_number(self) -> Optional[str]: ...

    def get_string(self, index: int) -> Optional[str]:
        """The string descriptor ``index`` in the device's first language."""
        ...

    def control_in(
        self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, length: int, timeout: Optional[int] = None
    ) -> bytes:
        """A device-to-host control request reading up to ``length`` bytes."""
        ...

    def control_out(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data: bytes = b"",
        timeout: Optional[int] = None,
    ) -> int:
        """A host-to-device control request; return the number of bytes of ``data`` written."""
        ...

    def write(self, endpoint: int, data: bytes, timeout: Optional[int] = None) -> int:
        """A bulk write to ``endpoint``, claiming the interface it belongs to."""
        ...

    def read(self, endpoint: int, size: int, timeout: Optional[int] = None) -> bytes:
        """A bulk read of up to ``size`` bytes from ``endpoint`` (an IN address), claiming its interface."""
        ...

    def wait_until_gone(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds for the device to leave the bus; return whether it did."""
        ...

    def reset(self) -> None:
        """Reset the device; it re-enumerates, so this handle is done."""
        ...

    def get_configuration(self) -> int: ...

    def set_configuration(self, configuration: int) -> None: ...

    def set_interface_altsetting(self, interface: int, alternate_setting: int) -> None: ...

    def close(self) -> None: ...
