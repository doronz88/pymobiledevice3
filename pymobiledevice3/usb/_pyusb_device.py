"""USB devices through pyusb (libusb), translating its errors to ``UsbError``."""

import contextlib
import time
from collections.abc import Generator
from typing import TYPE_CHECKING, Any, Optional, cast

from usb.core import USBError

from pymobiledevice3.usb.device import UsbError

if TYPE_CHECKING:
    # pyusb ships no type information; declare the signatures used here
    def find(find_all: bool = False, backend: Any = None, custom_match: Any = None, **args: Any) -> Any: ...
    def get_string(dev: Any, index: int, langid: Optional[int] = None) -> Optional[str]: ...
    def dispose_resources(device: Any) -> None: ...

else:
    from usb.core import find
    from usb.util import dispose_resources, get_string

# how often wait_until_gone scans the bus
_GONE_POLL_INTERVAL = 0.1


@contextlib.contextmanager
def _translated(operation: str) -> Generator[None, None, None]:
    try:
        yield
    except USBError as e:
        code = cast(Optional[int], getattr(e, "backend_error_code", None))
        raise UsbError(f"{operation} failed: {e}", code) from e


class PyUsbDevice:
    """A pyusb ``usb.core.Device``."""

    def __init__(self, device: Any) -> None:
        self._device = device

    def __repr__(self) -> str:
        return f"<PyUsbDevice {self.idVendor:04x}:{self.idProduct:04x}>"

    @property
    def idVendor(self) -> int:
        return cast(int, self._device.idVendor)

    @property
    def idProduct(self) -> int:
        return cast(int, self._device.idProduct)

    @property
    def serial_number(self) -> Optional[str]:
        with _translated("Reading the USB serial number"):
            return cast(Optional[str], self._device.serial_number)

    def get_string(self, index: int) -> Optional[str]:
        with _translated(f"Reading USB string descriptor {index}"):
            return get_string(self._device, index)

    def control_in(
        self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, length: int, timeout: Optional[int] = None
    ) -> bytes:
        with _translated(f"USB control request {bmRequestType:#04x}/{bRequest:#04x}"):
            return bytes(
                self._device.ctrl_transfer(
                    bmRequestType, bRequest, wValue, wIndex, data_or_wLength=length, timeout=timeout
                )
            )

    def control_out(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data: bytes = b"",
        timeout: Optional[int] = None,
    ) -> int:
        with _translated(f"USB control request {bmRequestType:#04x}/{bRequest:#04x}"):
            return cast(
                int,
                self._device.ctrl_transfer(
                    bmRequestType, bRequest, wValue, wIndex, data_or_wLength=data, timeout=timeout
                ),
            )

    def write(self, endpoint: int, data: bytes, timeout: Optional[int] = None) -> int:
        with _translated(f"USB write to endpoint {endpoint:#04x}"):
            return cast(int, self._device.write(endpoint, data, timeout=timeout))

    def read(self, endpoint: int, size: int, timeout: Optional[int] = None) -> bytes:
        with _translated(f"USB read from endpoint {endpoint:#04x}"):
            return bytes(self._device.read(endpoint, size, timeout=timeout))

    def wait_until_gone(self, timeout: float) -> bool:
        location = (self._device.bus, self._device.address)
        deadline = time.monotonic() + timeout
        while True:
            with _translated("Listing USB devices"):
                present = any((device.bus, device.address) == location for device in find(find_all=True))
            if not present:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(_GONE_POLL_INTERVAL)

    def reset(self) -> None:
        with _translated("USB reset"):
            self._device.reset()

    def get_configuration(self) -> int:
        with _translated("Reading the USB configuration"):
            return cast(int, self._device.get_active_configuration().bConfigurationValue)

    def set_configuration(self, configuration: int) -> None:
        with _translated(f"Setting USB configuration {configuration}"):
            self._device.set_configuration(configuration=configuration)

    def set_interface_altsetting(self, interface: int, alternate_setting: int) -> None:
        with _translated(f"Selecting alternate setting {alternate_setting} of USB interface {interface}"):
            self._device.set_interface_altsetting(interface=interface, alternate_setting=alternate_setting)

    def close(self) -> None:
        # release the libusb handle now rather than when the Device is garbage collected
        dispose_resources(self._device)


def list_devices() -> list[PyUsbDevice]:
    with _translated("Listing USB devices"):
        return [PyUsbDevice(device) for device in find(find_all=True)]
