"""
USB devices through IOKit's user-space USB interfaces (``IOUSBDeviceInterface320``/``IOUSBInterfaceInterface300``).

The behavior follows what pyusb over libusb does on macOS, so callers see no difference: the device is opened with
``USBDeviceOpenSeize`` on first use, an interface is claimed (opened) before a class/standard request addressed to
it and before a bulk transfer on one of its endpoints, and a reset re-enumerates the device and waits for the old one
to go away. Unlike libusb, IOKit also lists devices that Apple's drivers hold, such as an A16-or-later device in DFU
mode (Debug USB / KIS).
"""

import ctypes
import time
from ctypes import POINTER, Structure, byref, c_int32, c_uint8, c_uint16, c_uint32, c_void_p
from typing import Any, Optional

from pymobiledevice3.usb import _iokit
from pymobiledevice3.usb.device import DEFAULT_TIMEOUT, UsbError

_DEVICE_USER_CLIENT_TYPE = _iokit.uuid(
    0x9D, 0xC7, 0xB7, 0x80, 0x9E, 0xC0, 0x11, 0xD4, 0xA5, 0x4F, 0x00, 0x0A, 0x27, 0x05, 0x28, 0x61
)  # fmt: skip
_INTERFACE_USER_CLIENT_TYPE = _iokit.uuid(
    0x2D, 0x97, 0x86, 0xC6, 0x9E, 0xF3, 0x11, 0xD4, 0xAD, 0x51, 0x00, 0x0A, 0x27, 0x05, 0x28, 0x61
)  # fmt: skip
_DEVICE_INTERFACE_320 = _iokit.uuid(
    0x01, 0xA2, 0xD0, 0xE9, 0x42, 0xF6, 0x4A, 0x87, 0x8B, 0x8B, 0x77, 0x05, 0x7C, 0x8C, 0xE0, 0xCE
)  # fmt: skip
_INTERFACE_INTERFACE_300 = _iokit.uuid(
    0xBC, 0xEA, 0xAD, 0xDC, 0x88, 0x4D, 0x4F, 0x27, 0x83, 0x40, 0x36, 0xD6, 0x9F, 0xAB, 0x90, 0xF6
)  # fmt: skip

# IOUSBDeviceInterface320 vtable slots (offsetof() / sizeof(void *) in the SDK's IOUSBLib.h)
_DEV_CLOSE = 9
_DEV_GET_CONFIGURATION = 22
_DEV_SET_CONFIGURATION = 23
_DEV_CREATE_INTERFACE_ITERATOR = 28
_DEV_OPEN_SEIZE = 29
_DEV_REQUEST_TO = 30
_DEV_REENUMERATE = 37
# IOUSBInterfaceInterface300 vtable slots
_INTF_OPEN = 8
_INTF_CLOSE = 9
_INTF_GET_INTERFACE_NUMBER = 17
_INTF_GET_NUM_ENDPOINTS = 19
_INTF_SET_ALTERNATE_INTERFACE = 22
_INTF_GET_PIPE_PROPERTIES = 26
_INTF_READ_PIPE_TO = 39
_INTF_WRITE_PIPE_TO = 40

_IO_RETURN_EXCLUSIVE_ACCESS = 0xE00002C5
_IO_RETURN_NOT_OPEN = 0xE00002CD
_IO_RETURN_NO_DEVICE = 0xE00002C0
_IO_RETURN_UNDERRUN = 0xE00002E7
_IO_USB_PIPE_STALLED = 0xE000404F
_IO_USB_TRANSACTION_TIMEOUT = 0xE0004051
_USB_IN = 1

_REQUEST_DIRECTION_IN = 0x80
_REQUEST_RECIPIENT_MASK = 0x03
_REQUEST_RECIPIENT_INTERFACE = 0x01
_REQUEST_TYPE_MASK = 0x60
_REQUEST_TYPE_VENDOR = 0x40
_GET_DESCRIPTOR = 6
_STRING_DESCRIPTOR = 3

# how long a reset may take to make the old device go away (libusb's DARWIN_REENUMERATE_TIMEOUT_US)
_REENUMERATE_TIMEOUT = 10.0
_REENUMERATE_POLL_INTERVAL = 0.001


class _DevRequestTO(Structure):
    _fields_ = [
        ("bmRequestType", c_uint8),
        ("bRequest", c_uint8),
        ("wValue", c_uint16),
        ("wIndex", c_uint16),
        ("wLength", c_uint16),
        ("pData", c_void_p),
        ("wLenDone", c_uint32),
        ("noDataTimeout", c_uint32),
        ("completionTimeout", c_uint32),
    ]


class _FindInterfaceRequest(Structure):
    _fields_ = [
        ("bInterfaceClass", c_uint16),
        ("bInterfaceSubClass", c_uint16),
        ("bInterfaceProtocol", c_uint16),
        ("bAlternateSetting", c_uint16),
    ]


_DONT_CARE = 0xFFFF


def _describe(kern_return: int) -> str:
    code = kern_return & 0xFFFFFFFF
    if code == _IO_RETURN_EXCLUSIVE_ACCESS:
        return "another process has the device open (on macOS, usually deviceinterfaced)"
    if code == _IO_RETURN_NOT_OPEN:
        return "the device could not be opened (another process may hold it, usually deviceinterfaced)"
    if code == _IO_RETURN_NO_DEVICE:
        return "the device is gone (disconnected or re-enumerated)"
    if code == _IO_USB_PIPE_STALLED:
        return "the device stalled the request"
    if code == _IO_USB_TRANSACTION_TIMEOUT:
        return "timed out"
    return f"IOReturn {code:#x}"


class _Interface:
    """An opened (claimed) interface and its endpoints by address."""

    def __init__(self, interface: c_void_p) -> None:
        self.interface = interface
        self.pipes: dict[int, int] = {}
        self.refresh_pipes()

    def call(self, slot: int, argtypes: list[Any], *args: Any) -> int:
        return _iokit.com_call(self.interface, slot, c_int32, argtypes, *args) & 0xFFFFFFFF

    def refresh_pipes(self) -> None:
        count = c_uint8()
        self.call(_INTF_GET_NUM_ENDPOINTS, [POINTER(c_uint8)], byref(count))
        self.pipes = {}
        for pipe_ref in range(1, count.value + 1):
            direction, number, transfer_type, interval = c_uint8(), c_uint8(), c_uint8(), c_uint8()
            max_packet_size = c_uint16()
            kr = self.call(
                _INTF_GET_PIPE_PROPERTIES,
                [c_uint8, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint16), POINTER(c_uint8)],
                pipe_ref,
                byref(direction),
                byref(number),
                byref(transfer_type),
                byref(max_packet_size),
                byref(interval),
            )
            if kr == 0:
                self.pipes[number.value | (0x80 if direction.value == _USB_IN else 0)] = pipe_ref

    def close(self) -> None:
        self.call(_INTF_CLOSE, [])
        _iokit.release(self.interface)


class IOKitUsbDevice:
    """A USB device found in the IORegistry (an ``IOUSBHostDevice``)."""

    def __init__(self, service: int, vendor_id: int, product_id: int, serial_number: Optional[str]) -> None:
        # the caller hands over its reference to ``service``
        self._service = service
        self._vendor_id = vendor_id
        self._product_id = product_id
        self._serial_number = serial_number
        self._device: Optional[c_void_p] = None
        self._seized = False
        self._interfaces: dict[int, _Interface] = {}
        self._closed = False

    def __repr__(self) -> str:
        return f"<IOKitUsbDevice {self._vendor_id:04x}:{self._product_id:04x} {self._serial_number!r}>"

    @property
    def idVendor(self) -> int:
        return self._vendor_id

    @property
    def idProduct(self) -> int:
        return self._product_id

    @property
    def serial_number(self) -> Optional[str]:
        # IOKit reads it at enumeration, so the device needn't be opened as it would be with libusb
        return self._serial_number

    def _open(self) -> c_void_p:
        if self._closed:
            raise UsbError("The USB device was closed.")
        if self._device is None:
            try:
                self._device = _iokit.create_interface(self._service, _DEVICE_USER_CLIENT_TYPE, _DEVICE_INTERFACE_320)
            except _iokit.IOKitError as e:
                raise UsbError(f"Could not reach the USB device: {_describe(e.kern_return)}", e.kern_return) from e
            kr = _iokit.com_call(self._device, _DEV_OPEN_SEIZE, c_int32, []) & 0xFFFFFFFF
            if kr == 0:
                self._seized = True
            elif kr != _IO_RETURN_EXCLUSIVE_ACCESS:
                # like libusb, carry on without exclusive access: some requests still work
                raise UsbError(f"Could not open the USB device: {_describe(kr)}", kr)
        return self._device

    def _call(self, slot: int, argtypes: list[Any], *args: Any) -> int:
        return _iokit.com_call(self._open(), slot, c_int32, argtypes, *args) & 0xFFFFFFFF

    def _check(self, operation: str, kern_return: int) -> None:
        if kern_return not in (0, _IO_RETURN_UNDERRUN):
            raise UsbError(f"{operation} failed: {_describe(kern_return)}", kern_return)

    def _interface_services(self) -> list[int]:
        """The device's interface services in its current configuration; the caller releases them."""
        request = _FindInterfaceRequest(_DONT_CARE, _DONT_CARE, _DONT_CARE, _DONT_CARE)
        iterator = c_uint32()
        self._check(
            "Listing the USB interfaces",
            self._call(
                _DEV_CREATE_INTERFACE_ITERATOR,
                [POINTER(_FindInterfaceRequest), POINTER(c_uint32)],
                byref(request),
                byref(iterator),
            ),
        )
        return _iokit.iterator_objects(iterator.value)

    def _interface_numbers(self) -> list[int]:
        services = self._interface_services()
        try:
            return sorted(
                number
                for service in services
                if isinstance(number := _iokit.get_property(service, "bInterfaceNumber"), int)
            )
        finally:
            for service in services:
                _iokit.release_object(service)

    def _claim(self, number: int) -> _Interface:
        claimed = self._interfaces.get(number)
        if claimed is not None:
            return claimed
        services = self._interface_services()
        try:
            for service in services:
                if _iokit.get_property(service, "bInterfaceNumber") != number:
                    continue
                try:
                    interface = _iokit.create_interface(service, _INTERFACE_USER_CLIENT_TYPE, _INTERFACE_INTERFACE_300)
                except _iokit.IOKitError as e:
                    raise UsbError(
                        f"Could not reach USB interface {number}: {_describe(e.kern_return)}", e.kern_return
                    ) from e
                kr = _iokit.com_call(interface, _INTF_OPEN, c_int32, []) & 0xFFFFFFFF
                if kr != 0:
                    _iokit.release(interface)
                    raise UsbError(f"Could not claim USB interface {number}: {_describe(kr)}", kr)
                claimed = _Interface(interface)
                self._interfaces[number] = claimed
                return claimed
        finally:
            for service in services:
                _iokit.release_object(service)
        raise UsbError(f"The USB device has no interface {number}.")

    def _release_interfaces(self) -> None:
        for interface in self._interfaces.values():
            interface.close()
        self._interfaces = {}

    def get_string(self, index: int) -> Optional[str]:
        # as pyusb: the first language from string descriptor 0, then the string in it
        languages = self.control_in(_REQUEST_DIRECTION_IN, _GET_DESCRIPTOR, _STRING_DESCRIPTOR << 8, 0, 255)
        if len(languages) < 4:
            return None
        language = languages[2] | (languages[3] << 8)
        descriptor = self.control_in(
            _REQUEST_DIRECTION_IN, _GET_DESCRIPTOR, (_STRING_DESCRIPTOR << 8) | index, language, 255
        )
        if len(descriptor) < 2:
            return None
        return descriptor[2 : descriptor[0]].decode("utf-16-le")

    def control_in(
        self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, length: int, timeout: Optional[int] = None
    ) -> bytes:
        buffer = ctypes.create_string_buffer(max(length, 1))
        received = self._control(bmRequestType, bRequest, wValue, wIndex, buffer, length, timeout)
        return buffer.raw[:received]

    def control_out(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data: bytes = b"",
        timeout: Optional[int] = None,
    ) -> int:
        buffer = ctypes.create_string_buffer(bytes(data), max(len(data), 1))
        return self._control(bmRequestType, bRequest, wValue, wIndex, buffer, len(data), timeout)

    def _control(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int,
        wIndex: int,
        buffer: "ctypes.Array[ctypes.c_char]",
        length: int,
        timeout: Optional[int],
    ) -> int:
        """Run a control request on ``length`` bytes of ``buffer``; return how many were transferred."""
        if (
            bmRequestType & _REQUEST_RECIPIENT_MASK == _REQUEST_RECIPIENT_INTERFACE
            and bmRequestType & _REQUEST_TYPE_MASK != _REQUEST_TYPE_VENDOR
        ):
            # pyusb claims the interface a class/standard request is addressed to
            self._claim(wIndex & 0xFF)
        timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        request = _DevRequestTO(
            bmRequestType,
            bRequest,
            wValue,
            wIndex,
            length,
            ctypes.cast(buffer, c_void_p) if length else None,
            0,
            timeout,
            timeout,
        )
        self._check(
            f"USB control request {bmRequestType:#04x}/{bRequest:#04x}",
            self._call(_DEV_REQUEST_TO, [POINTER(_DevRequestTO)], byref(request)),
        )
        return request.wLenDone

    def _owner(self, endpoint: int) -> _Interface:
        """The claimed interface ``endpoint`` belongs to."""
        for interface in self._interfaces.values():
            if endpoint in interface.pipes:
                return interface
        # as pyusb: claim the interface the endpoint belongs to
        for number in self._interface_numbers():
            if number not in self._interfaces and endpoint in self._claim(number).pipes:
                return self._interfaces[number]
        raise UsbError(f"The USB device has no endpoint {endpoint:#04x} in its current settings.")

    def write(self, endpoint: int, data: bytes, timeout: Optional[int] = None) -> int:
        target = self._owner(endpoint)
        timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        buffer = ctypes.create_string_buffer(bytes(data), max(len(data), 1))
        kr = target.call(
            _INTF_WRITE_PIPE_TO,
            [c_uint8, c_void_p, c_uint32, c_uint32, c_uint32],
            target.pipes[endpoint],
            ctypes.cast(buffer, c_void_p) if data else None,
            len(data),
            timeout,
            timeout,
        )
        self._check(f"USB write to endpoint {endpoint:#04x}", kr)
        return len(data)

    def read(self, endpoint: int, size: int, timeout: Optional[int] = None) -> bytes:
        source = self._owner(endpoint)
        timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        buffer = ctypes.create_string_buffer(max(size, 1))
        received = c_uint32(size)
        kr = source.call(
            _INTF_READ_PIPE_TO,
            [c_uint8, c_void_p, POINTER(c_uint32), c_uint32, c_uint32],
            source.pipes[endpoint],
            ctypes.cast(buffer, c_void_p),
            byref(received),
            timeout,
            timeout,
        )
        self._check(f"USB read from endpoint {endpoint:#04x}", kr)
        return buffer.raw[: received.value]

    def wait_until_gone(self, timeout: float) -> bool:
        try:
            entry_id = _iokit.registry_entry_id(self._service)
        except _iokit.IOKitError:
            # no longer in the registry
            return True
        deadline = time.monotonic() + timeout
        while _iokit.is_registered(entry_id):
            if time.monotonic() >= deadline:
                return False
            time.sleep(_REENUMERATE_POLL_INTERVAL)
        return True

    def reset(self) -> None:
        self._check("USB re-enumeration", self._call(_DEV_REENUMERATE, [c_uint32], 0))
        # as libusb, wait for the device to leave so the next lookup cannot find it again
        self.wait_until_gone(_REENUMERATE_TIMEOUT)
        self.close()

    def get_configuration(self) -> int:
        configuration = c_uint8()
        self._check(
            "Reading the USB configuration",
            self._call(_DEV_GET_CONFIGURATION, [POINTER(c_uint8)], byref(configuration)),
        )
        return configuration.value

    def set_configuration(self, configuration: int) -> None:
        # setting a configuration invalidates the interfaces, so claim them again afterwards as libusb does
        claimed = list(self._interfaces)
        self._release_interfaces()
        self._check(
            f"Setting USB configuration {configuration}",
            self._call(_DEV_SET_CONFIGURATION, [c_uint8], configuration),
        )
        for number in claimed:
            self._claim(number)

    def set_interface_altsetting(self, interface: int, alternate_setting: int) -> None:
        claimed = self._claim(interface)
        kr = claimed.call(_INTF_SET_ALTERNATE_INTERFACE, [c_uint8], alternate_setting)
        # an interface with only a default setting may stall the request; libusb takes that as success
        if kr != _IO_USB_PIPE_STALLED:
            self._check(f"Selecting alternate setting {alternate_setting} of USB interface {interface}", kr)
        claimed.refresh_pipes()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._release_interfaces()
        if self._device is not None:
            if self._seized:
                _iokit.com_call(self._device, _DEV_CLOSE, c_int32, [])
            _iokit.release(self._device)
            self._device = None
        _iokit.release_object(self._service)


def list_devices() -> list[IOKitUsbDevice]:
    """Every USB device on the host; the caller closes the ones it keeps and the ones it skips."""
    devices: list[IOKitUsbDevice] = []
    with _iokit.matching_services("IOUSBHostDevice") as services:
        for service in services:
            vendor_id = _iokit.get_property(service, "idVendor")
            product_id = _iokit.get_property(service, "idProduct")
            if not isinstance(vendor_id, int) or not isinstance(product_id, int):
                continue
            serial = _iokit.get_property(service, "USB Serial Number")
            # matching_services releases its references when the block ends; each device keeps its own
            _iokit.retain_object(service)
            devices.append(IOKitUsbDevice(service, vendor_id, product_id, serial if isinstance(serial, str) else None))
    return devices
