"""
USB devices through libusb-1.0.

The behavior is pyusb's, which this replaces: the device is opened on first use, an interface is claimed before a
class/standard request addressed to it and before a transfer on one of its endpoints, and the endpoints are looked up
in the active configuration under each interface's current alternate setting.
"""

import ctypes
import time
from ctypes import POINTER, byref, c_int, c_void_p
from typing import Optional

from pymobiledevice3.usb import _libusb
from pymobiledevice3.usb.device import DEFAULT_TIMEOUT, UsbError

_REQUEST_DIRECTION_IN = 0x80
_REQUEST_RECIPIENT_MASK = 0x03
_REQUEST_RECIPIENT_INTERFACE = 0x01
_REQUEST_TYPE_MASK = 0x60
_REQUEST_TYPE_VENDOR = 0x40
_GET_DESCRIPTOR = 6
_STRING_DESCRIPTOR = 3
# what pyusb asks for when reading a string descriptor: the largest even length
_STRING_DESCRIPTOR_SIZE = 254
_ENDPOINT_TYPE_MASK = 0x03
_ENDPOINT_TYPE_INTERRUPT = 0x03

# how often wait_until_gone scans the bus
_GONE_POLL_INTERVAL = 0.1


def _device_list() -> list[tuple[int, int, int]]:
    """Every device on the bus as (referenced ``libusb_device *``, bus, address); the caller unrefs each one."""
    library = _libusb.library()
    devices = POINTER(c_void_p)()
    count = _libusb.check("Listing USB devices", library.lib.libusb_get_device_list(library.context, byref(devices)))
    try:
        listed: list[tuple[int, int, int]] = []
        for i in range(count):
            device = library.lib.libusb_ref_device(devices[i])
            listed.append((
                device,
                library.lib.libusb_get_bus_number(device),
                library.lib.libusb_get_device_address(device),
            ))
        return listed
    finally:
        # drop the list's own references; each listed device keeps the one taken above
        library.lib.libusb_free_device_list(devices, 1)


class LibUsbDevice:
    """A ``libusb_device`` and, once used, its ``libusb_device_handle``."""

    def __init__(self, device: int, bus: int, address: int, descriptor: _libusb.DeviceDescriptor) -> None:
        self._lib = _libusb.library().lib
        self._device: Optional[int] = device
        self._bus = bus
        self._address = address
        self._descriptor = descriptor
        self._handle: Optional[int] = None
        self._serial_number: Optional[str] = None
        # the first language of string descriptor 0, read once as pyusb does; None until read, 0 for none
        self._language: Optional[int] = None
        self._configuration: Optional[int] = None
        self._claimed: set[int] = set()
        # the alternate setting selected on each interface, when it is not the default one
        self._altsettings: dict[int, int] = {}
        # endpoint address -> (interface number, endpoint attributes)
        self._endpoints: dict[int, tuple[int, int]] = {}

    def __repr__(self) -> str:
        return f"<LibUsbDevice {self.idVendor:04x}:{self.idProduct:04x} bus {self._bus} address {self._address}>"

    @property
    def idVendor(self) -> int:
        return self._descriptor.idVendor

    @property
    def idProduct(self) -> int:
        return self._descriptor.idProduct

    @property
    def serial_number(self) -> Optional[str]:
        if self._serial_number is None:
            self._serial_number = self.get_string(self._descriptor.iSerialNumber)
        return self._serial_number

    def _open(self) -> int:
        if self._handle is None:
            if self._device is None:
                raise UsbError("The USB device was closed.")
            handle = c_void_p()
            _libusb.check("Opening the USB device", self._lib.libusb_open(self._device, byref(handle)))
            assert handle.value is not None
            self._handle = handle.value
        return self._handle

    def _claim(self, interface: int) -> None:
        handle = self._open()
        if interface not in self._claimed:
            _libusb.check(f"Claiming USB interface {interface}", self._lib.libusb_claim_interface(handle, interface))
            self._claimed.add(interface)

    def _release_interfaces(self) -> None:
        for interface in self._claimed:
            # as pyusb: it may be gone already
            self._lib.libusb_release_interface(self._handle, interface)
        self._claimed = set()

    def _active_configuration(self) -> int:
        if self._configuration is None:
            self._configuration = self.get_configuration()
            if self._configuration == 0:
                self._configuration = None
                raise UsbError("The USB device is not configured.")
        return self._configuration

    def _endpoint(self, endpoint: int) -> tuple[int, int]:
        """The interface ``endpoint`` belongs to, under the current settings, and the endpoint's attributes."""
        if endpoint not in self._endpoints:
            configuration = ctypes.POINTER(_libusb.ConfigDescriptor)()
            _libusb.check(
                "Reading the USB configuration descriptor",
                self._lib.libusb_get_config_descriptor_by_value(
                    self._device, self._active_configuration(), byref(configuration)
                ),
            )
            try:
                for i in range(configuration.contents.bNumInterfaces):
                    interface = configuration.contents.interface[i]
                    for j in range(interface.num_altsetting):
                        setting = interface.altsetting[j]
                        if setting.bAlternateSetting != self._altsettings.get(setting.bInterfaceNumber, 0):
                            continue
                        for k in range(setting.bNumEndpoints):
                            descriptor = setting.endpoint[k]
                            self._endpoints[descriptor.bEndpointAddress] = (
                                setting.bInterfaceNumber,
                                descriptor.bmAttributes,
                            )
            finally:
                self._lib.libusb_free_config_descriptor(configuration)
            if endpoint not in self._endpoints:
                raise UsbError(f"The USB device has no endpoint {endpoint:#04x} in its current settings.")
        return self._endpoints[endpoint]

    def get_string(self, index: int) -> Optional[str]:
        # as pyusb: no string at index 0; otherwise the string in the first language from string descriptor 0
        if index == 0:
            return None
        if self._language is None:
            languages = self.control_in(
                _REQUEST_DIRECTION_IN, _GET_DESCRIPTOR, _STRING_DESCRIPTOR << 8, 0, _STRING_DESCRIPTOR_SIZE
            )
            valid = len(languages) >= 4 and languages[0] >= 4 and not languages[0] & 1
            self._language = languages[2] | (languages[3] << 8) if valid else 0
        if not self._language:
            return None
        descriptor = self.control_in(
            _REQUEST_DIRECTION_IN,
            _GET_DESCRIPTOR,
            (_STRING_DESCRIPTOR << 8) | index,
            self._language,
            _STRING_DESCRIPTOR_SIZE,
        )
        if len(descriptor) < 2:
            raise UsbError(f"USB string descriptor {index} is invalid.")
        # an odd length is ignored, as pyusb does
        return descriptor[2 : descriptor[0] & 0xFE].decode("utf-16-le")

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
        handle = self._open()
        if (
            bmRequestType & _REQUEST_RECIPIENT_MASK == _REQUEST_RECIPIENT_INTERFACE
            and bmRequestType & _REQUEST_TYPE_MASK != _REQUEST_TYPE_VENDOR
        ):
            # as pyusb: claim the interface a class/standard request is addressed to
            self._claim(wIndex & 0xFF)
        return _libusb.check(
            f"USB control request {bmRequestType:#04x}/{bRequest:#04x}",
            self._lib.libusb_control_transfer(
                handle,
                bmRequestType,
                bRequest,
                wValue,
                wIndex,
                buffer,
                length,
                DEFAULT_TIMEOUT if timeout is None else timeout,
            ),
        )

    def _transfer(
        self, operation: str, endpoint: int, buffer: "ctypes.Array[ctypes.c_ubyte]", timeout: Optional[int]
    ) -> int:
        interface, attributes = self._endpoint(endpoint)
        self._claim(interface)
        transfer = (
            self._lib.libusb_interrupt_transfer
            if attributes & _ENDPOINT_TYPE_MASK == _ENDPOINT_TYPE_INTERRUPT
            else self._lib.libusb_bulk_transfer
        )
        transferred = c_int()
        code = transfer(
            self._handle,
            endpoint,
            buffer,
            len(buffer),
            byref(transferred),
            DEFAULT_TIMEOUT if timeout is None else timeout,
        )
        # as pyusb: a transfer that timed out after moving some data returns what it moved
        if not (transferred.value and code == _libusb.LIBUSB_ERROR_TIMEOUT):
            _libusb.check(operation, code)
        return transferred.value

    def write(self, endpoint: int, data: bytes, timeout: Optional[int] = None) -> int:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return self._transfer(f"USB write to endpoint {endpoint:#04x}", endpoint, buffer, timeout)

    def read(self, endpoint: int, size: int, timeout: Optional[int] = None) -> bytes:
        buffer = (ctypes.c_ubyte * size)()
        received = self._transfer(f"USB read from endpoint {endpoint:#04x}", endpoint, buffer, timeout)
        return bytes(buffer[:received])

    def wait_until_gone(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            listed = _device_list()
            for device, _, _ in listed:
                self._lib.libusb_unref_device(device)
            if all((bus, address) != (self._bus, self._address) for _, bus, address in listed):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(_GONE_POLL_INTERVAL)

    def reset(self) -> None:
        handle = self._open()
        self._release_interfaces()
        try:
            _libusb.check("USB reset", self._lib.libusb_reset_device(handle))
        finally:
            self.close()

    def get_configuration(self) -> int:
        configuration = c_int()
        _libusb.check(
            "Reading the USB configuration", self._lib.libusb_get_configuration(self._open(), byref(configuration))
        )
        return configuration.value

    def set_configuration(self, configuration: int) -> None:
        _libusb.check(
            f"Setting USB configuration {configuration}",
            self._lib.libusb_set_configuration(self._open(), configuration),
        )
        self._configuration = configuration
        self._altsettings = {}
        self._endpoints = {}

    def set_interface_altsetting(self, interface: int, alternate_setting: int) -> None:
        self._claim(interface)
        _libusb.check(
            f"Selecting alternate setting {alternate_setting} of USB interface {interface}",
            self._lib.libusb_set_interface_alt_setting(self._handle, interface, alternate_setting),
        )
        self._altsettings[interface] = alternate_setting
        self._endpoints = {}

    def close(self) -> None:
        if self._handle is not None:
            self._release_interfaces()
            self._lib.libusb_close(self._handle)
            self._handle = None
        if self._device is not None:
            self._lib.libusb_unref_device(self._device)
            self._device = None


def list_devices() -> list[LibUsbDevice]:
    """Every USB device on the host; the caller closes the ones it keeps and the ones it skips."""
    library = _libusb.library()
    devices: list[LibUsbDevice] = []
    for device, bus, address in _device_list():
        descriptor = _libusb.DeviceDescriptor()
        code = library.lib.libusb_get_device_descriptor(device, byref(descriptor))
        if code < 0:
            library.lib.libusb_unref_device(device)
            continue
        devices.append(LibUsbDevice(device, bus, address, descriptor))
    return devices
