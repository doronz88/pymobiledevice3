"""
Devices in DFU mode behind Debug USB (KIS) on macOS, through ``deviceinterfaced``.

An A16-or-later device in DFU mode enumerates as a Debug USB device whose IOKit user clients require a private
entitlement, so neither IOKit nor libusb can open it from here, root or not. ``deviceinterfaced`` holds it and serves
it to any client over XPC; MobileDevice.framework restores through it the same way (``taDFU_KISDaemon_*``). This
module calls the client API of DeviceInterface.framework that does so.
"""

import ctypes
import os
import sys
import tempfile
import time
from ctypes import c_bool, c_uint32, c_uint64, c_void_p
from typing import Any, NamedTuple, Optional, cast

from pymobiledevice3.usb.device import UsbError

if sys.platform == "darwin":
    from pymobiledevice3.usb import _iokit

_FRAMEWORK = "/Library/Apple/System/Library/PrivateFrameworks/DeviceInterface.framework/DeviceInterface"
_LIBC = "/usr/lib/libc.dylib"

_FIELDS = (
    "TADFU_Device_InterfaceID",
    "TADFU_Device_LocationID",
    "TADFU_Device_ProductID",
    "TADFU_Device_Serial_Number_String",
    "TADFU_Device_Nonce_String",
    "TADFU_Device_Payload_Base_Address",
    "TADFU_Device_Payload_Capacity",
)
# how often wait_until_gone asks deviceinterfaced
_GONE_POLL_INTERVAL = 0.1


class DfuInterface(NamedTuple):
    """One device in DFU mode behind KIS, as ``deviceinterfaced`` describes it."""

    interface_id: int
    location_id: int
    product_id: int
    # what the USB serial number and string descriptor carry for a device not behind KIS
    serial_number: str
    nonces: str
    payload_base_address: int
    payload_capacity: int


def _parse(device: dict[str, Any]) -> Optional[DfuInterface]:
    """``None`` for an entry missing fields, as one is for a moment while its device leaves."""
    if not all(key in device for key in _FIELDS):
        return None
    return DfuInterface(
        interface_id=int(device["TADFU_Device_InterfaceID"]),
        location_id=int(device["TADFU_Device_LocationID"]),
        product_id=int(device["TADFU_Device_ProductID"]),
        # both strings start with a space
        serial_number=str(device["TADFU_Device_Serial_Number_String"]).strip(),
        nonces=str(device["TADFU_Device_Nonce_String"]).strip(),
        payload_base_address=int(device["TADFU_Device_Payload_Base_Address"]),
        payload_capacity=int(device["TADFU_Device_Payload_Capacity"]),
    )


class DeviceInterfaceClient:
    """A connection to ``deviceinterfaced``'s DFU transport server (``com.apple.deviceinterfaced.tadfu-transport-server``)."""

    def __init__(self) -> None:
        try:
            self._lib = ctypes.CDLL(_FRAMEWORK)
        except OSError as e:
            raise UsbError(f"DeviceInterface.framework is not available: {e}") from e
        self._lib.tadfu_transport_client_usable.restype = c_bool
        self._lib.tadfu_transport_client_create_with_device_discovery_callbacks.restype = c_void_p
        self._lib.tadfu_transport_client_create_with_device_discovery_callbacks.argtypes = [c_void_p] * 4
        self._lib.tadfu_transport_client_copy_all_devices_information.restype = c_void_p
        self._lib.tadfu_transport_client_copy_all_devices_information.argtypes = [c_void_p]
        self._lib.tadfu_transport_client_download_data.restype = c_bool
        self._lib.tadfu_transport_client_download_data.argtypes = [c_void_p, c_uint64, c_uint64, c_void_p]
        self._lib.tadfu_transport_client_complete_dfu.restype = c_bool
        self._lib.tadfu_transport_client_complete_dfu.argtypes = [c_void_p, c_uint64, c_uint32]
        if not self._lib.tadfu_transport_client_usable():
            raise UsbError("This macOS version's deviceinterfaced does not serve devices in DFU mode behind KIS.")
        # no discovery callbacks: devices are listed on demand
        self._client = self._lib.tadfu_transport_client_create_with_device_discovery_callbacks(None, None, None, None)
        if not self._client:
            raise UsbError("Could not connect to deviceinterfaced.")
        self._libc = ctypes.CDLL(_LIBC)
        self._libc.fdopen.restype = c_void_p
        self._libc.fdopen.argtypes = [ctypes.c_int, ctypes.c_char_p]
        self._libc.fclose.argtypes = [c_void_p]

    def _entries(self) -> list[dict[str, Any]]:
        information = self._lib.tadfu_transport_client_copy_all_devices_information(self._client)
        if not information:
            return []
        try:
            devices = _iokit.cf_to_python(information)
        finally:
            _iokit.cf_release(information)
        if not isinstance(devices, dict):
            return []
        # keyed by interface ID
        return list(cast(dict[Any, dict[str, Any]], devices).values())

    def devices(self) -> list[DfuInterface]:
        return [device for entry in self._entries() if (device := _parse(entry)) is not None]

    def is_connected(self, interface_id: int) -> bool:
        return any(entry.get("TADFU_Device_InterfaceID") == interface_id for entry in self._entries())

    def wait_until_gone(self, interface_id: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while self.is_connected(interface_id):
            if time.monotonic() >= deadline:
                return False
            time.sleep(_GONE_POLL_INTERVAL)
        return True

    def download(self, device: DfuInterface, data: bytes) -> None:
        """Load ``data`` into the device's payload area."""
        if len(data) > device.payload_capacity:
            raise UsbError(
                f"The image ({len(data)} bytes) does not fit the device's payload area ({device.payload_capacity} bytes)."
            )
        # deviceinterfaced reads the image from a file descriptor passed to it over XPC
        with tempfile.TemporaryFile() as image:
            image.write(data)
            image.flush()
            image.seek(0)
            stream = self._libc.fdopen(os.dup(image.fileno()), b"rb")
            if not stream:
                raise UsbError("Could not open the image for deviceinterfaced.")
            try:
                if not self._lib.tadfu_transport_client_download_data(
                    self._client, device.interface_id, device.payload_base_address, stream
                ):
                    raise UsbError("deviceinterfaced failed to load the image into the device in DFU mode.")
            finally:
                self._libc.fclose(stream)

    def complete_dfu(self, device: DfuInterface, size: int) -> None:
        """Boot the ``size`` bytes loaded into the device's payload area."""
        if not self._lib.tadfu_transport_client_complete_dfu(self._client, device.interface_id, size):
            raise UsbError("deviceinterfaced failed to boot the image on the device in DFU mode.")


_client: Optional[DeviceInterfaceClient] = None


def client() -> DeviceInterfaceClient:
    """The process' connection to ``deviceinterfaced``, made on first use."""
    global _client
    if _client is None:
        _client = DeviceInterfaceClient()
    return _client
