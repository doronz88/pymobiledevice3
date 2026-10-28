"""Find a device in Recovery/DFU mode over USB and talk to it."""

import contextlib
import logging
import time
from array import array
from collections.abc import Iterable
from types import TracebackType
from typing import TYPE_CHECKING, NamedTuple, Optional, Union, cast

from pymobiledevice3.exceptions import IRecvError, IRecvNoDeviceConnectedError
from pymobiledevice3.irecv._usb import (
    APPLE_VENDOR_ID,
    USB_TIMEOUT,
    Mode,
    UsbDevice,
    USBError,
    dispose_resources,
    find,
    get_string,
)
from pymobiledevice3.irecv.device_info import DeviceInfo, parse_nonce
from pymobiledevice3.irecv.transport import DfuTransport, RecoveryTransport
from pymobiledevice3.irecv_devices import IRecvDevice

if TYPE_CHECKING:
    # IRECV_DEVICES ships no type information
    IRECV_DEVICES: tuple[IRecvDevice, ...]
else:
    from pymobiledevice3.irecv_devices import IRECV_DEVICES

logger = logging.getLogger(__name__)

# pause between USB scans while waiting for a device to show up
_FIND_POLL_INTERVAL = 0.1


class _Found(NamedTuple):
    device: UsbDevice
    mode: Mode
    info: DeviceInfo


def _read_device_info(device: UsbDevice) -> DeviceInfo:
    serial_number = device.serial_number
    if serial_number is None:
        raise IRecvError("The device in Recovery/DFU mode did not report its USB serial number.")
    return DeviceInfo.parse(serial_number)


def _find_device(ecid: Optional[int], timeout: float, is_recovery: Optional[bool]) -> Optional[_Found]:
    """
    Scan USB until a device in Recovery/DFU mode (and ``ecid``, if given) shows up or ``timeout`` passes.

    :raises IRecvError: if no ``ecid`` was given and more than one device is in Recovery/DFU mode.
    """
    end = time.time() + timeout
    while True:
        found: Optional[_Found] = None
        # pyusb ships no types: this is where its Devices are taken to be UsbDevices
        for device in cast(Iterable[UsbDevice], find(find_all=True)):
            # Match on the descriptor fields cached at enumeration. Reading string
            # descriptors (e.g. manufacturer) requires opening the device, which fails
            # for unrelated devices lacking a libusb-compatible driver (e.g. on Windows).
            if device.idVendor != APPLE_VENDOR_ID:
                continue

            mode = Mode.get_mode_from_value(device.idProduct)
            if mode is None:
                # not one of Apple's special modes
                continue

            if is_recovery is not None and mode.is_recovery != is_recovery:
                continue

            if found is not None:
                raise IRecvError("More than one device was found connected in recovery mode; select one by its ECID")

            try:
                info = _read_device_info(device)
                if ecid is not None and info.ecid != ecid:
                    # wrong device - move on
                    dispose_resources(device)
                    continue
            except (ValueError, NotImplementedError, USBError, IRecvError):
                # unreadable device (e.g. missing driver or permissions) - move on
                dispose_resources(device)
                continue

            found = _Found(device, mode, info)
            if ecid is not None:
                # Other devices may be in Recovery/DFU too, e.g. while another restore runs.
                break

        if found is not None or time.time() >= end:
            return found
        time.sleep(_FIND_POLL_INTERVAL)


class IRecv:
    """A device in Recovery, DFU or WTF mode."""

    def __init__(self, ecid: Optional[int] = None, timeout: float = 0xFFFFFFFF, is_recovery: Optional[bool] = None):
        self._device: Optional[UsbDevice] = None
        self._mode: Optional[Mode] = None
        self._info: Optional[DeviceInfo] = None
        self._transport: Optional[Union[RecoveryTransport, DfuTransport]] = None
        self.ap_nonce: Optional[bytes] = None
        self.sep_nonce: Optional[bytes] = None
        self._reinit(ecid=ecid, timeout=timeout, is_recovery=is_recovery)

    @property
    def device(self) -> UsbDevice:
        """The connected USB device.

        :raises IRecvNoDeviceConnectedError: if no device is connected.
        """
        if self._device is None:
            raise IRecvNoDeviceConnectedError("No device in Recovery or DFU mode is connected.")
        return self._device

    @property
    def mode(self) -> Mode:
        """The device's current mode (recovery/DFU/WTF).

        :raises IRecvNoDeviceConnectedError: if no device is connected.
        """
        if self._mode is None:
            raise IRecvNoDeviceConnectedError("No device in Recovery or DFU mode is connected.")
        return self._mode

    @property
    def info(self) -> DeviceInfo:
        """What the device reports in its USB serial number.

        :raises IRecvNoDeviceConnectedError: if no device is connected.
        """
        if self._info is None:
            raise IRecvNoDeviceConnectedError("No device in Recovery or DFU mode is connected.")
        return self._info

    @property
    def ecid(self) -> int:
        return self.info.ecid

    @property
    def ibfl(self) -> int:
        return self.info.ibfl

    @property
    def chip_id(self) -> int:
        return self.info.chip_id

    @property
    def board_id(self) -> int:
        return self.info.board_id

    @property
    def serial_number(self) -> Optional[str]:
        return self.info.serial_number

    @property
    def secure_rom_tag(self) -> Optional[str]:
        return self.info.secure_rom_tag

    @property
    def iboot_version(self) -> Optional[str]:
        """The SRTG field (kept for compatibility; see ``secure_rom_tag``)."""
        return self.info.secure_rom_tag

    @property
    def is_image4_supported(self) -> bool:
        return self.info.is_image4_supported

    @property
    def _irecv_device(self) -> IRecvDevice:
        for device in IRECV_DEVICES:
            if device.board_id == self.board_id and device.chip_id == self.chip_id:
                return device
        raise KeyError(f"failed to find device of: board_id: {self.board_id} chip_id: {self.chip_id}")

    @property
    def product_type(self) -> str:
        return self._irecv_device.product_type

    @property
    def hardware_model(self) -> str:
        return self._irecv_device.hardware_model

    @property
    def display_name(self) -> str:
        return self._irecv_device.display_name

    @property
    def status(self) -> int:
        """The DFU state the device reports (DFU/WTF mode)."""
        return self._dfu_transport().state

    def _current_transport(self) -> Union[RecoveryTransport, DfuTransport]:
        """
        How to talk to the device in its current mode, valid only until it re-enumerates (a reset or a mode change).

        :raises IRecvNoDeviceConnectedError: if no device is connected.
        """
        if self._transport is None:
            raise IRecvNoDeviceConnectedError("No device in Recovery or DFU mode is connected.")
        return self._transport

    def _recovery_transport(self) -> RecoveryTransport:
        transport = self._current_transport()
        if not isinstance(transport, RecoveryTransport):
            raise IRecvError(f"Only a device in Recovery mode takes iBoot commands; this one is in {self.mode.name}.")
        return transport

    def _dfu_transport(self) -> DfuTransport:
        transport = self._current_transport()
        if not isinstance(transport, DfuTransport):
            raise IRecvError(f"Only a device in DFU or WTF mode reports a DFU state; this one is in {self.mode.name}.")
        return transport

    def set_interface_altsetting(self, interface: Optional[int] = None, alternate_setting: Optional[int] = None):
        logger.debug(f"set_interface_altsetting: {interface} {alternate_setting}")
        if interface == 1:
            self.device.set_interface_altsetting(interface=interface, alternate_setting=alternate_setting)

    def set_configuration(self, configuration: Optional[int] = None):
        logger.debug(f"set_configuration: {configuration}")
        device = self.device
        try:
            if device.get_active_configuration().bConfigurationValue == configuration:
                return
        except USBError:
            pass

        device.set_configuration(configuration=configuration)

    def ctrl_transfer(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data_or_wLength: Union[None, int, bytes] = None,
        timeout: int = USB_TIMEOUT,
    ) -> Union["array[int]", int]:
        """A raw control request; see ``UsbDevice.ctrl_transfer``."""
        return self.device.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout=timeout)

    def send_zero_length_download(self, timeout: int = USB_TIMEOUT) -> None:
        """Send an empty DFU DNLOAD request, which iBoot expects after a ``go``/``bootx`` command."""
        self._recovery_transport().send_zero_length_download(timeout=timeout)

    def send_buffer(self, buf: bytes, desc: Optional[str] = None) -> None:
        """Upload ``buf``. In DFU/WTF mode the device then runs it, so it is reset and looked up again."""
        transport = self._current_transport()
        if isinstance(transport, RecoveryTransport):
            transport.upload(buf, desc or "recovery upload")
            return
        transport.upload(buf, desc or "DFU upload")
        self.reset()

    def reset(self) -> None:
        try:
            logger.debug("resetting usb device")
            logger.info("If the restore hangs here, disconnect & reconnect the device")
            self.device.reset()
        except USBError:
            pass

        self._reinit(ecid=self.ecid)

    def send_command(self, cmd: str, timeout: int = USB_TIMEOUT, b_request: int = 0) -> None:
        """
        :raises IRecvError: if the device is not in Recovery mode.
        """
        self._recovery_transport().send_command(cmd, timeout=timeout, b_request=b_request)

    def getenv(self, name: str) -> Optional[bytearray]:
        """Read an iBoot environment variable; ``None`` if the device is not in Recovery mode or the read failed."""
        transport = self._current_transport()
        if not isinstance(transport, RecoveryTransport):
            return None
        try:
            transport.send_command(f"getenv {name}")
        except USBError:
            return None
        return transport.read_command_reply()

    def set_autoboot(self, enable: bool) -> None:
        self.send_command(f"setenv auto-boot {str(enable).lower()}")
        self.send_command("saveenv")

    def reboot(self) -> None:
        """Reboot a device in Recovery mode; a device in DFU mode takes no commands, so it is left as is."""
        if not isinstance(self._current_transport(), RecoveryTransport):
            logger.warning(f"A device in {self.mode.name} takes no commands, so it cannot be rebooted from here.")
            return
        with contextlib.suppress(USBError):
            self.send_command("reboot")

    def _close(self) -> None:
        """Release the USB device and forget everything learned about it."""
        if self._device is not None:
            # Release the libusb handle explicitly rather than relying on garbage collection: a caller
            # may keep a reference to the Device across reset()->_reinit(), which would keep its handle
            # claimed, block the reset device from re-enumerating cleanly and hang the next lookup.
            dispose_resources(self._device)
        self._device = None
        self._mode = None
        self._info = None
        self._transport = None
        self.ap_nonce = None
        self.sep_nonce = None

    def _reinit(self, ecid: Optional[int] = None, timeout: float = 0xFFFFFFFF, is_recovery: Optional[bool] = None):
        self._close()
        found = _find_device(ecid=ecid, timeout=timeout, is_recovery=is_recovery)
        if found is None:
            raise IRecvNoDeviceConnectedError("No device in Recovery or DFU mode was found.")
        self._device, self._mode, self._info = found
        self._transport = RecoveryTransport(found.device) if found.mode.is_recovery else DfuTransport(found.device)

        descriptor = get_string(self.device, 1)
        if descriptor is None:
            raise IRecvError("Could not read the USB string descriptor of the device in Recovery/DFU mode.")
        self.ap_nonce = parse_nonce(descriptor, "NONC")
        self.sep_nonce = parse_nonce(descriptor, "SNON")

        self.set_configuration(1)

        if self.mode.is_recovery:
            self.set_interface_altsetting(0, 0)
            if self.mode.value > Mode.RECOVERY_MODE_2.value:
                self.set_interface_altsetting(1, 1)
        else:
            self.set_interface_altsetting(0, 0)

    def __str__(self) -> str:
        return str(self._info.fields if self._info is not None else {})

    def __enter__(self) -> "IRecv":
        return self

    def __exit__(
        self, exc_type: Optional[type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        self._close()
