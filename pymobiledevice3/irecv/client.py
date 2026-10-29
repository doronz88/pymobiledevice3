"""Find a device in Recovery/DFU mode over USB and talk to it."""

import contextlib
import logging
import sys
import time
from array import array
from collections.abc import Callable, Iterator
from types import TracebackType
from typing import TYPE_CHECKING, NamedTuple, Optional, Union

from pymobiledevice3.exceptions import IRecvError, IRecvNoDeviceConnectedError
from pymobiledevice3.irecv._usb import (
    APPLE_VENDOR_ID,
    KIS_PRODUCT_ID,
    USB_TIMEOUT,
    Mode,
    UsbDevice,
    USBError,
    list_devices,
)
from pymobiledevice3.irecv.device_info import DeviceInfo, parse_nonce
from pymobiledevice3.irecv.transport import (
    REQUEST_DIRECTION_IN,
    DeviceInterfaceTransport,
    DfuTransport,
    KisTransport,
    RecoveryTransport,
)
from pymobiledevice3.irecv_devices import IRecvDevice
from pymobiledevice3.usb import device_interface

if TYPE_CHECKING:
    # IRECV_DEVICES ships no type information
    IRECV_DEVICES: tuple[IRecvDevice, ...]
else:
    from pymobiledevice3.irecv_devices import IRECV_DEVICES

logger = logging.getLogger(__name__)

# pause between USB scans while waiting for a device to show up
_FIND_POLL_INTERVAL = 0.1
# how long a device in DFU mode behind KIS may take to leave the bus after booting an upload
_KIS_BOOT_TIMEOUT = USB_TIMEOUT / 1000

_Transport = Union[RecoveryTransport, DfuTransport, KisTransport, DeviceInterfaceTransport]
_KisTransport = (KisTransport, DeviceInterfaceTransport)


class _Found(NamedTuple):
    # None for a device reached through deviceinterfaced
    device: Optional[UsbDevice]
    mode: Mode
    info: DeviceInfo
    # set for a device behind KIS, which is configured and asked for its info while it is being found
    transport: Optional[_Transport] = None
    # its NONC/SNON string
    nonces: Optional[str] = None


def _read_device_info(device: UsbDevice) -> DeviceInfo:
    serial_number = device.serial_number
    if serial_number is None:
        raise IRecvError("The device in Recovery/DFU mode did not report its USB serial number.")
    return DeviceInfo.parse(serial_number)


def _open_kis(device: UsbDevice) -> Optional[_Found]:
    """
    Configure a device behind KIS and ask it what it is: unlike the others, it tells its mode only once opened.

    :return: ``None`` if it reports a mode this module does not know.
    """
    if device.get_configuration() != 1:
        device.set_configuration(1)
    device.set_interface_altsetting(0, 0)
    kis = KisTransport(device)
    kis.enable()
    kis_info = kis.device_info()
    mode = Mode.get_mode_from_value(kis_info.product_id)
    if mode is None:
        logger.debug(f"a device behind KIS reports the unknown USB product ID {kis_info.product_id:#06x}")
        return None
    return _Found(device, mode, DeviceInfo.parse(kis_info.serial_number), kis, kis_info.nonces)


def _device_interface_devices() -> list[_Found]:
    """The devices in DFU mode behind KIS that macOS' deviceinterfaced holds."""
    try:
        client = device_interface.client()
        devices = client.devices()
    except USBError as e:
        logger.debug(f"cannot reach devices behind KIS through deviceinterfaced: {e}")
        return []
    found: list[_Found] = []
    for device in devices:
        mode = Mode.get_mode_from_value(device.product_id)
        if mode is None:
            logger.debug(f"a device behind KIS reports the unknown USB product ID {device.product_id:#06x}")
            continue
        try:
            info = DeviceInfo.parse(device.serial_number)
        except IRecvError as e:
            logger.debug(f"a device behind KIS reports unreadable info: {e}")
            continue
        found.append(_Found(None, mode, info, DeviceInterfaceTransport(client, device), device.nonces))
    return found


def _candidates(devices: list[UsbDevice]) -> Iterator[tuple[Mode, Callable[[], Optional[_Found]]]]:
    """Each device in a boot mode, and how to read what it reports (``None`` if it cannot be read)."""

    def read(device: UsbDevice, mode: Mode) -> Optional[_Found]:
        try:
            return _Found(device, mode, _read_device_info(device))
        except (ValueError, NotImplementedError, USBError, IRecvError):
            # unreadable device (e.g. missing driver or permissions) - move on
            return None

    for device in devices:
        # Match on the descriptor fields cached at enumeration. Reading string
        # descriptors (e.g. manufacturer) requires opening the device, which fails
        # for unrelated devices lacking a libusb-compatible driver (e.g. on Windows).
        if device.idVendor != APPLE_VENDOR_ID:
            continue

        if device.idProduct == KIS_PRODUCT_ID:
            if sys.platform == "darwin":
                # only deviceinterfaced may open it; it is listed below
                continue
            try:
                kis = _open_kis(device)
            except (USBError, IRecvError) as e:
                # it may still be settling after enumerating - try again on the next scan
                logger.debug(f"could not open a device behind KIS: {e}")
                continue
            if kis is not None:
                yield kis.mode, lambda kis=kis: kis
            continue

        mode = Mode.get_mode_from_value(device.idProduct)
        if mode is None:
            # not one of Apple's special modes
            continue
        yield mode, lambda device=device, mode=mode: read(device, mode)

    if sys.platform == "darwin":
        for kis in _device_interface_devices():
            yield kis.mode, lambda kis=kis: kis


def _find_device(ecid: Optional[int], timeout: float, is_recovery: Optional[bool]) -> Optional[_Found]:
    """
    Scan USB until a device in Recovery/DFU mode (and ``ecid``, if given) shows up or ``timeout`` passes.

    :raises IRecvError: if no ``ecid`` was given and more than one device is in Recovery/DFU mode.
    """
    end = time.time() + timeout
    while True:
        found: Optional[_Found] = None
        devices = list_devices()
        try:
            for mode, read in _candidates(devices):
                if is_recovery is not None and mode.is_recovery != is_recovery:
                    continue

                if found is not None:
                    raise IRecvError(
                        "More than one device was found connected in recovery mode; select one by its ECID"
                    )

                candidate = read()
                if candidate is None:
                    continue
                if ecid is not None and candidate.info.ecid != ecid:
                    # wrong device - move on
                    continue

                found = candidate
                if ecid is not None:
                    # Other devices may be in Recovery/DFU too, e.g. while another restore runs.
                    break
        finally:
            # release every device but the one found
            for device in devices:
                if found is None or device is not found.device:
                    device.close()

        if found is not None or time.time() >= end:
            return found
        time.sleep(_FIND_POLL_INTERVAL)


class IRecv:
    """A device in Recovery, DFU or WTF mode."""

    def __init__(self, ecid: Optional[int] = None, timeout: float = 0xFFFFFFFF, is_recovery: Optional[bool] = None):
        self._device: Optional[UsbDevice] = None
        self._mode: Optional[Mode] = None
        self._info: Optional[DeviceInfo] = None
        self._transport: Optional[_Transport] = None
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

    @property
    def is_kis(self) -> bool:
        """Whether the device is in DFU mode behind Debug USB (KIS), as A16 and later are."""
        return isinstance(self._transport, _KisTransport)

    def _current_transport(self) -> _Transport:
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
            if isinstance(transport, _KisTransport):
                raise IRecvError("A device in DFU mode behind KIS reports no DFU state.")
            raise IRecvError(f"Only a device in DFU or WTF mode reports a DFU state; this one is in {self.mode.name}.")
        return transport

    def set_interface_altsetting(self, interface: int, alternate_setting: int) -> None:
        logger.debug(f"set_interface_altsetting: {interface} {alternate_setting}")
        if interface == 1:
            self.device.set_interface_altsetting(interface=interface, alternate_setting=alternate_setting)

    def set_configuration(self, configuration: int = 1) -> None:
        logger.debug(f"set_configuration: {configuration}")
        device = self.device
        try:
            if device.get_configuration() == configuration:
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
        data_or_wLength: Union[int, bytes, None] = None,
        timeout: int = USB_TIMEOUT,
    ) -> Union["array[int]", int]:
        """A raw control request, as pyusb takes it: the bytes read for a device-to-host request, the number of bytes
        written otherwise."""
        if bmRequestType & REQUEST_DIRECTION_IN:
            length = data_or_wLength if isinstance(data_or_wLength, int) else len(data_or_wLength or b"")
            return array("B", self.device.control_in(bmRequestType, bRequest, wValue, wIndex, length, timeout=timeout))
        data = b"" if isinstance(data_or_wLength, int) else bytes(data_or_wLength or b"")
        return self.device.control_out(bmRequestType, bRequest, wValue, wIndex, data, timeout=timeout)

    def send_zero_length_download(self, timeout: int = USB_TIMEOUT) -> None:
        """Send an empty DFU DNLOAD request, which iBoot expects after a ``go``/``bootx`` command."""
        self._recovery_transport().send_zero_length_download(timeout=timeout)

    def send_buffer(self, buf: bytes, desc: Optional[str] = None) -> None:
        """Upload ``buf``. In DFU/WTF mode the device then runs it, so it is reset and looked up again."""
        transport = self._current_transport()
        if isinstance(transport, RecoveryTransport):
            transport.upload(buf, desc or "recovery upload")
            return
        if isinstance(transport, _KisTransport):
            if self.mode != Mode.DFU_MODE:
                raise IRecvError(
                    f"A device behind KIS takes uploads only in DFU mode; this one is in {self.mode.name}."
                )
            transport.upload(buf, desc or "KIS upload")
            # booting the upload makes the device re-enumerate; don't find it again before it left
            if not transport.wait_until_gone(_KIS_BOOT_TIMEOUT):
                logger.warning("The device in DFU mode is still connected after booting the upload.")
            self._reinit(ecid=self.ecid)
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
            # Release the USB handle explicitly rather than relying on garbage collection: a caller
            # may keep a reference to the Device across reset()->_reinit(), which would keep its handle
            # claimed, block the reset device from re-enumerating cleanly and hang the next lookup.
            self._device.close()
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
        self._device, self._mode, self._info = found.device, found.mode, found.info
        if found.transport is not None:
            # behind KIS: configured, and the nonces read, while it was found
            self._transport = found.transport
            nonces = found.nonces or ""
            self.ap_nonce = parse_nonce(nonces, "NONC")
            self.sep_nonce = parse_nonce(nonces, "SNON")
            return
        assert found.device is not None
        self._transport = RecoveryTransport(found.device) if found.mode.is_recovery else DfuTransport(found.device)

        descriptor = self.device.get_string(1)
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
