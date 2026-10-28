import binascii
import contextlib
import logging
import math
import struct
import time
from array import array
from collections.abc import Iterable
from enum import Enum
from types import TracebackType
from typing import TYPE_CHECKING, Any, Optional, cast

from usb.core import Device, USBError

from pymobiledevice3.exceptions import IRecvError, IRecvNoDeviceConnectedError, PyMobileDevice3Exception
from pymobiledevice3.irecv_devices import IRecvDevice
from pymobiledevice3.progress import BYTES_UNIT, ProgressBar

if TYPE_CHECKING:
    # pyusb (usb.core / usb.util) and IRECV_DEVICES ship no type information, so their symbols
    # resolve as partially-unknown. Declare precise signatures for type checking while importing
    # the real implementations at runtime.
    def find(find_all: bool = False, backend: Any = None, custom_match: Any = None, **args: Any) -> Any: ...
    def get_string(dev: Any, index: int, langid: Optional[int] = None) -> Optional[str]: ...
    def dispose_resources(device: Any) -> None: ...

    IRECV_DEVICES: tuple[IRecvDevice, ...]
else:
    from usb.core import find
    from usb.util import dispose_resources, get_string

    from pymobiledevice3.irecv_devices import IRECV_DEVICES

USB_TIMEOUT = 10000
IRECV_TRANSFER_SIZE_RECOVERY = 0x8000
IRECV_TRANSFER_SIZE_DFU = 0x800
# libirecovery IRECV_SEND_OPT_DFU_SMALL_PKT: Port DFU uploads go in 64-byte packets without the DFU CRC trailer
IRECV_TRANSFER_SIZE_DFU_SMALL = 0x40

# Debug USB ("KIS") mode: the device exposes its DFU mode through a request/reply protocol over bulk
# endpoints instead of the DFU class requests (libirecovery irecv_kis_*)
KIS_PRODUCT_ID = 0x1881
KIS_PORTAL_CONFIG = 0x01
KIS_PORTAL_RSM = 0x10
KIS_INDEX_UPLOAD = 0x0D
KIS_INDEX_ENABLE_A = 0x0A
KIS_INDEX_ENABLE_B = 0x14
KIS_INDEX_GET_INFO = 0x100
KIS_INDEX_BOOT_IMG = 0x103
KIS_ENABLE_A_VAL = 0x21
KIS_ENABLE_B_VAL = 0x01
KIS_PORTAL_ENDPOINTS = {KIS_PORTAL_CONFIG: 1, KIS_PORTAL_RSM: 3}
KIS_REQ_HEADER = struct.Struct("<HBBBBBBI")
KIS_GENERIC_REPLY_SIZE = KIS_REQ_HEADER.size + 8
KIS_DEVICE_INFO_SIZE = 0x300
KIS_UPLOAD_CHUNK_SIZE = 0x4000
# offsets inside the GET_INFO reply payload (KIS_device_info.deviceInfo)
KIS_INFO_NONCE_OFFSET = 24
KIS_INFO_DEVICE_DESCRIPTOR = 64
# the device may need a moment after enumerating before it accepts configuration (libirecovery 3eb4fbb)
KIS_OPEN_RETRIES = 10
KIS_OPEN_RETRY_DELAY = 0.5


class Mode(Enum):
    RECOVERY_MODE_1 = 0x1280
    RECOVERY_MODE_2 = 0x1281
    RECOVERY_MODE_3 = 0x1282
    RECOVERY_MODE_4 = 0x1283
    WTF_MODE = 0x1222
    DFU_MODE = 0x1227
    # the USB-C port controller of an Apple silicon Mac, waiting for its firmware (libirecovery d3198a5)
    PORT_DFU_MODE = 0xF014

    @classmethod
    def has_value(cls, value: int):
        return any(value == m.value for m in cls)

    @classmethod
    def get_mode_from_value(cls, value: int):
        """
        :rtype: Mode
        """
        for m in cls:
            if value == m.value:
                return m
        return None

    @property
    def is_recovery(self):
        return self not in (self.WTF_MODE, self.DFU_MODE, self.PORT_DFU_MODE)


def kis_request_header(portal: int, index: int, arg_count: int, payload_size: int, reply_words: int) -> bytes:
    """Build a KIS request header (libirecovery irecv_kis_request_init)."""
    if arg_count > 0xFF or index >= 1 << 10 or reply_words >= 1 << 14:
        raise ValueError("KIS request out of range")
    return KIS_REQ_HEADER.pack(
        0,  # sequence number; the device does not care
        0xA0,  # protocol version
        portal,
        arg_count,
        index & 0xFF,
        ((index >> 8) & 0x3) | ((reply_words << 2) & 0xFC),
        (reply_words >> 6) & 0xFF,
        payload_size + (arg_count << 2),
    )


def kis_read_string(device_info: bytes, word_offset: int) -> Optional[str]:
    """Read a USB string descriptor out of a KIS GET_INFO payload (libirecovery irecv_kis_read_string)."""
    offset = word_offset * 4
    if offset + 2 > len(device_info):
        return None
    length = device_info[offset]
    descriptor_type = device_info[offset + 1]
    if length & 1 or length // 2 >= 0x100 or offset + 2 + length > len(device_info) or descriptor_type != 3:
        return None
    return device_info[offset + 2 : offset + 2 + length : 2].decode("latin-1")


def nonce_with_tag(string: str, tag: str) -> Optional[bytes]:
    if f"{tag}:" not in string:
        return None
    return binascii.unhexlify(string.split(f"{tag}:")[1].split(" ")[0])


CPFM_FLAG_SECURITY_MODE = 1 << 0
CPFM_FLAG_PRODUCTION_MODE = 1 << 1

IBOOT_FLAG_IMAGE4_AWARE = 1 << 2
IBOOT_FLAG_EFFECTIVE_SECURITY_MODE = 1 << 3
IBOOT_FLAG_EFFECTIVE_PRODUCTION_MODE = 1 << 4

APPLE_VENDOR_ID = 0x05AC

logger = logging.getLogger(__name__)


class IRecv:
    def __init__(
        self,
        ecid: Optional[int] = None,
        timeout: float = 0xFFFFFFFF,
        is_recovery: Optional[bool] = None,
        mode: Optional[Mode] = None,
    ):
        self._mode: Optional[Mode] = None
        self._device_info: dict[str, str] = {}
        self._device: Optional[Device] = None
        self._is_kis = False
        # the KIS GET_INFO reply carries what the USB string descriptors carry otherwise
        self._kis_nonces: Optional[str] = None
        self._reinit(ecid=ecid, timeout=timeout, is_recovery=is_recovery, mode=mode)

    @property
    def device(self) -> Any:
        """The connected USB device.

        :raises IRecvNoDeviceConnectedError: if no device is connected (before/after ``_reinit``).
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
    def ecid(self):
        return int(self._device_info["ECID"], 16)

    @property
    def ibfl(self):
        return int(self._device_info["IBFL"], 16)

    @property
    def chip_id(self):
        return int(self._device_info["CPID"], 16)

    @property
    def board_id(self):
        return int(self._device_info["BDID"], 16)

    @property
    def is_kis(self) -> bool:
        """Whether the device is in Debug USB (KIS) mode (its ``mode`` is the mode it reports through KIS)."""
        return self._is_kis

    @property
    def port_dfu_board_id(self) -> int:
        """The BDID of a Port DFU device, truncated to 32 bits the way libirecovery stores it."""
        return self.board_id & 0xFFFFFFFF

    @property
    def product_revision(self) -> int:
        """The PREV field of a Port DFU device."""
        return int(self._device_info["PREV"], 16)

    @property
    def serial_number(self) -> str:
        return self._device_info["SRNM"]

    @property
    def iboot_version(self) -> str:
        return self._device_info["SRTG"]

    @property
    def is_image4_supported(self):
        return self.ibfl & IBOOT_FLAG_IMAGE4_AWARE

    @property
    def _irecv_device(self) -> IRecvDevice:
        chip_id = self.chip_id
        board_id = self.board_id
        if self._mode == Mode.PORT_DFU_MODE:
            # the port controller reports the Mac's CPID and BDID inside its own BDID (libirecovery d3198a5)
            chip_id = (self.port_dfu_board_id >> 8) & 0xFFFF
            board_id = (self.port_dfu_board_id >> 24) & 0xFF
        for device in IRECV_DEVICES:
            if device.board_id == board_id and device.chip_id == chip_id:
                return device
        raise KeyError(f"failed to find device of: board_id: {board_id} chip_id: {chip_id}")

    @property
    def product_type(self):
        return self._irecv_device.product_type

    @property
    def hardware_model(self):
        return self._irecv_device.hardware_model

    @property
    def display_name(self):
        return self._irecv_device.display_name

    @property
    def status(self):
        return self.ctrl_transfer(0xA1, 3, data_or_wLength=b"\x00" * 6)[4]

    def set_interface_altsetting(self, interface: Optional[int] = None, alternate_setting: Optional[int] = None):
        logger.debug(f"set_interface_altsetting: {interface} {alternate_setting}")
        if interface == 1:
            self.device.set_interface_altsetting(interface=interface, alternate_setting=alternate_setting)

    def set_configuration(self, configuration: Optional[int] = None):
        logger.debug(f"set_configuration: {configuration}")
        device = self.device
        try:
            active_configuration: Any = device.get_active_configuration()
            if active_configuration.bConfigurationValue == configuration:
                return
        except USBError:
            pass

        device.set_configuration(configuration=configuration)

    def ctrl_transfer(
        self, bmRequestType: int, bRequest: int, timeout: int = USB_TIMEOUT, **kwargs: Any
    ) -> "array[int]":
        return cast("array[int]", self.device.ctrl_transfer(bmRequestType, bRequest, timeout=timeout, **kwargs))

    def send_buffer(self, buf: bytes, desc: Optional[str] = None, small_packets: bool = False):
        """
        Upload ``buf`` to the device and, in DFU mode, tell it the upload finished.

        :param small_packets: DFU only: send 64-byte packets without the DFU CRC trailer, waiting for the
            device after each one (libirecovery IRECV_SEND_OPT_DFU_SMALL_PKT, used for Port DFU)
        """
        if self._is_kis:
            self._kis_send_buffer(buf, desc)
            return

        device = self.device
        mode = self.mode
        packet_size = IRECV_TRANSFER_SIZE_RECOVERY if mode.is_recovery else IRECV_TRANSFER_SIZE_DFU
        small_packets = small_packets and not mode.is_recovery
        if small_packets:
            packet_size = IRECV_TRANSFER_SIZE_DFU_SMALL

        # initiate transfer
        if mode.is_recovery:
            self.ctrl_transfer(0x41, 0)
        else:
            response = self.ctrl_transfer(0xA1, 5, data_or_wLength=1)
            state = response[0]
            logger.debug(f"irecv state: {state}")
            if state == 2:
                # DFU IDLE
                pass
            elif state == 10:
                self.ctrl_transfer(0x21, 4)
                raise PyMobileDevice3Exception(
                    "The device in DFU mode was in an error state, so the upload did not start. The error was "
                    "cleared; retry the upload."
                )
            else:
                self.ctrl_transfer(0x21, 6)
                raise PyMobileDevice3Exception(
                    f"The device in DFU mode was not ready for an upload (DFU state {state}), so it was aborted. "
                    "Retry the upload."
                )

        crc = -1

        num_packets = math.ceil(len(buf) / packet_size)

        if desc is None:
            desc = "recovery upload" if mode.is_recovery else "DFU upload"
        with ProgressBar(total=len(buf), desc=desc, unit=BYTES_UNIT) as bar:
            for _offset in range(0, len(buf), packet_size):
                # Use bulk transfer for recovery mode and control transfer for DFU and WTF mode
                chunk = buf[_offset : _offset + packet_size]
                bar.update(len(chunk))
                packet_index = _offset // packet_size

                if mode.is_recovery:
                    n = cast(int, device.write(0x04, chunk, timeout=USB_TIMEOUT))
                    if n != len(chunk):
                        raise OSError("failed to upload data")
                elif small_packets:
                    self.ctrl_transfer(0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=chunk)
                    self._wait_for_dfu_status(5)
                else:
                    if _offset + packet_size >= len(buf):
                        # last packet

                        # calculate crc of all sent data
                        crc = binascii.crc32(buf, crc)

                        # add crc of dfu_xbuf (salted value)
                        dfu_xbuf = bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xAC, 0x05, 0x00, 0x01, 0x55, 0x46, 0x44, 0x10])
                        crc = binascii.crc32(dfu_xbuf, crc)

                        crc_chunk = dfu_xbuf + struct.pack("<I", crc)

                        if len(chunk) + 16 > packet_size:
                            # crc exceeds the max allowed packet size
                            self.ctrl_transfer(0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=chunk)
                            self.ctrl_transfer(0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=crc_chunk)
                        else:
                            self.ctrl_transfer(
                                0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=chunk + crc_chunk
                            )
                    else:
                        self.ctrl_transfer(0x21, 1, wValue=packet_index, wIndex=0, data_or_wLength=chunk)

        if mode.is_recovery and len(buf) % 512 == 0:
            # Terminating zero-length packet.
            device.write(0x04, b"", timeout=USB_TIMEOUT)

        if not mode.is_recovery:
            logger.debug("waiting for status == 5")
            while self.status != 5:
                time.sleep(1)

            self.ctrl_transfer(0x21, 1, wValue=num_packets, wIndex=0)

            for _offset in range(2):
                # i know it's not used but idevicerestore does that also
                _ = self.status

            self.reset()

    def _wait_for_dfu_status(self, wanted: int, retries: int = 20) -> None:
        for _ in range(retries):
            if self.status == wanted:
                return
            time.sleep(1)
        raise IRecvError(f"The device in DFU mode did not reach DFU status {wanted}.")

    def _kis_request(self, request: bytes, reply_size: int) -> bytes:
        endpoint = KIS_PORTAL_ENDPOINTS.get(request[3])
        if endpoint is None:
            raise ValueError(f"no KIS endpoint known for portal {request[3]}")
        device = self.device
        sent = cast(int, device.write(endpoint, request, timeout=USB_TIMEOUT))
        if sent != len(request):
            raise IRecvError(f"Sent only {sent} of {len(request)} bytes of a KIS request.")
        return bytes(cast("array[int]", device.read(endpoint | 0x80, reply_size, timeout=USB_TIMEOUT)))

    def _kis_config_write32(self, portal: int, index: int, value: int) -> None:
        request = kis_request_header(portal, index, 1, 0, 1) + struct.pack("<I", value)
        reply = self._kis_request(request, KIS_GENERIC_REPLY_SIZE)
        written, status = struct.unpack_from("<II", reply.ljust(KIS_GENERIC_REPLY_SIZE, b"\0"), KIS_REQ_HEADER.size)
        if written != 4:
            # libirecovery only logs this too
            logger.debug(f"KIS config write {index:#x}: {written} bytes written, status {status}")

    def _kis_init(self) -> None:
        """Enable KIS and read the device info it reports (libirecovery irecv_kis_init/load_device_info)."""
        self._kis_config_write32(KIS_PORTAL_CONFIG, KIS_INDEX_ENABLE_A, KIS_ENABLE_A_VAL)
        self._kis_config_write32(KIS_PORTAL_CONFIG, KIS_INDEX_ENABLE_B, KIS_ENABLE_B_VAL)
        request = kis_request_header(KIS_PORTAL_RSM, KIS_INDEX_GET_INFO, 0, 0, KIS_DEVICE_INFO_SIZE // 4)
        reply = self._kis_request(request, KIS_REQ_HEADER.size + KIS_DEVICE_INFO_SIZE + 8)
        serial, nonces, product_id = self.parse_kis_device_info(reply)
        self._is_kis = True
        self._kis_nonces = nonces
        self._populate_device_info(serial)
        mode = Mode.get_mode_from_value(product_id)
        if mode is None:
            raise IRecvError(f"The device in KIS mode reported an unknown mode {product_id:#x}.")
        self._mode = mode

    @staticmethod
    def parse_kis_device_info(reply: bytes) -> tuple[str, str, int]:
        """Return the serial string, the nonce string and the USB product ID from a KIS GET_INFO reply."""
        device_info = reply[KIS_REQ_HEADER.size :].ljust(KIS_DEVICE_INFO_SIZE + 8, b"\0")
        descriptor = device_info[KIS_INFO_DEVICE_DESCRIPTOR : KIS_INFO_DEVICE_DESCRIPTOR + 18]
        (product_id,) = struct.unpack_from("<H", descriptor, 10)
        (nonce_offset,) = struct.unpack_from("<I", device_info, KIS_INFO_NONCE_OFFSET)
        serial = kis_read_string(device_info, descriptor[16])
        nonces = kis_read_string(device_info, nonce_offset)
        if serial is None or nonces is None:
            raise IRecvError("The device in KIS mode returned unreadable device info.")
        return serial, nonces, product_id

    def _kis_send_buffer(self, buf: bytes, desc: Optional[str] = None) -> None:
        """Upload ``buf`` over KIS and boot it (libirecovery irecv_kis_send_buffer with DFU_NOTIFY_FINISH)."""
        if self.mode != Mode.DFU_MODE:
            raise IRecvError("Uploads over KIS are only supported in DFU mode.")
        with ProgressBar(total=len(buf), desc=desc or "KIS upload", unit=BYTES_UNIT) as bar:
            for address in range(0, len(buf), KIS_UPLOAD_CHUNK_SIZE):
                chunk = buf[address : address + KIS_UPLOAD_CHUNK_SIZE]
                request = (
                    kis_request_header(KIS_PORTAL_RSM, KIS_INDEX_UPLOAD, 3, len(chunk), 0)
                    + struct.pack("<QI", address, len(chunk))
                    + chunk
                )
                self._kis_request(request, KIS_GENERIC_REPLY_SIZE)
                bar.update(len(chunk))
        self._kis_config_write32(KIS_PORTAL_RSM, KIS_INDEX_BOOT_IMG, len(buf))

        # the device now boots the image and re-enumerates; wait for it to go away before looking for it again
        ecid = self.ecid
        usb_device: Any = self.device
        location = (usb_device.bus, usb_device.address)
        dispose_resources(usb_device)
        self._device = None
        deadline = time.time() + USB_TIMEOUT / 1000
        while time.time() < deadline and any(
            (d.bus, d.address) == location for d in cast(Iterable[Any], find(find_all=True))
        ):
            time.sleep(0.5)
        self._reinit(ecid=ecid)

    def reset(self):
        try:
            logger.debug("resetting usb device")
            logger.info("If the restore hangs here, disconnect & reconnect the device")
            self.device.reset()
        except USBError:
            pass

        if self._mode == Mode.PORT_DFU_MODE:
            # the port controller does not come back: the Mac re-enumerates in DFU mode under its own
            # ECID, so the caller looks for that one (see Recovery.port_dfu_restore)
            dispose_resources(self.device)
            self._device = None
            return

        self._reinit(ecid=self.ecid)

    def send_command(self, cmd: str, timeout: int = USB_TIMEOUT, b_request: int = 0):
        self.device.ctrl_transfer(0x40, b_request, 0, 0, cmd.encode() + b"\0", timeout=timeout)

    def getenv(self, name: str):
        try:
            self.send_command(f"getenv {name}")
        except USBError:
            return None
        return bytearray(self.device.ctrl_transfer(0xC0, 0, 0, 0, 255))

    def set_autoboot(self, enable: bool):
        self.send_command(f"setenv auto-boot {str(enable).lower()}")
        self.send_command("saveenv")

    def reboot(self):
        with contextlib.suppress(USBError):
            self.send_command("reboot")

    def _reinit(
        self,
        ecid: Optional[int] = None,
        timeout: float = 0xFFFFFFFF,
        is_recovery: Optional[bool] = None,
        mode: Optional[Mode] = None,
    ):
        if self._device is not None:
            # Explicitly release the libusb handle instead of relying on garbage collection: callers
            # such as send_buffer() keep a local reference to the Device across reset()->_reinit(), so
            # the object is not collected and its handle would stay claimed — blocking the reset
            # device from re-enumerating cleanly and hanging the subsequent _find().
            dispose_resources(self._device)
        self._device = None
        self._device_info = {}
        self._mode = None
        self._is_kis = False
        self._kis_nonces = None
        self._find(ecid=ecid, timeout=timeout, is_recovery=is_recovery, mode=mode)
        if self._device is None or self._mode is None:
            raise IRecvNoDeviceConnectedError("No device in Recovery or DFU mode was found.")
        if self._is_kis:
            # configured, and the device info read, while it was found
            assert self._kis_nonces is not None
            self.ap_nonce = nonce_with_tag(self._kis_nonces, "NONC")
            self.sep_nonce = nonce_with_tag(self._kis_nonces, "SNON")
            return
        self._populate_device_info()

        self.ap_nonce = self._copy_nonce_with_tag("NONC")
        self.sep_nonce = self._copy_nonce_with_tag("SNON")

        self.set_configuration(1)

        if self.mode.is_recovery:
            self.set_interface_altsetting(0, 0)
            if self.mode.value > Mode.RECOVERY_MODE_2.value:
                self.set_interface_altsetting(1, 1)
        else:
            self.set_interface_altsetting(0, 0)

    def _copy_nonce_with_tag(self, tag: str):
        device_string = get_string(self.device, 1)
        if device_string is None:
            raise IRecvError("Could not read the USB string descriptor of the device in Recovery/DFU mode.")
        if tag in device_string:
            return binascii.unhexlify(device_string.split(f"{tag}:")[1].split(" ")[0])
        else:
            return None

    def _open_kis(self) -> None:
        """Configure a freshly found KIS device and read its device info, retrying while it settles."""
        for attempt in range(KIS_OPEN_RETRIES):
            try:
                self.device.set_configuration(1)
                self.device.set_interface_altsetting(interface=0, alternate_setting=0)
                break
            except USBError:
                if attempt + 1 == KIS_OPEN_RETRIES:
                    raise
                logger.debug("could not configure the KIS device, retrying...")
                time.sleep(KIS_OPEN_RETRY_DELAY)
        self._kis_init()

    def _find(
        self,
        ecid: Optional[int] = None,
        timeout: float = 0xFFFFFFFF,
        is_recovery: Optional[bool] = None,
        mode: Optional[Mode] = None,
    ):
        start = time.time()
        end = start + timeout
        while (self._device is None) and (time.time() < end):
            for device in cast(Iterable[Device], find(find_all=True)):
                usb_device: Any = device

                # Match on the descriptor fields cached at enumeration. Reading string
                # descriptors (e.g. manufacturer) requires opening the device, which fails
                # for unrelated devices lacking a libusb-compatible driver (e.g. on Windows).
                if usb_device.idVendor != APPLE_VENDOR_ID:
                    continue

                is_kis = usb_device.idProduct == KIS_PRODUCT_ID
                device_mode = Mode.get_mode_from_value(usb_device.idProduct)
                if device_mode is None and not is_kis:
                    # not one of Apple's special modes
                    continue

                # a KIS device's mode is known only once it is opened
                if device_mode is not None and not self._mode_matches(device_mode, is_recovery, mode):
                    continue

                if self._device is not None:
                    raise IRecvError(
                        "More than one device was found connected in recovery mode; select one by its ECID"
                    )

                try:
                    self._device = device
                    self._mode = device_mode
                    self._device_info = {}
                    self._is_kis = False
                    if is_kis:
                        self._open_kis()
                        assert self._mode is not None
                        if not self._mode_matches(self._mode, is_recovery, mode):
                            dispose_resources(device)
                            self._device = None
                            self._mode = None
                            continue
                    else:
                        self._populate_device_info()

                    if ecid is not None:
                        found_ecid = int(self._device_info["ECID"], 16)
                        if found_ecid != ecid:
                            # wrong device - move on
                            self._device = None
                            self._mode = None
                            continue
                except (ValueError, NotImplementedError, USBError, IRecvError):
                    # unreadable device (e.g. missing driver or permissions) - move on
                    self._device = None
                    self._mode = None
                    continue

                if ecid is not None:
                    # Other devices may be in Recovery/DFU too, e.g. while another restore runs.
                    break

    @staticmethod
    def _mode_matches(device_mode: Mode, is_recovery: Optional[bool], mode: Optional[Mode]) -> bool:
        if is_recovery is not None and device_mode.is_recovery != is_recovery:
            return False
        return mode is None or device_mode == mode

    def _populate_device_info(self, serial_number: Optional[str] = None):
        if serial_number is None:
            serial_number = cast(Optional[str], self.device.serial_number)
        if serial_number is None:
            raise IRecvError("The device in Recovery/DFU mode did not report its USB serial number.")
        for component in serial_number.split(" "):
            k, v = component.split(":")
            if k in ("SRNM", "SRTG") and "[" in v:
                # trim the `[]`
                v = v[1:-1]
            self._device_info[k] = v

    def __str__(self):
        return str(self._device_info)

    def __enter__(self):
        return self

    def __exit__(
        self, exc_type: Optional[type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ):
        del self._device


def main():
    print(IRecv())


if __name__ == "__main__":
    main()
