"""
Talking to a device in Recovery mode (iBoot: commands and USB bulk uploads), DFU mode (the SecureROM: USB DFU
class requests) or, on A16 and later, DFU mode behind Debug USB (KIS: requests and replies over bulk endpoints).

A transport wraps the ``UsbDevice`` it was created for and is only valid until that device re-enumerates (after a
reset or a mode change). ``IRecv`` owns the transport and replaces it whenever it looks the device up again; nothing
else should keep one.
"""

import binascii
import logging
import math
import struct
import time
from enum import IntEnum
from typing import NamedTuple, Optional

from pymobiledevice3.exceptions import IRecvError, PyMobileDevice3Exception
from pymobiledevice3.irecv._usb import USB_TIMEOUT, UsbDevice
from pymobiledevice3.progress import BYTES_UNIT, ProgressBar
from pymobiledevice3.usb.device_interface import DeviceInterfaceClient, DfuInterface

logger = logging.getLogger(__name__)

# bmRequestType values
REQUEST_TYPE_CLASS_OUT = 0x21  # host-to-device, class, interface
REQUEST_TYPE_CLASS_IN = 0xA1  # device-to-host, class, interface
REQUEST_TYPE_VENDOR_OUT = 0x40  # host-to-device, vendor, device
REQUEST_TYPE_VENDOR_INTERFACE_OUT = 0x41  # host-to-device, vendor, interface
REQUEST_TYPE_VENDOR_IN = 0xC0  # device-to-host, vendor, device
REQUEST_DIRECTION_IN = 0x80

RECOVERY_PACKET_SIZE = 0x8000
RECOVERY_BULK_ENDPOINT = 0x04
DFU_PACKET_SIZE = 0x800
# How long to wait for the device to finish an upload: libirecovery's 20 one-second retries.
DFU_STATUS_RETRIES = 20

# Debug USB (KIS), as libirecovery implements it (irecv_kis_*)
KIS_PORTAL_CONFIG = 0x01
KIS_PORTAL_RSM = 0x10
KIS_PORTAL_ENDPOINTS = {KIS_PORTAL_CONFIG: 1, KIS_PORTAL_RSM: 3}
KIS_INDEX_UPLOAD = 0x0D
KIS_INDEX_ENABLE_A = 0x0A
KIS_INDEX_ENABLE_B = 0x14
KIS_INDEX_GET_INFO = 0x100
KIS_INDEX_BOOT_IMG = 0x103
# what macOS writes to the enable registers
KIS_ENABLE_A_VALUE = 0x21
KIS_ENABLE_B_VALUE = 0x01
KIS_PROTOCOL_VERSION = 0xA0
KIS_HEADER = struct.Struct("<HBBBBBBI")
# a reply header, then the bytes read/written and a status
KIS_GENERIC_REPLY_SIZE = KIS_HEADER.size + 8
KIS_DEVICE_INFO_SIZE = 0x300
KIS_UPLOAD_CHUNK_SIZE = 0x4000
# offsets inside the GET_INFO payload
KIS_INFO_NONCE_OFFSET = 24
KIS_INFO_DEVICE_DESCRIPTOR = 64

# Salt Apple's DFU appends after the image before its CRC.
_DFU_CRC_SALT = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xAC, 0x05, 0x00, 0x01, 0x55, 0x46, 0x44, 0x10])


class DfuRequest(IntEnum):
    """USB DFU class requests (USB DFU 1.1, section 3)."""

    DNLOAD = 1
    GETSTATUS = 3
    CLRSTATUS = 4
    GETSTATE = 5
    ABORT = 6


class DfuState(IntEnum):
    """USB DFU device states (USB DFU 1.1, section 6.1.2)."""

    DFU_IDLE = 2
    DFU_DNLOAD_IDLE = 5
    DFU_ERROR = 10


def dfu_crc_trailer(buf: bytes) -> bytes:
    """The salt and little-endian CRC Apple's DFU expects after the last packet of an image."""
    crc = binascii.crc32(_DFU_CRC_SALT, binascii.crc32(buf, -1))
    return _DFU_CRC_SALT + struct.pack("<I", crc)


class UsbTransport:
    """USB control requests to one connected device."""

    def __init__(self, device: UsbDevice) -> None:
        self.device = device

    def control_in(
        self,
        bmRequestType: int,
        bRequest: int,
        length: int,
        wValue: int = 0,
        wIndex: int = 0,
        timeout: Optional[int] = USB_TIMEOUT,
    ) -> bytes:
        """
        A device-to-host control request reading up to ``length`` bytes.

        A ``None`` timeout uses ``pymobiledevice3.usb.device.DEFAULT_TIMEOUT``.
        """
        return self.device.control_in(bmRequestType, bRequest, wValue, wIndex, length, timeout=timeout)

    def control_out(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data: bytes = b"",
        timeout: int = USB_TIMEOUT,
    ) -> int:
        """A host-to-device control request; returns the number of payload bytes written."""
        return self.device.control_out(bmRequestType, bRequest, wValue, wIndex, data, timeout=timeout)


class RecoveryTransport(UsbTransport):
    """A device running iBoot (Recovery mode): it takes commands and bulk uploads."""

    def send_command(self, cmd: str, timeout: int = USB_TIMEOUT, b_request: int = 0) -> None:
        self.control_out(REQUEST_TYPE_VENDOR_OUT, b_request, data=cmd.encode() + b"\0", timeout=timeout)

    def read_command_reply(self) -> bytearray:
        """The reply to the last command (e.g. a ``getenv``), read with the default USB timeout."""
        return bytearray(self.control_in(REQUEST_TYPE_VENDOR_IN, 0, 255, timeout=None))

    def send_zero_length_download(self, timeout: int = USB_TIMEOUT) -> None:
        """Send an empty DFU DNLOAD request, which iBoot expects after a ``go``/``bootx`` command."""
        self.control_out(REQUEST_TYPE_CLASS_OUT, DfuRequest.DNLOAD, timeout=timeout)

    def upload(self, buf: bytes, desc: str) -> None:
        """Upload ``buf`` over the bulk endpoint."""
        self.control_out(REQUEST_TYPE_VENDOR_INTERFACE_OUT, 0)
        with ProgressBar(total=len(buf), desc=desc, unit=BYTES_UNIT) as bar:
            for offset in range(0, len(buf), RECOVERY_PACKET_SIZE):
                chunk = buf[offset : offset + RECOVERY_PACKET_SIZE]
                bar.update(len(chunk))
                n = self.device.write(RECOVERY_BULK_ENDPOINT, chunk, timeout=USB_TIMEOUT)
                if n != len(chunk):
                    raise OSError("failed to upload data")

        if len(buf) % 512 == 0:
            # Terminating zero-length packet.
            self.device.write(RECOVERY_BULK_ENDPOINT, b"", timeout=USB_TIMEOUT)


class DfuTransport(UsbTransport):
    """A device running the SecureROM (DFU or WTF mode): it only takes DFU class requests."""

    @property
    def state(self) -> int:
        """The bState field of a DFU GETSTATUS reply."""
        return self.control_in(REQUEST_TYPE_CLASS_IN, DfuRequest.GETSTATUS, 6)[4]

    def _wait_for_state(self, wanted: int, retries: int = DFU_STATUS_RETRIES) -> None:
        for _ in range(retries):
            if self.state == wanted:
                return
            time.sleep(1)
        raise IRecvError(f"The device in DFU mode did not reach DFU state {wanted} after the upload.")

    def _start_upload(self) -> None:
        state = self.control_in(REQUEST_TYPE_CLASS_IN, DfuRequest.GETSTATE, 1)[0]
        logger.debug(f"irecv state: {state}")
        if state == DfuState.DFU_IDLE:
            return
        if state == DfuState.DFU_ERROR:
            self.control_out(REQUEST_TYPE_CLASS_OUT, DfuRequest.CLRSTATUS)
            raise PyMobileDevice3Exception(
                "The device in DFU mode was in an error state, so the upload did not start. The error was "
                "cleared; retry the upload."
            )
        self.control_out(REQUEST_TYPE_CLASS_OUT, DfuRequest.ABORT)
        raise PyMobileDevice3Exception(
            f"The device in DFU mode was not ready for an upload (DFU state {state}), so it was aborted. "
            "Retry the upload."
        )

    def upload(self, buf: bytes, desc: str) -> None:
        """
        Upload ``buf`` and tell the device the upload finished.

        The device then has to be reset to run the image, which makes it re-enumerate: this transport is done.
        """
        self._start_upload()
        trailer = dfu_crc_trailer(buf)
        num_packets = math.ceil(len(buf) / DFU_PACKET_SIZE)

        def dnload(packet_index: int, data: bytes) -> None:
            self.control_out(REQUEST_TYPE_CLASS_OUT, DfuRequest.DNLOAD, wValue=packet_index, data=data)

        with ProgressBar(total=len(buf), desc=desc, unit=BYTES_UNIT) as bar:
            for offset in range(0, len(buf), DFU_PACKET_SIZE):
                chunk = buf[offset : offset + DFU_PACKET_SIZE]
                bar.update(len(chunk))
                packet_index = offset // DFU_PACKET_SIZE
                if offset + DFU_PACKET_SIZE < len(buf):
                    dnload(packet_index, chunk)
                elif len(chunk) + len(trailer) > DFU_PACKET_SIZE:
                    # the CRC trailer does not fit in the last packet
                    dnload(packet_index, chunk)
                    dnload(packet_index, trailer)
                else:
                    dnload(packet_index, chunk + trailer)

        logger.debug("waiting for DFU state dfuDNLOAD-IDLE")
        self._wait_for_state(DfuState.DFU_DNLOAD_IDLE)

        # a zero-length DNLOAD ends the upload
        self.control_out(REQUEST_TYPE_CLASS_OUT, DfuRequest.DNLOAD, wValue=num_packets)
        for _ in range(2):
            # idevicerestore reads the status twice here too
            _ = self.state


def kis_header(portal: int, index: int, arg_count: int, payload_size: int, reply_words: int) -> bytes:
    """A KIS request header: ``arg_count`` 32-bit arguments and ``payload_size`` bytes follow it."""
    if arg_count > 0xFF or index >= 1 << 10 or reply_words >= 1 << 14:
        raise ValueError("KIS request out of range")
    return KIS_HEADER.pack(
        0,  # sequence number; the device ignores it
        KIS_PROTOCOL_VERSION,
        portal,
        arg_count,
        index & 0xFF,
        ((index >> 8) & 0x3) | ((reply_words << 2) & 0xFC),
        (reply_words >> 6) & 0xFF,
        payload_size + (arg_count << 2),
    )


def _kis_string(payload: bytes, word_offset: int) -> Optional[str]:
    """The USB string descriptor at ``word_offset`` 32-bit words into a GET_INFO payload, if well formed."""
    offset = word_offset * 4
    if offset + 2 > len(payload):
        return None
    length, descriptor_type = payload[offset], payload[offset + 1]
    if length & 1 or descriptor_type != 3 or offset + 2 + length > len(payload):
        return None
    return payload[offset + 2 : offset + 2 + length : 2].decode("latin-1")


class KisDeviceInfo(NamedTuple):
    """What a GET_INFO request returns: what the USB descriptors of a device not behind KIS would carry."""

    serial_number: str
    nonces: str
    product_id: int

    @classmethod
    def parse(cls, reply: bytes) -> "KisDeviceInfo":
        """
        :raises IRecvError: if the reply is malformed.
        """
        payload = reply[KIS_HEADER.size :].ljust(KIS_DEVICE_INFO_SIZE, b"\0")
        descriptor = payload[KIS_INFO_DEVICE_DESCRIPTOR : KIS_INFO_DEVICE_DESCRIPTOR + 18]
        (product_id,) = struct.unpack_from("<H", descriptor, 10)
        (nonce_offset,) = struct.unpack_from("<I", payload, KIS_INFO_NONCE_OFFSET)
        serial_number = _kis_string(payload, descriptor[16])
        nonces = _kis_string(payload, nonce_offset)
        if serial_number is None or nonces is None:
            raise IRecvError("The device in DFU mode (KIS) returned malformed device info.")
        return cls(serial_number, nonces, product_id)


class KisTransport:
    """A device in DFU mode behind Debug USB (KIS): requests and replies over bulk endpoints."""

    def __init__(self, device: UsbDevice) -> None:
        self.device = device

    def request(self, request: bytes, reply_size: int) -> bytes:
        portal = request[3]
        endpoint = KIS_PORTAL_ENDPOINTS.get(portal)
        if endpoint is None:
            raise ValueError(f"no KIS endpoint is known for portal {portal:#x}")
        sent = self.device.write(endpoint, request, timeout=USB_TIMEOUT)
        if sent != len(request):
            raise IRecvError(f"Sent only {sent} of {len(request)} bytes of a KIS request.")
        return self.device.read(endpoint | 0x80, reply_size, timeout=USB_TIMEOUT)

    def write32(self, portal: int, index: int, value: int) -> None:
        reply = self.request(kis_header(portal, index, 1, 0, 1) + struct.pack("<I", value), KIS_GENERIC_REPLY_SIZE)
        written, status = struct.unpack_from("<II", reply.ljust(KIS_GENERIC_REPLY_SIZE, b"\0"), KIS_HEADER.size)
        if written != 4:
            # libirecovery ignores this too
            logger.debug(f"KIS write of {index:#x}: {written} bytes written, status {status}")

    def enable(self) -> None:
        self.write32(KIS_PORTAL_CONFIG, KIS_INDEX_ENABLE_A, KIS_ENABLE_A_VALUE)
        self.write32(KIS_PORTAL_CONFIG, KIS_INDEX_ENABLE_B, KIS_ENABLE_B_VALUE)

    def device_info(self) -> KisDeviceInfo:
        request = kis_header(KIS_PORTAL_RSM, KIS_INDEX_GET_INFO, 0, 0, KIS_DEVICE_INFO_SIZE // 4)
        return KisDeviceInfo.parse(self.request(request, KIS_HEADER.size + KIS_DEVICE_INFO_SIZE + 8))

    def upload(self, buf: bytes, desc: str) -> None:
        """Upload ``buf`` and boot it; the device then re-enumerates, so this transport is done."""
        with ProgressBar(total=len(buf), desc=desc, unit=BYTES_UNIT) as bar:
            for address in range(0, len(buf), KIS_UPLOAD_CHUNK_SIZE):
                chunk = buf[address : address + KIS_UPLOAD_CHUNK_SIZE]
                request = (
                    kis_header(KIS_PORTAL_RSM, KIS_INDEX_UPLOAD, 3, len(chunk), 0)
                    + struct.pack("<QI", address, len(chunk))
                    + chunk
                )
                self.request(request, KIS_GENERIC_REPLY_SIZE)
                bar.update(len(chunk))
        self.write32(KIS_PORTAL_RSM, KIS_INDEX_BOOT_IMG, len(buf))

    def wait_until_gone(self, timeout: float) -> bool:
        return self.device.wait_until_gone(timeout)


class DeviceInterfaceTransport:
    """
    A device in DFU mode behind KIS on macOS, reached through ``deviceinterfaced`` (the only process allowed to
    open it there).
    """

    def __init__(self, client: DeviceInterfaceClient, device: DfuInterface) -> None:
        self.client = client
        self.device = device

    def upload(self, buf: bytes, desc: str) -> None:
        """Upload ``buf`` and boot it; the device then re-enumerates, so this transport is done."""
        with ProgressBar(total=len(buf), desc=desc, unit=BYTES_UNIT) as bar:
            # deviceinterfaced takes the whole image at once
            self.client.download(self.device, buf)
            bar.update(len(buf))
        self.client.complete_dfu(self.device, len(buf))

    def wait_until_gone(self, timeout: float) -> bool:
        return self.client.wait_until_gone(self.device.interface_id, timeout)
