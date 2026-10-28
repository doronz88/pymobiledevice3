"""
Talking to a device in Recovery mode (iBoot: commands and USB bulk uploads) or DFU mode (the SecureROM: USB DFU
class requests).

A transport wraps the ``UsbDevice`` it was created for and is only valid until that device re-enumerates (after a
reset or a mode change). ``IRecv`` owns the transport and replaces it whenever it looks the device up again; nothing
else should keep one.
"""

import binascii
import logging
import math
import struct
import time
from array import array
from enum import IntEnum
from typing import Optional, Union, cast

from pymobiledevice3.exceptions import IRecvError, PyMobileDevice3Exception
from pymobiledevice3.irecv._usb import USB_TIMEOUT, UsbDevice
from pymobiledevice3.progress import BYTES_UNIT, ProgressBar

logger = logging.getLogger(__name__)

# bmRequestType values
REQUEST_TYPE_CLASS_OUT = 0x21  # host-to-device, class, interface
REQUEST_TYPE_CLASS_IN = 0xA1  # device-to-host, class, interface
REQUEST_TYPE_VENDOR_OUT = 0x40  # host-to-device, vendor, device
REQUEST_TYPE_VENDOR_INTERFACE_OUT = 0x41  # host-to-device, vendor, interface
REQUEST_TYPE_VENDOR_IN = 0xC0  # device-to-host, vendor, device

RECOVERY_PACKET_SIZE = 0x8000
RECOVERY_BULK_ENDPOINT = 0x04
DFU_PACKET_SIZE = 0x800
# How long to wait for the device to finish an upload: libirecovery's 20 one-second retries.
DFU_STATUS_RETRIES = 20

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
        data_or_wLength: Union[int, bytes],
        wValue: int = 0,
        wIndex: int = 0,
        timeout: Optional[int] = USB_TIMEOUT,
    ) -> "array[int]":
        """
        A device-to-host control request reading ``data_or_wLength`` bytes (a length, or a buffer of that size).

        A ``None`` timeout uses pyusb's default.
        """
        return cast(
            "array[int]",
            self.device.ctrl_transfer(
                bmRequestType, bRequest, wValue, wIndex, data_or_wLength=data_or_wLength, timeout=timeout
            ),
        )

    def control_out(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data: Optional[bytes] = None,
        timeout: int = USB_TIMEOUT,
    ) -> int:
        """A host-to-device control request; returns the number of payload bytes written."""
        return cast(
            int,
            self.device.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data_or_wLength=data, timeout=timeout),
        )


class RecoveryTransport(UsbTransport):
    """A device running iBoot (Recovery mode): it takes commands and bulk uploads."""

    def send_command(self, cmd: str, timeout: int = USB_TIMEOUT, b_request: int = 0) -> None:
        self.control_out(REQUEST_TYPE_VENDOR_OUT, b_request, data=cmd.encode() + b"\0", timeout=timeout)

    def read_command_reply(self) -> bytearray:
        """The reply to the last command (e.g. a ``getenv``), read with pyusb's default timeout."""
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
        return self.control_in(REQUEST_TYPE_CLASS_IN, DfuRequest.GETSTATUS, b"\x00" * 6)[4]

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
