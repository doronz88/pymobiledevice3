"""Uploading images to a device in Recovery mode (USB bulk) or DFU mode (USB DFU class requests)."""

import binascii
import logging
import math
import struct
import time
from array import array
from enum import IntEnum
from typing import Any, cast

from pymobiledevice3.exceptions import IRecvError, PyMobileDevice3Exception
from pymobiledevice3.irecv._usb import USB_TIMEOUT
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


def ctrl_transfer(
    device: Any, bmRequestType: int, bRequest: int, timeout: int = USB_TIMEOUT, **kwargs: Any
) -> "array[int]":
    return cast("array[int]", device.ctrl_transfer(bmRequestType, bRequest, timeout=timeout, **kwargs))


def dfu_state(device: Any) -> int:
    """The bState field of a DFU GETSTATUS reply."""
    return ctrl_transfer(device, REQUEST_TYPE_CLASS_IN, DfuRequest.GETSTATUS, data_or_wLength=b"\x00" * 6)[4]


def dfu_crc_trailer(buf: bytes) -> bytes:
    """The salt and little-endian CRC Apple's DFU expects after the last packet of an image."""
    crc = binascii.crc32(_DFU_CRC_SALT, binascii.crc32(buf, -1))
    return _DFU_CRC_SALT + struct.pack("<I", crc)


def _wait_for_dfu_state(device: Any, wanted: int, retries: int = DFU_STATUS_RETRIES) -> None:
    for _ in range(retries):
        if dfu_state(device) == wanted:
            return
        time.sleep(1)
    raise IRecvError(f"The device in DFU mode did not reach DFU state {wanted} after the upload.")


def upload_recovery(device: Any, buf: bytes, desc: str) -> None:
    """Upload ``buf`` to a device in Recovery mode over the bulk endpoint."""
    ctrl_transfer(device, REQUEST_TYPE_VENDOR_INTERFACE_OUT, 0)
    with ProgressBar(total=len(buf), desc=desc, unit=BYTES_UNIT) as bar:
        for offset in range(0, len(buf), RECOVERY_PACKET_SIZE):
            chunk = buf[offset : offset + RECOVERY_PACKET_SIZE]
            bar.update(len(chunk))
            n = cast(int, device.write(RECOVERY_BULK_ENDPOINT, chunk, timeout=USB_TIMEOUT))
            if n != len(chunk):
                raise OSError("failed to upload data")

    if len(buf) % 512 == 0:
        # Terminating zero-length packet.
        device.write(RECOVERY_BULK_ENDPOINT, b"", timeout=USB_TIMEOUT)


def _start_dfu_upload(device: Any) -> None:
    state = ctrl_transfer(device, REQUEST_TYPE_CLASS_IN, DfuRequest.GETSTATE, data_or_wLength=1)[0]
    logger.debug(f"irecv state: {state}")
    if state == DfuState.DFU_IDLE:
        return
    if state == DfuState.DFU_ERROR:
        ctrl_transfer(device, REQUEST_TYPE_CLASS_OUT, DfuRequest.CLRSTATUS)
        raise PyMobileDevice3Exception(
            "The device in DFU mode was in an error state, so the upload did not start. The error was "
            "cleared; retry the upload."
        )
    ctrl_transfer(device, REQUEST_TYPE_CLASS_OUT, DfuRequest.ABORT)
    raise PyMobileDevice3Exception(
        f"The device in DFU mode was not ready for an upload (DFU state {state}), so it was aborted. Retry the upload."
    )


def upload_dfu(device: Any, buf: bytes, desc: str) -> None:
    """
    Upload ``buf`` to a device in DFU or WTF mode and tell it the upload finished.

    The caller resets the device afterwards: it then runs the image.
    """
    _start_dfu_upload(device)
    trailer = dfu_crc_trailer(buf)
    num_packets = math.ceil(len(buf) / DFU_PACKET_SIZE)

    def dnload(packet_index: int, data: bytes) -> None:
        ctrl_transfer(
            device, REQUEST_TYPE_CLASS_OUT, DfuRequest.DNLOAD, wValue=packet_index, wIndex=0, data_or_wLength=data
        )

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
    _wait_for_dfu_state(device, DfuState.DFU_DNLOAD_IDLE)

    # a zero-length DNLOAD ends the upload
    ctrl_transfer(device, REQUEST_TYPE_CLASS_OUT, DfuRequest.DNLOAD, wValue=num_packets, wIndex=0)
    for _ in range(2):
        # idevicerestore reads the status twice here too
        dfu_state(device)
