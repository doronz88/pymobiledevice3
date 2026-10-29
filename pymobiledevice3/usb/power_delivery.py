"""
Apple's USB Power Delivery commands, sent from a Mac's own USB-C port controller.

Apple devices accept a few Apple-defined USB-PD messages (Vendor Defined Messages) on the USB-C CC line, handled by
the device's USB-C controller rather than by iOS: one of them reboots the device, with no pairing and in any boot
stage the controller is up in (normal mode and Recovery mode are verified). A Mac sends them through the port
controller's user-space plug-in, ``AppleHPMLib``, which only root can open, and only on ports with an Apple PD
controller ("AppleHPM": the Thunderbolt/USB4 ports). A PD message only reaches the device at the other end of the
cable, so a hub in between hides the device.

The controller's register and command interface follows AsahiLinux's macvdmtool.
"""

import ctypes
import os
import re
import struct
import sys
import time
from ctypes import POINTER, byref, c_char_p, c_int32, c_uint8, c_uint32, c_uint64, c_void_p
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.irecv._usb import APPLE_VENDOR_ID, Mode

if sys.platform == "darwin":
    from pymobiledevice3.usb import _iokit

KIS_PRODUCT_ID = 0x1881

# Structured VDM header: Apple's SVID, structured, command 0x12 (an Apple-defined "action")
_APPLE_VDM_HEADER = (APPLE_VENDOR_ID << 16) | 0x8012
_REBOOT_VDOS = (0x00000105, 0x80000000)

# The AppleHPMLib plug-in (macvdmtool's AppleHPMLib.h)
_HPM_PLUGIN_TYPE = (0x12, 0xA1, 0xDC, 0xCF, 0xCF, 0x7A, 0x47, 0x75, 0xBE, 0xE5, 0x9C, 0x43, 0x19, 0xF4, 0xCD, 0x2B)
_HPM_INTERFACE = (0xC1, 0x3A, 0xCD, 0xD9, 0x20, 0x9E, 0x4B, 0x01, 0xB7, 0xBE, 0xE0, 0x5C, 0xD8, 0x83, 0xC7, 0xB1)
# vtable slots after IUnknown and two 16-bit fields
_HPM_READ = 5
_HPM_WRITE = 6
_HPM_COMMAND = 7

_REG_MODE = 0x03
_REG_DATA = 0x09
_REG_RX_VDM = 0x4D
_DEBUG_MODE = "DBMa"
_VDM_REPLY_POLLS = 16
_VDM_REPLY_INTERVAL = 0.01


class PowerDeliveryError(PyMobileDevice3Exception):
    pass


class VdmReply(IntEnum):
    """The command type bits of a structured VDM reply header."""

    REQUEST = 0x00
    ACK = 0x40
    NAK = 0x80
    BUSY = 0xC0


@dataclass(frozen=True)
class ApplePort:
    """An Apple device at the other end of a USB-C port that can send it PD messages."""

    port: int
    # what the device enumerates as on the port's USB 2 lines, when it does
    product: Optional[str]
    product_id: Optional[int]
    serial: Optional[str]

    @property
    def mode(self) -> str:
        if self.product_id is None:
            return "not on USB"
        if self.product_id == KIS_PRODUCT_ID:
            return "DFU mode"
        mode = Mode.get_mode_from_value(self.product_id)
        if mode is None:
            return "normal mode"
        return "Recovery mode" if mode.is_recovery else "DFU mode"

    @property
    def ecid(self) -> Optional[int]:
        return ecid_from_usb_serial(self.serial)

    def describe(self) -> str:
        ecid = self.ecid
        ecid_text = "" if ecid is None else f", ECID {ecid:#x}"
        # in Recovery/DFU the product string is the mode's name ("Apple Mobile Device (Recovery Mode)")
        product = self.product if self.mode == "normal mode" and self.product else "Apple device"
        return f"{product} in {self.mode} on Port-USB-C@{self.port}{ecid_text}"


def ecid_from_usb_serial(serial: Optional[str]) -> Optional[int]:
    """The ECID in a USB serial number: ``ECID:<hex>`` in Recovery/DFU, the UDID (CPID + ECID) when booted."""
    if not serial:
        return None
    match = re.search(r"\bECID:([0-9A-Fa-f]+)", serial)
    if match:
        return int(match.group(1), 16)
    if re.fullmatch(r"[0-9A-Fa-f]{24}", serial):
        return int(serial[8:], 16)
    return None


def apple_ports_from_registry(
    ports: list[dict[str, Any]], sop_identities: list[dict[str, Any]], usb2_states: list[dict[str, Any]]
) -> list[ApplePort]:
    """Pair each PD-capable port (``PortNumber``) with an Apple PD partner and the USB device it enumerated."""
    apple_ports: list[ApplePort] = []
    for port in ports:
        number = port.get("PortNumber")
        if number is None:
            continue
        if not any(
            sop.get("ParentPortNumber") == number and sop.get("Vendor ID") == APPLE_VENDOR_ID for sop in sop_identities
        ):
            continue
        usb: dict[str, Any] = {}
        for state in usb2_states:
            if state.get("ParentPortNumber") == number:
                usb = state.get("Metadata") or {}
        apple_ports.append(ApplePort(number, usb.get("Product"), usb.get("Product ID"), usb.get("Serial Number")))
    return apple_ports


def _require_macos() -> None:
    if sys.platform != "darwin":
        raise PowerDeliveryError("Sending USB Power Delivery messages is only supported on macOS.")


def list_apple_ports() -> list[ApplePort]:
    """Every Apple device directly on one of this Mac's PD-capable USB-C ports."""
    _require_macos()

    def all_properties(class_name: str, keys: tuple[str, ...]) -> list[dict[str, Any]]:
        with _iokit.matching_services(class_name) as services:
            return [{key: _iokit.get_property(service, key) for key in keys} for service in services]

    return apple_ports_from_registry(
        all_properties("AppleHPMInterface", ("PortNumber",)),
        all_properties("IOPortTransportComponentCCUSBPDSOP", ("ParentPortNumber", "Vendor ID")),
        all_properties("IOPortTransportStateUSB2", ("ParentPortNumber", "Metadata")),
    )


def _unlock_key() -> int:
    """The port controller's unlock key: the first four characters of the Mac's board name (e.g. ``J773``)."""
    with _iokit.matching_services("IOPlatformExpertDevice") as services:
        if not services:
            raise PowerDeliveryError("Could not find this Mac's board name.")
        board = _iokit.name(services[0])
    return struct.unpack(">I", board[:4].encode())[0]


class PortController:
    """One port's Apple PD controller, opened through ``AppleHPMLib`` (needs root)."""

    def __init__(self, port: int) -> None:
        _require_macos()
        self.port = port
        self._interface = self._open(port)
        self._closed = False

    @staticmethod
    def _open(port: int) -> c_void_p:
        with _iokit.matching_services("AppleHPMInterface") as interfaces:
            for interface in interfaces:
                if _iokit.get_property(interface, "PortNumber") != port:
                    continue
                controller = _iokit.ancestor(interface, "AppleHPM")
                try:
                    return _iokit.create_interface(
                        controller, _iokit.uuid(*_HPM_PLUGIN_TYPE), _iokit.uuid(*_HPM_INTERFACE)
                    )
                except _iokit.IOKitError as e:
                    if os.geteuid() != 0:
                        raise PowerDeliveryError(
                            "Sending USB Power Delivery messages needs root: rerun the command with sudo."
                        ) from e
                    raise PowerDeliveryError(f"Could not open the USB-C controller of Port-USB-C@{port}: {e}") from e
                finally:
                    _iokit.release_object(controller)
        raise PowerDeliveryError(f"Port-USB-C@{port} has no Apple USB-C PD controller.")

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _iokit.release(self._interface)

    def __enter__(self) -> "PortController":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def read(self, register: int) -> bytes:
        buffer = ctypes.create_string_buffer(64)
        length = c_uint64()
        kr = _iokit.com_call(
            self._interface,
            _HPM_READ,
            c_int32,
            [c_uint64, c_uint8, c_void_p, c_uint64, c_uint32, POINTER(c_uint64)],
            0,
            register,
            buffer,
            len(buffer),
            0,
            byref(length),
        )
        if kr:
            raise PowerDeliveryError(
                f"Reading register {register:#x} of Port-USB-C@{self.port} failed: {kr & 0xFFFFFFFF:#x}"
            )
        return buffer.raw

    def command(self, command: str, args: bytes = b"") -> bool:
        """Run a four-character controller command; True when the controller reports success."""
        if args:
            kr = _iokit.com_call(
                self._interface,
                _HPM_WRITE,
                c_int32,
                [c_uint64, c_uint8, c_char_p, c_uint64, c_uint32],
                0,
                _REG_DATA,
                args,
                len(args),
                0,
            )
            if kr:
                return False
        kr = _iokit.com_call(
            self._interface,
            _HPM_COMMAND,
            c_int32,
            [c_uint64, c_uint32, c_uint32],
            0,
            struct.unpack(">I", command.encode())[0],
            0,
        )
        return kr == 0 and self.read(_REG_DATA)[0] & 0xF == 0

    @property
    def mode(self) -> str:
        return self.read(_REG_MODE).split(b"\0")[0].decode(errors="replace")

    def enter_debug_mode(self) -> bool:
        """Unlock the controller and switch it to the mode that sends VDMs; True if it was switched by this call."""
        if self.mode == _DEBUG_MODE:
            return False
        key = struct.pack("<I", _unlock_key())
        if not self.command("LOCK", key) and not (self.command("Gaid") and self.command("LOCK", key)):
            raise PowerDeliveryError(f"Could not unlock the USB-C controller of Port-USB-C@{self.port}.")
        if not self.command(_DEBUG_MODE, b"\x01") or self.mode != _DEBUG_MODE:
            raise PowerDeliveryError(f"The USB-C controller of Port-USB-C@{self.port} did not enter VDM mode.")
        return True

    def leave_debug_mode(self) -> None:
        self.command(_DEBUG_MODE, b"\x00")

    def send_vdm(self, header: int, vdos: tuple[int, ...]) -> VdmReply:
        """Send a structured VDM and return how the device answered it."""
        before = self.read(_REG_RX_VDM)[0]
        words = (header, *vdos)
        if not self.command("VDMs", bytes([(3 << 4) | len(words)]) + struct.pack(f"<{len(words)}I", *words)):
            raise PowerDeliveryError(f"The USB-C controller of Port-USB-C@{self.port} could not send the message.")
        for _ in range(_VDM_REPLY_POLLS):
            reply = self.read(_REG_RX_VDM)
            if reply[0] != before:
                (reply_header,) = struct.unpack_from("<I", reply, 1)
                if reply_header & ~0xC0 != header & ~0xC0:
                    raise PowerDeliveryError(f"Unexpected reply {reply_header:#010x} to VDM {header:#010x}.")
                return VdmReply(reply_header & 0xC0)
            time.sleep(_VDM_REPLY_INTERVAL)
        raise PowerDeliveryError(f"The device on Port-USB-C@{self.port} did not answer the message.")


def reboot(port: int) -> None:
    """Reboot the Apple device on ``port`` (needs root)."""
    with PortController(port) as controller:
        switched = controller.enter_debug_mode()
        try:
            reply = controller.send_vdm(_APPLE_VDM_HEADER, _REBOOT_VDOS)
        finally:
            if switched:
                controller.leave_debug_mode()
    if reply != VdmReply.ACK:
        raise PowerDeliveryError(f"The device on Port-USB-C@{port} refused to reboot (reply: {reply.name}).")
