"""The identity a device in Recovery/DFU mode reports through its USB string descriptors."""

import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional

from pymobiledevice3.exceptions import IRecvError

CPFM_FLAG_SECURITY_MODE = 1 << 0
CPFM_FLAG_PRODUCTION_MODE = 1 << 1

IBOOT_FLAG_IMAGE4_AWARE = 1 << 2
IBOOT_FLAG_EFFECTIVE_SECURITY_MODE = 1 << 3
IBOOT_FLAG_EFFECTIVE_PRODUCTION_MODE = 1 << 4


@dataclass(frozen=True)
class DeviceInfo:
    """
    The fields of the USB serial number string, e.g.
    ``CPID:8150 CPRV:11 BDID:0C ECID:001074523440401C IBFL:3C SRNM:[ABCDEFGHIJ]``.
    """

    fields: Mapping[str, str]

    @classmethod
    def parse(cls, serial_number: str) -> "DeviceInfo":
        """
        :raises IRecvError: if a field is not ``KEY:VALUE``.
        """
        fields: dict[str, str] = {}
        for component in serial_number.split(" "):
            key, sep, value = component.partition(":")
            if not sep:
                raise IRecvError(f"Malformed field {component!r} in the USB serial number {serial_number!r}.")
            if key in ("SRNM", "SRTG") and "[" in value:
                # trim the `[]`
                value = value[1:-1]
            fields[key] = value
        return cls(fields)

    def _hex_field(self, key: str) -> int:
        """
        :raises IRecvError: if the device did not report the field or it is not a hex number.
        """
        value = self.fields.get(key)
        if value is None:
            raise IRecvError(f"The device in Recovery/DFU mode did not report {key}.")
        try:
            return int(value, 16)
        except ValueError:
            raise IRecvError(f"The device in Recovery/DFU mode reported a malformed {key}: {value!r}.") from None

    @property
    def ecid(self) -> int:
        return self._hex_field("ECID")

    @property
    def chip_id(self) -> int:
        return self._hex_field("CPID")

    @property
    def board_id(self) -> int:
        return self._hex_field("BDID")

    @property
    def ibfl(self) -> int:
        return self._hex_field("IBFL")

    @property
    def serial_number(self) -> Optional[str]:
        """The device's serial number (SRNM), if reported."""
        return self.fields.get("SRNM")

    @property
    def secure_rom_tag(self) -> Optional[str]:
        """The SecureROM tag (SRTG); a device still reporting it after iBSS was sent never left DFU mode."""
        return self.fields.get("SRTG")

    @property
    def is_image4_supported(self) -> bool:
        return bool(self.ibfl & IBOOT_FLAG_IMAGE4_AWARE)

    def __str__(self) -> str:
        return str(dict(self.fields))


def parse_nonce(descriptor: str, tag: str) -> Optional[bytes]:
    """Return the hex nonce ``tag`` (``NONC`` or ``SNON``) carries in a USB string descriptor, if any."""
    if tag not in descriptor:
        return None
    return binascii.unhexlify(descriptor.split(f"{tag}:")[1].split(" ")[0])
