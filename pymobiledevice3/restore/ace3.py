"""
Ace3Binary: the personalized firmware a Port DFU USB-C port controller boots (idevicerestore ace3.c).

It is assembled from the UARP SuperBinary ``USBPortController1,USBFirmware`` the IPSW ships and the
``USBPortController1,Ticket`` TSS signs for the controller.
"""

import struct
from typing import Any, Optional, cast

from bpylist2 import archiver

from pymobiledevice3.exceptions import PyMobileDevice3Exception

ACE3_MAGIC = 0xACE00003
ACE3_HEADER = struct.Struct("<10I3Q")
# UARP SuperBinary header and payload header fields (big endian)
UARP_HEADER = struct.Struct(">11I")
UARP_PAYLOAD_HEADER = struct.Struct(">10I")

CRC_POLYNOMIAL = 0x04C11DB7


def _reverse_bits8(value: int) -> int:
    return int(f"{value:08b}"[::-1], 2)


def _crc_table() -> list[int]:
    table: list[int] = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            crc = ((crc << 1) ^ CRC_POLYNOMIAL) if crc & 0x80000000 else (crc << 1)
        table.append(crc & 0xFFFFFFFF)
    return table


_CRC_TABLE = _crc_table()
_REVERSED_BYTES = bytes(_reverse_bits8(i) for i in range(256))


def ace3_crc(data: bytes, salt: int = 0xFFFFFFFF) -> int:
    """
    idevicerestore ``crc_buffer``: a CRC-32 (polynomial 0x04C11DB7) shifted MSB first, without reflecting
    the register, but taking the bits of each byte LSB first.
    """
    crc = salt
    for byte in data.translate(_REVERSED_BYTES):
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC_TABLE[((crc >> 24) ^ byte) & 0xFF]
    return crc


def uarp_version_convert(version: tuple[int, int, int, int]) -> int:
    """Pack a UARP payload version into the Ace3Binary header field (idevicerestore ``uarp_version_convert``)."""
    major = version[0] - 0xE00 if version[0] >= 0xE00 else version[0]
    if major > 0x63:
        return 0
    major_flag = 0xE00 if version[0] >= 0xE00 else 0
    minor = version[1]
    if minor > 0x3E7:
        return 0
    release = version[2]
    if release > 0x63:
        return 0
    minor16 = minor & 0xFFFF
    major8 = major & 0xFF
    release8 = release & 0xFF
    minor_bcd = (
        (((0x147B * (minor16 >> 2)) >> 9) & 0x3FF00)
        | (0x10 * (((minor16 // 0xA) & 0xFF) % 0xA & 0xF))
        | (minor16 % 0xA)
    )
    result = (
        (minor_bcd << 8)
        | (((major8 % 0xA) | (0x10 * (major8 // 0xA)) | major_flag) << 20)
        | (release8 % 0xA)
        | (((0xCD * release8) >> 7) & 0xF0)
    )
    return result & 0xFFFFFFFF


def _find_payload_tags(uarp_plist: dict[str, Any], board_id: int, product_revision: int) -> tuple[str, str]:
    """Return the 4CC of the controller's payload and the tags of its data payloads for this board/revision."""
    for payload in uarp_plist.get("SuperBinary Payloads", []):
        meta = cast(dict[str, Any], payload).get("Payload MetaData")
        if not isinstance(meta, dict):
            continue
        meta = cast(dict[str, Any], meta)
        if meta.get("Personalization Manifest Prefix") != "USBPortController":
            continue
        if meta.get("Personalization Board ID (64 bits)") != board_id:
            continue
        payload_4cc = cast(str, payload["Payload 4CC"])
        for match in meta.get("Personalization Matching Data", []):
            if not isinstance(match, dict):
                break
            match = cast(dict[str, Any], match)
            minimum = match.get("Personalization Matching Data Product Revision Minimum", 0)
            maximum = match.get("Personalization Matching Data Product Revision Maximum", 0)
            if minimum <= product_revision <= maximum:
                return payload_4cc, cast(str, match["Personalization Matching Data Payload Tags"])
        raise PyMobileDevice3Exception(
            f"The USB port controller firmware has no data payloads for product revision {product_revision:#x}."
        )
    raise PyMobileDevice3Exception(f"The USB port controller firmware has no payload for board ID {board_id:#x}.")


def create_ace3_binary(uarp_fw: bytes, board_id: int, product_revision: int, tss: dict[str, Any]) -> bytes:
    """
    Build the Ace3Binary for a Port DFU device (idevicerestore ``ace3_create_binary``).

    :param uarp_fw: the ``USBPortController1,USBFirmware`` UARP SuperBinary from the IPSW
    :param board_id: the Port DFU device's BDID
    :param product_revision: the Port DFU device's PREV
    :param tss: the TSS response carrying ``USBPortController1,Ticket``
    """
    im4m = cast(bytes, tss["USBPortController1,Ticket"])

    # header fields used: [1] header size, [2] where the keyed-archive plist starts (it runs to the end of
    # the file), [9]/[10] offset and size of the payload headers
    header = UARP_HEADER.unpack_from(uarp_fw)
    header_size = header[1]
    plist_offset = header[2]
    toc_offset = header[9]
    toc_size = header[10]
    uarp_plist = cast(dict[str, Any], archiver.unarchive(uarp_fw[plist_offset:]))

    payload_4cc, data_tags = _find_payload_tags(uarp_plist, board_id, product_revision)
    data1_4cc = data_tags[:4]
    data2_4cc = data_tags[5:9]

    payloads: dict[str, bytes] = {}
    data1_version = 0
    # the payload headers follow the SuperBinary header
    offset = toc_offset or header_size
    toc_end = min(offset + toc_size, len(uarp_fw))
    while offset + UARP_PAYLOAD_HEADER.size <= toc_end:
        entry = UARP_PAYLOAD_HEADER.unpack_from(uarp_fw, offset)
        entry_size = entry[0]
        if entry_size == 0:
            break
        tag = uarp_fw[offset + 4 : offset + 8].decode("latin-1")
        data = uarp_fw[entry[8] : entry[8] + entry[9]]
        if tag == payload_4cc:
            payloads["dl"] = data
        elif tag == data1_4cc:
            payloads["data1"] = data
            data1_version = uarp_version_convert((entry[2], entry[3], entry[4], entry[5]))
        elif tag == data2_4cc:
            payloads["data2"] = data
        offset += entry_size

    dl = payloads.get("dl", b"")
    data1 = payloads.get("data1", b"")
    data2 = payloads.get("data2", b"")
    content = data1 + data2 + im4m + dl

    fill = 0xFFFFFFFFFFFFFFFF
    header_bytes = ACE3_HEADER.pack(
        ACE3_MAGIC,
        data1_version,
        0x00002800,
        ACE3_HEADER.size,
        len(data1),
        len(data2),
        ACE3_HEADER.size + len(data1) + len(data2),
        len(im4m) + len(dl),
        len(content),
        ace3_crc(content),
        fill,
        fill,
        fill,
    )
    return header_bytes + content


def build_port_dfu_tss_parameters(build_identity: dict[str, Any], ecid: int, nonce: Optional[bytes]) -> dict[str, Any]:
    """The entries of the ``USBPortController1,Ticket`` TSS request (idevicerestore Port DFU restore)."""
    manifest = cast(dict[str, Any], build_identity["Manifest"])
    usb_firmware = manifest.get("USBPortController1,USBFirmware")
    if usb_firmware is None:
        raise PyMobileDevice3Exception("Unable to find USBPortController1,USBFirmware in the build identity.")
    parameters: dict[str, Any] = {
        "@USBPortController1,Ticket": True,
        "USBPortController1,ECID": ecid,
    }
    for key in ("USBPortController1,BoardID", "USBPortController1,ChipID", "USBPortController1,SecurityDomain"):
        if key in build_identity:
            parameters[key] = build_identity[key]
    parameters["USBPortController1,SecurityMode"] = True
    parameters["USBPortController1,ProductionMode"] = True
    parameters["USBPortController1,USBFirmware"] = {
        key: value for key, value in cast(dict[str, Any], usb_firmware).items() if key != "Info"
    }
    parameters["USBPortController1,Nonce"] = nonce or b""
    return parameters
