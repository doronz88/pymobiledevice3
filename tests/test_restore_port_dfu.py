import plistlib
import struct
from types import SimpleNamespace
from typing import Any, Optional, cast

import pytest
from bpylist2 import archiver
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.ipsw import IPSW

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.irecv import (
    IRecv,
    Mode,
)
from pymobiledevice3.restore import recovery as recovery_module
from pymobiledevice3.restore.ace3 import (
    ACE3_MAGIC,
    ace3_crc,
    build_port_dfu_tss_parameters,
    create_ace3_binary,
    uarp_version_convert,
)
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Recovery
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse

# MacBook Air (M2, 2022): CPID 0x8112, BDID 0x28. The port controller reports them inside its own BDID.
MAC_CHIP_ID = 0x8112
MAC_BOARD_ID = 0x28
PORT_DFU_BOARD_ID = (MAC_BOARD_ID << 24) | (MAC_CHIP_ID << 8) | 0x01
PORT_DFU_CHIP_ID = 0x3A
PORT_DFU_ECID = 0x1122334455
PREV = 0x22
IM4M = b"IM4M-ticket"


def _reference_crc(data: bytes, salt: int = 0xFFFFFFFF) -> int:
    """idevicerestore ace3.c crc_buffer(), bit by bit."""
    result = salt
    for byte in data:
        for j in range(8):
            tmp0 = (2 * result) & 0xFFFFFFFF
            tmp2 = (result >> 31) ^ ((byte >> j) & 1)
            result = ((tmp2 + 2 * result) ^ 0x4C11DB6) & 0xFFFFFFFF
            if not tmp2:
                result = tmp0
    return result


@pytest.mark.parametrize("data", [b"", b"\x00", b"123456789", bytes(range(256)) * 3])
def test_ace3_crc_matches_idevicerestore(data: bytes) -> None:
    assert ace3_crc(data) == _reference_crc(data)


def test_uarp_version_convert() -> None:
    # BCD of 17.123.45, the 0xE00 major flag kept on top
    assert uarp_version_convert((17, 123, 45, 0)) == 0x01712345
    assert uarp_version_convert((0xE11, 123, 45, 0)) == 0xE1712345
    # out of range parts give 0
    assert uarp_version_convert((100, 0, 0, 0)) == 0
    assert uarp_version_convert((1, 1000, 0, 0)) == 0
    assert uarp_version_convert((1, 0, 100, 0)) == 0


def _uarp(entries: list[tuple[bytes, tuple[int, int, int, int], bytes]], metadata: dict[str, Any]) -> bytes:
    header_size = 0x2C
    toc_size = 0x28 * len(entries)
    data_offset = header_size + toc_size
    toc = b""
    payload_data = b""
    for tag, version, data in entries:
        toc += struct.pack(">I4s4IIIII", 0x28, tag, *version, 0, 0, data_offset + len(payload_data), len(data))
        payload_data += data
    plist_offset = data_offset + len(payload_data)
    header = struct.pack(">11I", 2, header_size, plist_offset, 0, 0, 0, 0, 0, 0, header_size, toc_size)
    return header + toc + payload_data + archiver.archive(metadata)


def _uarp_metadata(board_id: int = PORT_DFU_BOARD_ID, tags: str = "PDT1,PDT2") -> dict[str, Any]:
    return {
        "SuperBinary Payloads": [
            {"Payload 4CC": "OTHR", "Payload MetaData": {"Personalization Manifest Prefix": "Other"}},
            {
                "Payload 4CC": "DLD1",
                "Payload MetaData": {
                    "Personalization Manifest Prefix": "USBPortController",
                    "Personalization Board ID (64 bits)": board_id,
                    "Personalization Matching Data": [
                        {
                            "Personalization Matching Data Product Revision Minimum": 0,
                            "Personalization Matching Data Product Revision Maximum": 0x10,
                            "Personalization Matching Data Payload Tags": "OLD1,OLD2",
                        },
                        {
                            "Personalization Matching Data Product Revision Minimum": 0x20,
                            "Personalization Matching Data Product Revision Maximum": 0x2F,
                            "Personalization Matching Data Payload Tags": tags,
                        },
                    ],
                },
            },
        ]
    }


UARP_ENTRIES = [
    (b"OLD1", (1, 0, 0, 0), b"old-data-1"),
    (b"PDT1", (17, 123, 45, 0), b"data-one"),
    (b"DLD1", (0, 0, 0, 0), b"downloader"),
    (b"PDT2", (0, 0, 0, 0), b"data-two!"),
]


def test_ace3_binary_layout() -> None:
    binary = create_ace3_binary(
        _uarp(UARP_ENTRIES, _uarp_metadata()), PORT_DFU_BOARD_ID, PREV, {"USBPortController1,Ticket": IM4M}
    )

    content = b"data-one" + b"data-two!" + IM4M + b"downloader"
    header = struct.unpack("<10I3Q", binary[:0x40])
    assert header == (
        ACE3_MAGIC,
        0x01712345,  # version of the first data payload
        0x2800,
        0x40,
        len(b"data-one"),
        len(b"data-two!"),
        0x40 + len(b"data-one") + len(b"data-two!"),
        len(IM4M) + len(b"downloader"),
        len(content),
        _reference_crc(content),
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    )
    assert binary[0x40:] == content


def test_ace3_binary_requires_a_payload_for_the_board() -> None:
    with pytest.raises(PyMobileDevice3Exception, match="board ID"):
        create_ace3_binary(
            _uarp(UARP_ENTRIES, _uarp_metadata(board_id=1)),
            PORT_DFU_BOARD_ID,
            PREV,
            {"USBPortController1,Ticket": IM4M},
        )


def test_ace3_binary_requires_data_payloads_for_the_revision() -> None:
    with pytest.raises(PyMobileDevice3Exception, match="revision"):
        create_ace3_binary(
            _uarp(UARP_ENTRIES, _uarp_metadata()), PORT_DFU_BOARD_ID, 0x18, {"USBPortController1,Ticket": IM4M}
        )


USB_FIRMWARE_PATH = "Firmware/usbpc/ace3.uarp"
USB_FIRMWARE_ENTRY = {"Digest": b"digest", "Trusted": True, "Info": {"Path": USB_FIRMWARE_PATH}}


def _identity(variant: str, **extra: Any) -> dict[str, Any]:
    return {
        "ApBoardID": "0x28",
        "ApChipID": "0x8112",
        "USBPortController1,BoardID": PORT_DFU_BOARD_ID & 0xFFFFFFFF,
        "USBPortController1,ChipID": f"{PORT_DFU_CHIP_ID:#x}",
        "USBPortController1,SecurityDomain": 1,
        "Info": {
            "DeviceClass": "J413AP",
            "Variant": variant,
            "RestoreBehavior": "Update" if "Upgrade" in variant else "Erase",
            **extra,
        },
        "Manifest": {"USBPortController1,USBFirmware": USB_FIRMWARE_ENTRY},
    }


def test_port_dfu_tss_parameters() -> None:
    parameters = build_port_dfu_tss_parameters(_identity("Customer Erase Install (IPSW)"), PORT_DFU_ECID, b"nonce")

    assert parameters == {
        "@USBPortController1,Ticket": True,
        "USBPortController1,ECID": PORT_DFU_ECID,
        "USBPortController1,BoardID": PORT_DFU_BOARD_ID & 0xFFFFFFFF,
        "USBPortController1,ChipID": f"{PORT_DFU_CHIP_ID:#x}",
        "USBPortController1,SecurityDomain": 1,
        "USBPortController1,SecurityMode": True,
        "USBPortController1,ProductionMode": True,
        "USBPortController1,USBFirmware": {"Digest": b"digest", "Trusted": True},
        "USBPortController1,Nonce": b"nonce",
    }


class _FakeIPSW:
    def __init__(self, manifest: dict[str, Any], files: dict[str, bytes]) -> None:
        self.build_manifest = BuildManifest(self, plistlib.dumps(manifest))
        self._files = files

    def read(self, path: str) -> bytes:
        return self._files[path]


class _FakePortDfuIRecv:
    mode = Mode.PORT_DFU_MODE
    hardware_model = "j413ap"
    ecid = PORT_DFU_ECID
    chip_id = PORT_DFU_CHIP_ID
    port_dfu_board_id = PORT_DFU_BOARD_ID & 0xFFFFFFFF
    product_revision = PREV
    ap_nonce = b"\x01\x02\x03"
    is_image4_supported = True

    def __init__(self) -> None:
        self.uploads: list[tuple[bytes, Optional[str], bool]] = []

    def send_buffer(self, buf: bytes, desc: Optional[str] = None, small_packets: bool = False) -> None:
        self.uploads.append((buf, desc, small_packets))


@pytest.mark.asyncio
async def test_port_dfu_restore_boots_the_controller_and_switches_to_the_mac(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = {
        "ProductBuildVersion": "24A335",
        "ProductVersion": "27.0",
        "SupportedProductTypes": ["Mac14,2"],
        "BuildIdentities": [
            _identity("Customer Upgrade Install (IPSW)"),
            _identity("Customer Erase Install (IPSW)", MacOSVariant="macOS Customer"),
        ],
    }
    uarp = _uarp(UARP_ENTRIES, _uarp_metadata(board_id=PORT_DFU_BOARD_ID & 0xFFFFFFFF))
    port_dfu = _FakePortDfuIRecv()
    device = Device(irecv=cast(IRecv, port_dfu))
    device.get_ecid_value()  # cache the controller's ECID, which must not survive the switch
    recovery = Recovery(cast(IPSW, _FakeIPSW(manifest, {USB_FIRMWARE_PATH: uarp})), device)

    requests: list[dict[str, Any]] = []

    async def send_receive(self: TSSRequest) -> TSSResponse:
        requests.append(dict(self._request))
        return TSSResponse({"USBPortController1,Ticket": IM4M})

    mac = SimpleNamespace(ecid=0xAABBCCDD)
    reconnects: list[dict[str, Any]] = []

    def irecv_factory(**kwargs: Any) -> Any:
        reconnects.append(kwargs)
        return mac

    monkeypatch.setattr(TSSRequest, "send_receive", send_receive)
    monkeypatch.setattr(recovery_module, "IRecv", irecv_factory)

    await recovery.port_dfu_restore()

    (request,) = requests
    assert request["USBPortController1,ECID"] == PORT_DFU_ECID
    assert request["USBPortController1,Nonce"] == b"\x03\x02\x01"  # reported backwards
    assert "@HostPlatformInfo" in request
    ((binary, desc, small_packets),) = port_dfu.uploads
    assert binary == create_ace3_binary(uarp, PORT_DFU_BOARD_ID & 0xFFFFFFFF, PREV, {"USBPortController1,Ticket": IM4M})
    assert (desc, small_packets) == ("Ace3Binary", True)
    assert reconnects == [{"timeout": recovery_module.PORT_DFU_RECONNECT_TIMEOUT, "mode": Mode.DFU_MODE}]
    assert device.irecv is mac
    assert await device.get_ecid() == 0xAABBCCDD


@pytest.mark.asyncio
async def test_boot_ramdisk_leaves_port_dfu_before_fetching_tss(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = {
        "ProductBuildVersion": "24A335",
        "ProductVersion": "27.0",
        "SupportedProductTypes": ["Mac14,2"],
        "BuildIdentities": [_identity("Customer Upgrade Install (IPSW)")],
    }
    recovery = Recovery(cast(IPSW, _FakeIPSW(manifest, {})), Device(irecv=cast(IRecv, _FakePortDfuIRecv())))
    steps: list[str] = []

    async def port_dfu_restore() -> None:
        steps.append("port_dfu_restore")

    async def fetch_tss_record() -> TSSResponse:
        steps.append("fetch_tss_record")
        raise RuntimeError("stop here")

    monkeypatch.setattr(recovery, "port_dfu_restore", port_dfu_restore)
    monkeypatch.setattr(recovery, "fetch_tss_record", fetch_tss_record)

    with pytest.raises(RuntimeError, match="stop here"):
        await recovery.boot_ramdisk()
    assert steps == ["port_dfu_restore", "fetch_tss_record"]
