import struct
from typing import Any, Optional, cast

import pytest

from pymobiledevice3 import irecv as irecv_module
from pymobiledevice3.irecv import KIS_REQ_HEADER, IRecv, Mode, kis_read_string, kis_request_header

# MacBook Air (M2, 2022): CPID 0x8112, BDID 0x28. The port controller reports them inside its own BDID.
PORT_DFU_BOARD_ID = (0x28 << 24) | (0x8112 << 8) | 0x01
PORT_DFU_CHIP_ID = 0x3A


def test_port_dfu_device_maps_to_the_mac_model() -> None:
    irecv = IRecv.__new__(IRecv)
    irecv._mode = Mode.PORT_DFU_MODE
    irecv._device_info = {"CPID": f"{PORT_DFU_CHIP_ID:04X}", "BDID": f"{PORT_DFU_BOARD_ID:X}", "PREV": "22"}

    assert irecv.hardware_model == "j413ap"
    assert irecv.product_revision == 0x22
    assert not Mode.PORT_DFU_MODE.is_recovery


class _FakeUsbDevice:
    def __init__(self, replies: Optional[list[bytes]] = None) -> None:
        self.writes: list[tuple[int, bytes]] = []
        self.reads: list[tuple[int, int]] = []
        self.ctrl: list[tuple[int, int, int, Any]] = []
        self.replies = replies or []
        self.was_reset = False
        self.bus, self.address = 1, 2

    def write(self, endpoint: int, data: bytes, timeout: int = 0) -> int:
        self.writes.append((endpoint, bytes(data)))
        return len(data)

    def read(self, endpoint: int, size: int, timeout: int = 0) -> bytes:
        self.reads.append((endpoint, size))
        return (
            self.replies.pop(0)
            if self.replies
            else KIS_REQ_HEADER.pack(0, 0, 0, 0, 0, 0, 0, 0) + struct.pack("<II", 4, 0)
        )

    def ctrl_transfer(
        self, bmRequestType: int, bRequest: int, wValue: int = 0, wIndex: int = 0, data_or_wLength: Any = None, **_: Any
    ) -> Any:
        self.ctrl.append((bmRequestType, bRequest, wValue, data_or_wLength))
        if bRequest == 5:
            return [2]  # DFU idle
        if bRequest == 3:
            return [0, 0, 0, 0, 5, 0]  # DFU status: download idle
        return len(data_or_wLength) if isinstance(data_or_wLength, (bytes, bytearray)) else 0

    def reset(self) -> None:
        self.was_reset = True


def test_kis_request_headers_match_libirecovery() -> None:
    assert kis_request_header(0x01, 0x0A, 1, 0, 1) == bytes.fromhex("0000a001010a040004000000")
    # 10-bit index and 14-bit reply word count are split across the header bytes
    assert kis_request_header(0x10, 0x100, 0, 0, 0xC0) == bytes.fromhex("0000a0100000010300000000")
    assert kis_request_header(0x10, 0x0D, 3, 0x4000, 0) == bytes.fromhex("0000a010030d00000c400000")


def _string_descriptor(text: str) -> bytes:
    encoded = text.encode("utf-16-le")
    return bytes([len(encoded), 3]) + encoded


def _kis_info_reply(serial: str, nonces: str, product_id: int) -> bytes:
    info = bytearray(0x308)
    serial_word, nonce_word = 0x30, 0x80
    struct.pack_into("<I", info, 24, nonce_word)
    descriptor = bytearray(18)
    struct.pack_into("<HH", descriptor, 8, 0x05AC, product_id)
    descriptor[16] = serial_word
    info[64:82] = descriptor
    for word, text in ((serial_word, serial), (nonce_word, nonces)):
        encoded = _string_descriptor(text)
        info[word * 4 : word * 4 + len(encoded)] = encoded
    return KIS_REQ_HEADER.pack(0, 0xA0, 0x10, 0, 0, 0, 0, 0) + bytes(info)


def test_kis_device_info_is_parsed() -> None:
    reply = _kis_info_reply("CPID:8112 BDID:28 ECID:0000000AABBCCDD", "NONC:0102 SNON:0304", Mode.DFU_MODE.value)

    serial, nonces, product_id = IRecv.parse_kis_device_info(reply)

    assert serial == "CPID:8112 BDID:28 ECID:0000000AABBCCDD"
    assert nonces == "NONC:0102 SNON:0304"
    assert product_id == Mode.DFU_MODE.value
    # an odd length, a non-string descriptor or one running past the buffer is rejected
    assert kis_read_string(bytes([3, 3, 0, 0]), 0) is None
    assert kis_read_string(bytes([2, 1, 0x41, 0]), 0) is None
    assert kis_read_string(bytes([8, 3, 0x41, 0]), 0) is None


def test_kis_init_enables_kis_and_takes_the_reported_mode() -> None:
    usb = _FakeUsbDevice(
        replies=[
            KIS_REQ_HEADER.pack(0, 0, 0, 0, 0, 0, 0, 0) + struct.pack("<II", 4, 0),
            KIS_REQ_HEADER.pack(0, 0, 0, 0, 0, 0, 0, 0) + struct.pack("<II", 4, 0),
            _kis_info_reply("CPID:8112 BDID:28 ECID:0000000AABBCCDD", "NONC:0102 SNON:0304", Mode.DFU_MODE.value),
        ]
    )
    irecv = IRecv.__new__(IRecv)
    irecv._device = cast(Any, usb)
    irecv._device_info = {}
    irecv._is_kis = False

    irecv._kis_init()

    assert usb.writes == [
        (1, kis_request_header(0x01, 0x0A, 1, 0, 1) + struct.pack("<I", 0x21)),
        (1, kis_request_header(0x01, 0x14, 1, 0, 1) + struct.pack("<I", 0x01)),
        (3, kis_request_header(0x10, 0x100, 0, 0, 0xC0)),
    ]
    assert usb.reads == [(0x81, 20), (0x81, 20), (0x83, 0x314)]
    assert irecv.is_kis
    assert irecv.mode == Mode.DFU_MODE
    assert irecv.ecid == 0xAABBCCDD


def test_kis_upload_is_chunked_and_booted(monkeypatch: pytest.MonkeyPatch) -> None:
    usb = _FakeUsbDevice()
    irecv = IRecv.__new__(IRecv)
    irecv._device = cast(Any, usb)
    irecv._mode = Mode.DFU_MODE
    irecv._is_kis = True
    irecv._device_info = {"ECID": "AABBCCDD"}
    reinits: list[Any] = []
    monkeypatch.setattr(irecv_module, "find", lambda find_all=False: [])
    monkeypatch.setattr(irecv_module, "dispose_resources", lambda device: None)
    monkeypatch.setattr(IRecv, "_reinit", lambda self, **kwargs: reinits.append(kwargs))

    image = bytes(range(256)) * 0x41  # 0x4100 bytes: one full chunk and one of 0x100
    irecv.send_buffer(image)

    upload_header = kis_request_header(0x10, 0x0D, 3, 0x4000, 0)
    assert usb.writes == [
        (3, upload_header + struct.pack("<QI", 0, 0x4000) + image[:0x4000]),
        (3, kis_request_header(0x10, 0x0D, 3, 0x100, 0) + struct.pack("<QI", 0x4000, 0x100) + image[0x4000:]),
        (3, kis_request_header(0x10, 0x103, 1, 0, 1) + struct.pack("<I", len(image))),
    ]
    assert reinits == [{"ecid": 0xAABBCCDD}]


def test_port_dfu_upload_uses_small_packets_without_crc_and_does_not_reconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    usb = _FakeUsbDevice()
    irecv = IRecv.__new__(IRecv)
    irecv._device = cast(Any, usb)
    irecv._mode = Mode.PORT_DFU_MODE
    irecv._is_kis = False
    irecv._device_info = {"ECID": "1122334455"}
    monkeypatch.setattr(irecv_module, "dispose_resources", lambda device: None)
    monkeypatch.setattr(IRecv, "_reinit", lambda self, **kwargs: pytest.fail("must not look for the controller again"))

    image = bytes(range(100))
    irecv.send_buffer(image, small_packets=True)

    downloads = [
        (value, data) for request_type, request, value, data in usb.ctrl if (request_type, request) == (0x21, 1)
    ]
    assert downloads == [(0, image[:0x40]), (1, image[0x40:]), (2, None)]
    assert usb.was_reset
    assert irecv._device is None
