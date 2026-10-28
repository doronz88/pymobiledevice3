import binascii
import struct
from array import array
from typing import Any, Optional, Union, cast

import pytest

from pymobiledevice3 import irecv
from pymobiledevice3.exceptions import IRecvError, IRecvNoDeviceConnectedError
from pymobiledevice3.irecv import client as irecv_client
from pymobiledevice3.irecv import transport
from pymobiledevice3.irecv._usb import UsbDevice
from pymobiledevice3.irecv.device_info import DeviceInfo, parse_nonce
from pymobiledevice3.irecv.transport import DfuTransport, RecoveryTransport

DFU_SERIAL = "CPID:8150 CPRV:11 CPFM:03 SCEP:01 BDID:0C ECID:001074523440401C IBFL:3C SRTG:[iBoot-11881.0.111]"
RECOVERY_SERIAL = "CPID:8150 CPRV:11 BDID:0C ECID:001074523440401C IBFL:3C SRNM:[ABCDEFGHIJ]"


def test_device_info_parses_the_usb_serial_number() -> None:
    info = DeviceInfo.parse(DFU_SERIAL)
    assert (info.chip_id, info.board_id, info.ecid, info.ibfl) == (0x8150, 0x0C, 0x001074523440401C, 0x3C)
    assert info.secure_rom_tag == "iBoot-11881.0.111"
    assert info.serial_number is None
    assert info.is_image4_supported

    info = DeviceInfo.parse(RECOVERY_SERIAL)
    assert info.serial_number == "ABCDEFGHIJ"
    assert info.secure_rom_tag is None


def test_device_info_reports_missing_fields_when_read() -> None:
    info = DeviceInfo.parse("CPID:8900 CPRV:01")
    assert info.chip_id == 0x8900
    with pytest.raises(IRecvError, match="ECID"):
        _ = info.ecid


def test_device_info_rejects_malformed_fields() -> None:
    with pytest.raises(IRecvError, match="Malformed"):
        DeviceInfo.parse("CPID:8150 garbage")


def test_parse_nonce() -> None:
    descriptor = "NONC:00112233 SNON:AABB"
    assert parse_nonce(descriptor, "NONC") == bytes.fromhex("00112233")
    assert parse_nonce(descriptor, "SNON") == bytes.fromhex("AABB")
    assert parse_nonce("NONC:00", "SNON") is None


class _FakeDfuDevice:
    """Records USB calls; reports dfuIDLE before an upload and ``final_state`` after it."""

    def __init__(self, final_state: int = transport.DfuState.DFU_DNLOAD_IDLE) -> None:
        self.final_state = final_state
        self.dnloads: list[tuple[int, bytes]] = []
        self.writes: list[bytes] = []

    def ctrl_transfer(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data_or_wLength: Union[None, int, bytes] = None,
        timeout: Optional[int] = None,
    ) -> Union["array[int]", int]:
        if bmRequestType == transport.REQUEST_TYPE_CLASS_IN and bRequest == transport.DfuRequest.GETSTATE:
            return array("B", [transport.DfuState.DFU_IDLE])
        if bmRequestType == transport.REQUEST_TYPE_CLASS_IN and bRequest == transport.DfuRequest.GETSTATUS:
            return array("B", [0, 0, 0, 0, self.final_state, 0])
        if bmRequestType == transport.REQUEST_TYPE_CLASS_OUT and bRequest == transport.DfuRequest.DNLOAD:
            data = data_or_wLength if isinstance(data_or_wLength, bytes) else b""
            self.dnloads.append((wValue, data))
            return len(data)
        return 0

    def write(self, endpoint: int, data: bytes, timeout: Optional[int] = None) -> int:
        assert endpoint == transport.RECOVERY_BULK_ENDPOINT
        self.writes.append(bytes(data))
        return len(data)


def _expected_trailer(buf: bytes) -> bytes:
    salt = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xAC, 0x05, 0x00, 0x01, 0x55, 0x46, 0x44, 0x10])
    return salt + struct.pack("<I", binascii.crc32(salt, binascii.crc32(buf, -1)))


@pytest.mark.parametrize(
    "size", [1, transport.DFU_PACKET_SIZE - 16, transport.DFU_PACKET_SIZE - 15, 3 * transport.DFU_PACKET_SIZE]
)
def test_dfu_upload_appends_the_crc_and_finishes(size: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport.time, "sleep", lambda seconds: None)
    buf = bytes(range(256)) * (size // 256) + bytes(size % 256)
    device = _FakeDfuDevice()

    DfuTransport(cast(UsbDevice, device)).upload(buf, "test")

    *data_packets, finish = device.dnloads
    assert finish == ((len(buf) + transport.DFU_PACKET_SIZE - 1) // transport.DFU_PACKET_SIZE, b"")
    assert b"".join(data for _, data in data_packets) == buf + _expected_trailer(buf)
    # the trailer goes into the last packet, or into one of its own when it does not fit
    last_chunk = len(buf) - (len(buf) - 1) // transport.DFU_PACKET_SIZE * transport.DFU_PACKET_SIZE
    assert len(data_packets[-1][1]) == (16 if last_chunk + 16 > transport.DFU_PACKET_SIZE else last_chunk + 16)


def test_dfu_upload_gives_up_when_the_device_never_settles(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(transport.time, "sleep", sleeps.append)
    with pytest.raises(IRecvError, match="did not reach"):
        DfuTransport(cast(UsbDevice, _FakeDfuDevice(final_state=transport.DfuState.DFU_ERROR))).upload(b"image", "test")
    assert len(sleeps) == transport.DFU_STATUS_RETRIES


@pytest.mark.parametrize(("size", "zlp"), [(1000, False), (1024, True)])
def test_recovery_upload_ends_full_packets_with_a_zlp(size: int, zlp: bool) -> None:
    device = _FakeDfuDevice()
    RecoveryTransport(cast(UsbDevice, device)).upload(bytes(size), "test")
    assert b"".join(device.writes) == bytes(size)
    assert (device.writes[-1] == b"") == zlp


class _FakeUsbDevice:
    idVendor = irecv.APPLE_VENDOR_ID
    idProduct = irecv.Mode.RECOVERY_MODE_2.value

    def __init__(self, ecid: int) -> None:
        self.serial_number = f"CPID:8150 CPRV:11 BDID:0C ECID:{ecid:016X} IBFL:3C SRNM:[ABCDEFGHIJ]"


def test_find_device_releases_the_devices_it_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    devices = [_FakeUsbDevice(1), _FakeUsbDevice(2), _FakeUsbDevice(3)]
    disposed: list[Any] = []
    monkeypatch.setattr(irecv_client, "find", lambda find_all=False, **kwargs: list(devices))
    monkeypatch.setattr(irecv_client, "dispose_resources", disposed.append)

    found = irecv_client._find_device(ecid=2, timeout=0, is_recovery=None)

    assert found is not None and found.device is devices[1]
    assert disposed == [devices[0]]


def test_closing_releases_the_device(monkeypatch: pytest.MonkeyPatch) -> None:
    disposed: list[Any] = []
    monkeypatch.setattr(irecv_client, "dispose_resources", disposed.append)
    client = irecv.IRecv.__new__(irecv.IRecv)
    device = _FakeUsbDevice(1)
    client._device = cast(UsbDevice, device)
    client._mode = irecv.Mode.RECOVERY_MODE_2
    client._info = DeviceInfo.parse(device.serial_number)
    client.ap_nonce = client.sep_nonce = b"n"

    with client:
        assert client.ecid == 1

    assert disposed == [device]
    assert client.ap_nonce is None
    assert client._transport is None
    with pytest.raises(IRecvNoDeviceConnectedError):
        _ = client.device


def _client_in(mode: irecv.Mode, device: Any) -> irecv.IRecv:
    client = irecv.IRecv.__new__(irecv.IRecv)
    client._device = cast(UsbDevice, device)
    client._mode = mode
    client._info = DeviceInfo.parse(RECOVERY_SERIAL)
    usb_device = cast(UsbDevice, device)
    client._transport = RecoveryTransport(usb_device) if mode.is_recovery else DfuTransport(usb_device)
    client.ap_nonce = client.sep_nonce = None
    return client


def test_iboot_commands_need_recovery_mode() -> None:
    client = _client_in(irecv.Mode.DFU_MODE, _FakeDfuDevice())
    with pytest.raises(IRecvError, match="Recovery mode"):
        client.send_command("go")
    with pytest.raises(IRecvError, match="Recovery mode"):
        client.send_zero_length_download()
    # as before the split: nothing to read and nothing to reboot
    assert client.getenv("build-version") is None
    client.reboot()


def test_dfu_state_needs_dfu_mode() -> None:
    client = _client_in(irecv.Mode.RECOVERY_MODE_2, _FakeDfuDevice())
    with pytest.raises(IRecvError, match="DFU"):
        _ = client.status


def test_dfu_upload_resets_the_device(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport.time, "sleep", lambda seconds: None)
    client = _client_in(irecv.Mode.DFU_MODE, _FakeDfuDevice())
    resets: list[bool] = []
    monkeypatch.setattr(client, "reset", lambda: resets.append(True))
    client.send_buffer(b"image")
    assert resets == [True]
