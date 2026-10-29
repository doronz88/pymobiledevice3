import binascii
import struct
from array import array
from typing import Any, Optional, cast

import pytest

from pymobiledevice3 import irecv
from pymobiledevice3.exceptions import IRecvError, IRecvNoDeviceConnectedError
from pymobiledevice3.irecv import client as irecv_client
from pymobiledevice3.irecv import transport
from pymobiledevice3.irecv._usb import UsbDevice
from pymobiledevice3.irecv.device_info import DeviceInfo, parse_nonce
from pymobiledevice3.irecv.transport import DeviceInterfaceTransport, DfuTransport, KisTransport, RecoveryTransport
from pymobiledevice3.usb import device_interface

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

    def control_in(
        self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, length: int, timeout: Optional[int] = None
    ) -> bytes:
        if bmRequestType == transport.REQUEST_TYPE_CLASS_IN and bRequest == transport.DfuRequest.GETSTATE:
            return bytes([transport.DfuState.DFU_IDLE])
        if bmRequestType == transport.REQUEST_TYPE_CLASS_IN and bRequest == transport.DfuRequest.GETSTATUS:
            return bytes([0, 0, 0, 0, self.final_state, 0])
        return b""

    def control_out(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data: bytes = b"",
        timeout: Optional[int] = None,
    ) -> int:
        if bmRequestType == transport.REQUEST_TYPE_CLASS_OUT and bRequest == transport.DfuRequest.DNLOAD:
            self.dnloads.append((wValue, data))
        return len(data)

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
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_find_device_releases_the_devices_it_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    devices = [_FakeUsbDevice(1), _FakeUsbDevice(2), _FakeUsbDevice(3)]
    monkeypatch.setattr(irecv_client, "list_devices", lambda: list(devices))

    found = irecv_client._find_device(ecid=2, timeout=0, is_recovery=None)

    assert found is not None and found.device is devices[1]
    # the ones before it were skipped and the one after it never looked at: all but the found one are released
    assert [device.closed for device in devices] == [True, False, True]


def test_closing_releases_the_device() -> None:
    client = irecv.IRecv.__new__(irecv.IRecv)
    device = _FakeUsbDevice(1)
    client._device = cast(UsbDevice, device)
    client._mode = irecv.Mode.RECOVERY_MODE_2
    client._info = DeviceInfo.parse(device.serial_number)
    client.ap_nonce = client.sep_nonce = b"n"

    with client:
        assert client.ecid == 1

    assert device.closed
    assert client.ap_nonce is None
    assert client._transport is None
    with pytest.raises(IRecvNoDeviceConnectedError):
        _ = client.device


def test_ctrl_transfer_keeps_the_pyusb_shape() -> None:
    device = _FakeDfuDevice()
    client = _client_in(irecv.Mode.DFU_MODE, device)

    status = client.ctrl_transfer(transport.REQUEST_TYPE_CLASS_IN, transport.DfuRequest.GETSTATUS, 0, 0, 6)
    assert status == array("B", [0, 0, 0, 0, transport.DfuState.DFU_DNLOAD_IDLE, 0])
    assert client.ctrl_transfer(transport.REQUEST_TYPE_CLASS_OUT, transport.DfuRequest.DNLOAD, 3, 0, b"abc") == 3
    assert device.dnloads == [(3, b"abc")]


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


KIS_DFU_SERIAL = "CPID:8150 CPRV:11 CPFM:03 SCEP:01 BDID:0C ECID:001074523440401C IBFL:3C SRTG:[iBoot-11881.0.111]"


def _string_descriptor(text: str) -> bytes:
    encoded = text.encode("utf-16-le")
    return bytes([len(encoded), 3]) + encoded


def _kis_info_reply(serial: str, nonces: str, product_id: int) -> bytes:
    """A GET_INFO reply: the device descriptor at 64, the serial string at word 32, the nonces right after it."""
    payload = bytearray(transport.KIS_DEVICE_INFO_SIZE)
    serial_descriptor = _string_descriptor(serial)
    nonce_word = (128 + len(serial_descriptor) + 3) // 4
    struct.pack_into("<I", payload, transport.KIS_INFO_NONCE_OFFSET, nonce_word)
    descriptor = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x200, 0, 0, 0, 64, 0x05AC, product_id, 0, 1, 2, 32, 1)
    payload[transport.KIS_INFO_DEVICE_DESCRIPTOR : transport.KIS_INFO_DEVICE_DESCRIPTOR + 18] = descriptor
    payload[128 : 128 + len(serial_descriptor)] = serial_descriptor
    nonce_descriptor = _string_descriptor(nonces)
    payload[nonce_word * 4 : nonce_word * 4 + len(nonce_descriptor)] = nonce_descriptor
    return bytes(transport.KIS_HEADER.size) + bytes(payload) + struct.pack("<II", transport.KIS_DEVICE_INFO_SIZE, 0)


class _FakeKisDevice:
    """Answers KIS requests the way an A16 or later device in DFU mode does."""

    idVendor = irecv.APPLE_VENDOR_ID
    idProduct = irecv_client.KIS_PRODUCT_ID
    serial_number = None

    def __init__(self, serial: str = KIS_DFU_SERIAL, product_id: int = irecv.Mode.DFU_MODE.value) -> None:
        self.info_reply = _kis_info_reply(serial, "NONC:00112233 SNON:AABB", product_id)
        self.requests: list[bytes] = []
        self.configuration = 0
        self.closed = False
        self.gone = False

    def get_configuration(self) -> int:
        return self.configuration

    def set_configuration(self, configuration: int) -> None:
        self.configuration = configuration

    def set_interface_altsetting(self, interface: int, alternate_setting: int) -> None:
        assert (interface, alternate_setting) == (0, 0)

    def write(self, endpoint: int, data: bytes, timeout: Optional[int] = None) -> int:
        assert endpoint == transport.KIS_PORTAL_ENDPOINTS[data[3]]
        self.requests.append(bytes(data))
        return len(data)

    def read(self, endpoint: int, size: int, timeout: Optional[int] = None) -> bytes:
        index = self.requests[-1][5] | ((self.requests[-1][6] & 0x3) << 8)
        if index == transport.KIS_INDEX_GET_INFO:
            return self.info_reply[:size]
        return bytes(transport.KIS_HEADER.size) + struct.pack("<II", 4, 0)

    def wait_until_gone(self, timeout: float) -> bool:
        return self.gone

    def close(self) -> None:
        self.closed = True


def test_kis_header_matches_libirecovery() -> None:
    # GET_INFO asking for 0x300 bytes back (irecv_kis_request_init)
    header = transport.kis_header(transport.KIS_PORTAL_RSM, transport.KIS_INDEX_GET_INFO, 0, 0, 0x300 // 4)
    assert header == bytes.fromhex("0000a01000000103") + bytes(4)
    # an upload chunk: three argument words, then the data
    assert struct.unpack("<I", transport.kis_header(transport.KIS_PORTAL_RSM, 0x0D, 3, 0x4000, 0)[8:]) == (0x400C,)


def test_kis_device_info_parses_the_get_info_reply() -> None:
    info = transport.KisDeviceInfo.parse(_kis_info_reply(KIS_DFU_SERIAL, "NONC:00 SNON:11", 0x1227))
    assert info == transport.KisDeviceInfo(KIS_DFU_SERIAL, "NONC:00 SNON:11", 0x1227)
    with pytest.raises(IRecvError, match="malformed"):
        transport.KisDeviceInfo.parse(bytes(transport.KIS_HEADER.size + transport.KIS_DEVICE_INFO_SIZE))


def test_find_device_opens_kis_devices_to_learn_their_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    # on macOS only deviceinterfaced may open them
    monkeypatch.setattr(irecv_client.sys, "platform", "linux")
    other = _FakeKisDevice(KIS_DFU_SERIAL.replace("001074523440401C", "0000000000000001"))
    device = _FakeKisDevice()
    monkeypatch.setattr(irecv_client, "list_devices", lambda: [other, device])

    found = irecv_client._find_device(ecid=0x001074523440401C, timeout=0, is_recovery=False)

    assert found is not None and found.device is device
    assert found.mode == irecv.Mode.DFU_MODE
    assert found.nonces == "NONC:00112233 SNON:AABB"
    assert device.configuration == 1
    # enabled on the config portal, then asked for its info
    assert [request[3] for request in device.requests] == [
        transport.KIS_PORTAL_CONFIG,
        transport.KIS_PORTAL_CONFIG,
        transport.KIS_PORTAL_RSM,
    ]
    assert other.closed and not device.closed
    # a recovery-only lookup does not take it
    assert irecv_client._find_device(ecid=None, timeout=0, is_recovery=True) is None


def test_kis_upload_sends_chunks_then_boots(monkeypatch: pytest.MonkeyPatch) -> None:
    device = _FakeKisDevice()
    usb_device = cast(UsbDevice, device)
    found = irecv_client._Found(
        usb_device, irecv.Mode.DFU_MODE, DeviceInfo.parse(KIS_DFU_SERIAL), KisTransport(usb_device), ""
    )
    monkeypatch.setattr(irecv_client, "_find_device", lambda **kwargs: found)
    client = irecv.IRecv()
    assert client.is_kis and client.ap_nonce is None
    reinits: list[Optional[int]] = []
    monkeypatch.setattr(client, "_reinit", lambda ecid=None, **kwargs: reinits.append(ecid))
    device.gone = True
    image = bytes(range(256)) * 80  # a chunk and a quarter

    client.send_buffer(image)

    *uploads, boot = device.requests
    assert [struct.unpack_from("<QI", chunk, transport.KIS_HEADER.size) for chunk in uploads] == [
        (0, transport.KIS_UPLOAD_CHUNK_SIZE),
        (transport.KIS_UPLOAD_CHUNK_SIZE, len(image) - transport.KIS_UPLOAD_CHUNK_SIZE),
    ]
    assert b"".join(chunk[transport.KIS_HEADER.size + 12 :] for chunk in uploads) == image
    assert boot[3:6] == bytes([transport.KIS_PORTAL_RSM, 1, transport.KIS_INDEX_BOOT_IMG & 0xFF])
    assert struct.unpack_from("<I", boot, transport.KIS_HEADER.size) == (len(image),)
    assert reinits == [0x001074523440401C]


class _FakeDeviceInterfaceClient:
    """deviceinterfaced holding one device in DFU mode behind KIS."""

    def __init__(self) -> None:
        self.device = device_interface.DfuInterface(
            interface_id=7,
            location_id=0x100000,
            product_id=irecv.Mode.DFU_MODE.value,
            serial_number=KIS_DFU_SERIAL,
            nonces="NONC:00112233 SNON:AABB DCC:0:1:0",
            payload_base_address=1 << 40,
            payload_capacity=0x1000,
        )
        self.connected = True
        self.calls: list[tuple[str, int]] = []

    def devices(self) -> list[device_interface.DfuInterface]:
        return [self.device] if self.connected else []

    def download(self, device: device_interface.DfuInterface, data: bytes) -> None:
        self.calls.append(("download", len(data)))

    def complete_dfu(self, device: device_interface.DfuInterface, size: int) -> None:
        self.calls.append(("complete_dfu", size))
        self.connected = False

    def wait_until_gone(self, interface_id: int, timeout: float) -> bool:
        return not self.connected


def test_find_device_reaches_kis_devices_through_deviceinterfaced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(irecv_client.sys, "platform", "darwin")
    usb_kis = _FakeKisDevice()
    fake = _FakeDeviceInterfaceClient()
    monkeypatch.setattr(irecv_client, "list_devices", lambda: [usb_kis])
    monkeypatch.setattr(device_interface, "client", lambda: fake)

    found = irecv_client._find_device(ecid=0x001074523440401C, timeout=0, is_recovery=False)

    assert found is not None and found.device is None
    assert found.mode == irecv.Mode.DFU_MODE
    assert isinstance(found.transport, DeviceInterfaceTransport)
    # the Debug USB device itself is never opened
    assert usb_kis.requests == [] and usb_kis.closed


def test_deviceinterfaced_upload_boots_and_waits_for_the_device(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(irecv_client.sys, "platform", "darwin")
    fake = _FakeDeviceInterfaceClient()
    monkeypatch.setattr(irecv_client, "list_devices", lambda: [])
    monkeypatch.setattr(device_interface, "client", lambda: fake)
    client = irecv.IRecv(timeout=0)
    assert client.is_kis
    assert client.ap_nonce == bytes.fromhex("00112233") and client.sep_nonce == bytes.fromhex("AABB")
    reinits: list[Optional[int]] = []
    monkeypatch.setattr(client, "_reinit", lambda ecid=None, **kwargs: reinits.append(ecid))

    client.send_buffer(b"ibss")

    assert fake.calls == [("download", 4), ("complete_dfu", 4)]
    assert reinits == [0x001074523440401C]


def test_deviceinterfaced_entries_missing_fields_are_skipped() -> None:
    # deviceinterfaced keeps a half-filled entry for a moment while the device leaves
    assert device_interface._parse({"TADFU_Device_InterfaceID": 7}) is None
