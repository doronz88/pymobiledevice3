import plistlib
import socket
import struct

import pytest
from bytestruct import BinaryParseError, TruncatedDataError

from pymobiledevice3.exceptions import BadDevError
from pymobiledevice3.usbmux import (
    BinaryMuxConnection,
    MuxDevice,
    PlistMuxConnection,
    UsbmuxdDeviceRecord,
    UsbmuxdHeader,
    UsbmuxdMessageType,
    UsbmuxdRemoveData,
    UsbmuxdResult,
    UsbmuxdResultData,
    UsbmuxdVersion,
    build_usbmuxd_connect_payload,
    build_usbmuxd_request,
    parse_usbmuxd_response,
)


def test_plist_mux_ignores_paired_message() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        mux = PlistMuxConnection(sock)
        mux._process_device_state({"DeviceID": 28, "MessageType": "Paired"})
        assert mux.devices == []
    finally:
        sock.close()


# Golden packets below were produced by the original construct-based definitions.
def test_build_connect_request() -> None:
    payload = build_usbmuxd_connect_payload(5, socket.htons(62078))
    packet = build_usbmuxd_request(UsbmuxdVersion.BINARY, UsbmuxdMessageType.CONNECT, 1, payload)
    assert packet.hex() == "1800000000000000020000000100000005000000f27e0000"


def test_build_listen_request() -> None:
    packet = build_usbmuxd_request(UsbmuxdVersion.BINARY, UsbmuxdMessageType.LISTEN, 2)
    assert packet.hex() == "10000000000000000300000002000000"


def test_build_plist_request() -> None:
    packet = build_usbmuxd_request(UsbmuxdVersion.PLIST, UsbmuxdMessageType.PLIST, 3, b"<plist/>")
    assert packet.hex() == "180000000100000008000000030000003c706c6973742f3e"


def _packet(message: int, body: bytes, version: int = 0, tag: int = 7) -> bytes:
    return struct.pack("<IIII", 16 + len(body), version, message, tag) + body


def _device_record(serial: bytes) -> bytes:
    return struct.pack("<IH", 3, 0x12A8) + serial.ljust(256, b"\0") + b"\0\0" + struct.pack("<I", 0x14100000)


def test_parse_responses() -> None:
    response = parse_usbmuxd_response(_packet(UsbmuxdMessageType.RESULT, struct.pack("<I", 3)))
    assert response.header == UsbmuxdHeader(0, UsbmuxdMessageType.RESULT, 7)
    assert response.data == UsbmuxdResultData(UsbmuxdResult.CONNREFUSED)

    response = parse_usbmuxd_response(_packet(UsbmuxdMessageType.ADD, _device_record(b"00008030-001A2C3E0E12802E")))
    assert response.data == UsbmuxdDeviceRecord(3, 0x12A8, "00008030-001A2C3E0E12802E", 0x14100000)

    response = parse_usbmuxd_response(_packet(UsbmuxdMessageType.REMOVE, struct.pack("<I", 42)))
    assert response.data == UsbmuxdRemoveData(42)

    response = parse_usbmuxd_response(_packet(UsbmuxdMessageType.PLIST, b"<plist/>", version=1))
    assert response.data == b"<plist/>"

    response = parse_usbmuxd_response(_packet(UsbmuxdMessageType.PAIRED, b""))
    assert response.data is None


@pytest.mark.parametrize(
    "packet",
    [
        _packet(UsbmuxdMessageType.ADD, _device_record(b"serial")),
        _packet(UsbmuxdMessageType.RESULT, struct.pack("<I", 0)),
        _packet(UsbmuxdMessageType.PLIST, b"<plist/>"),
    ],
)
def test_parse_truncated_raises_stream_error(packet: bytes) -> None:
    for cut in range(len(packet)):
        with pytest.raises(TruncatedDataError):
            parse_usbmuxd_response(packet[:cut])


def test_parse_body_shorter_than_declared_length_raises_stream_error() -> None:
    packet = struct.pack("<IIII", 18, 0, UsbmuxdMessageType.RESULT, 1) + b"\0\0" + b"\0" * 16
    with pytest.raises(TruncatedDataError):
        parse_usbmuxd_response(packet)


def test_parse_declared_length_shorter_than_its_own_field() -> None:
    for length in range(4):
        with pytest.raises(BinaryParseError) as error:
            parse_usbmuxd_response(struct.pack("<IIII", length, 0, UsbmuxdMessageType.RESULT, 1))
        assert not isinstance(error.value, TruncatedDataError)


def test_parse_invalid_serial() -> None:
    with pytest.raises(BinaryParseError, match=r"UsbmuxdDeviceRecord\.serial_number at offset 22"):
        parse_usbmuxd_response(_packet(UsbmuxdMessageType.ADD, _device_record(b"\xff")))


def test_serial_filling_its_field_parses_whole() -> None:
    response = parse_usbmuxd_response(_packet(UsbmuxdMessageType.ADD, _device_record(b"x" * 256)))
    assert response.data == UsbmuxdDeviceRecord(3, 0x12A8, "x" * 256, 0x14100000)


def test_device_record_padding_is_skipped() -> None:
    record = bytearray(_device_record(b"udid"))
    record[262:264] = b"\xaa\xbb"
    response = parse_usbmuxd_response(_packet(UsbmuxdMessageType.ADD, bytes(record)))
    assert response.data == UsbmuxdDeviceRecord(3, 0x12A8, "udid", 0x14100000)


async def test_binary_mux_listen_and_device_updates() -> None:
    client, server = socket.socketpair()
    client.setblocking(False)
    try:
        mux = BinaryMuxConnection(client)
        server.sendall(_packet(UsbmuxdMessageType.RESULT, struct.pack("<I", 0), tag=1))
        await mux.listen()
        assert server.recv(1024) == build_usbmuxd_request(UsbmuxdVersion.BINARY, UsbmuxdMessageType.LISTEN, 1)

        server.sendall(_packet(UsbmuxdMessageType.ADD, _device_record(b"udid")))
        await mux.receive_device_state_update()
        assert mux.devices == [MuxDevice(3, "udid", "USB")]

        server.sendall(_packet(UsbmuxdMessageType.REMOVE, struct.pack("<I", 3)))
        await mux.receive_device_state_update()
        assert mux.devices == []

        server.sendall(_packet(UsbmuxdMessageType.RESULT, struct.pack("<I", UsbmuxdResult.BADDEV), tag=2))
        with pytest.raises(BadDevError, match="usbmuxd rejected the LISTEN request: BADDEV"):
            await mux.listen()
    finally:
        client.close()
        server.close()


async def test_plist_mux_roundtrip() -> None:
    client, server = socket.socketpair()
    client.setblocking(False)
    try:
        mux = PlistMuxConnection(client)
        reply = plistlib.dumps({"MessageType": "Result", "BUID": "abc"})
        server.sendall(_packet(UsbmuxdMessageType.PLIST, reply, version=1, tag=1))
        assert await mux.get_buid() == "abc"
        request = parse_usbmuxd_response(server.recv(4096))
        assert request.header == UsbmuxdHeader(UsbmuxdVersion.PLIST, UsbmuxdMessageType.PLIST, 1)
        assert isinstance(request.data, bytes)
        assert plistlib.loads(request.data)["MessageType"] == "ReadBUID"
    finally:
        client.close()
        server.close()
