import abc
import asyncio
import os
import plistlib
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from types import TracebackType
from typing import Annotated, Any, NoReturn, Optional, Union

from pymobiledevice3.binary import (
    U32_LE,
    BinaryStruct,
    ByteReader,
    Bytes,
    BytesLike,
    OpenIntEnum,
    PaddedString,
    u16,
    u32,
)
from pymobiledevice3.exceptions import (
    BadCommandError,
    BadDevError,
    ConnectionFailedError,
    ConnectionFailedToUsbmuxdError,
    MuxException,
    MuxVersionError,
    NotPairedError,
)
from pymobiledevice3.osu.os_utils import get_os_utils

# used on Windows
ITUNES_HOST = ("127.0.0.1", 27015)

# used for macOS and Linux
USBMUXD_PIPE = "/var/run/usbmuxd"


class UsbmuxdVersion(IntEnum):
    BINARY = 0
    PLIST = 1


class UsbmuxdResult(OpenIntEnum):
    OK = 0
    BADCOMMAND = 1
    BADDEV = 2
    CONNREFUSED = 3
    NOSUCHSERVICE = 4
    BADVERSION = 6


class UsbmuxdMessageType(OpenIntEnum):
    RESULT = 1
    CONNECT = 2
    LISTEN = 3
    ADD = 4
    REMOVE = 5
    PAIRED = 6
    PLIST = 8


@dataclass
class UsbmuxdHeader(BinaryStruct, byte_order="<"):
    version: u32
    message: u32
    tag: u32


@dataclass
class UsbmuxdResultData(BinaryStruct, byte_order="<"):
    result: Annotated[UsbmuxdResult, u32]


@dataclass
class _UsbmuxdConnectRequest(BinaryStruct, byte_order="<"):
    device_id: u32
    port: u16
    reserved: u16 = 0


@dataclass
class UsbmuxdDeviceRecord(BinaryStruct, byte_order="<"):
    device_id: u32
    product_id: u16
    serial_number: Annotated[str, PaddedString(256)]
    padding: Annotated[bytes, Bytes(2)] = field(default=bytes(2), init=False, repr=False, compare=False)
    location: u32


@dataclass
class UsbmuxdRemoveData(BinaryStruct, byte_order="<"):
    device_id: u32


# RESULT -> UsbmuxdResultData, ADD -> UsbmuxdDeviceRecord, REMOVE -> UsbmuxdRemoveData, PLIST -> bytes, other -> None
UsbmuxdResponseData = Union[UsbmuxdResultData, UsbmuxdDeviceRecord, UsbmuxdRemoveData, bytes, None]


@dataclass
class UsbmuxdResponse:
    header: UsbmuxdHeader
    data: UsbmuxdResponseData


def build_usbmuxd_request(version: int, message: int, tag: int, payload: bytes = b"") -> bytes:
    """Build a length-prefixed usbmuxd packet (the length includes its own 4 bytes)."""
    header = UsbmuxdHeader(version, message, tag).build()
    return U32_LE.pack(U32_LE.size + len(header) + len(payload)) + header + payload


def build_usbmuxd_connect_payload(device_id: int, port: int) -> bytes:
    """Build the binary-protocol CONNECT body; ``port`` is packed as-is (callers pass it network-ordered)."""
    return _UsbmuxdConnectRequest(device_id, port).build()


def parse_usbmuxd_response(data: BytesLike) -> UsbmuxdResponse:
    """
    Parse a length-prefixed usbmuxd packet.

    Bytes past the declared length, and past the end of a fixed-size body, are ignored.

    :raises TruncatedDataError: if the packet is shorter than its declared length or its body is truncated.
    :raises BinaryParseError: if the declared length is shorter than the length field itself, or a device
        record's serial number is not NUL-terminated UTF-8.
    """
    outer = ByteReader(data)
    reader = outer.sub(outer.unpack_one(U32_LE) - U32_LE.size)
    header = UsbmuxdHeader.read(reader)
    body: UsbmuxdResponseData = None
    if header.message == UsbmuxdMessageType.RESULT:
        body = UsbmuxdResultData.read(reader)
    elif header.message == UsbmuxdMessageType.ADD:
        body = UsbmuxdDeviceRecord.read(reader)
    elif header.message == UsbmuxdMessageType.REMOVE:
        body = UsbmuxdRemoveData.read(reader)
    elif header.message == UsbmuxdMessageType.PLIST:
        body = reader.read_all()
    return UsbmuxdResponse(header, body)


@dataclass
class MuxDevice:
    devid: int
    serial: str
    connection_type: str

    async def connect(self, port: int, usbmux_address: Optional[str] = None) -> socket.socket:
        mux = await create_mux(usbmux_address=usbmux_address)
        try:
            return await mux.connect(self, port)
        except BaseException:
            await mux.close()
            raise

    @property
    def is_usb(self) -> bool:
        return self.connection_type == "USB"

    @property
    def is_network(self) -> bool:
        return self.connection_type == "Network"

    def matches_udid(self, udid: str) -> bool:
        return self.serial.replace("-", "") == udid.replace("-", "")


class MuxConnection:
    ITUNES_HOST = ITUNES_HOST
    USBMUXD_PIPE = USBMUXD_PIPE

    @staticmethod
    def _resolve_usbmux_address(usbmux_address: Optional[str] = None):
        if usbmux_address is None:
            # Honor the libusbmuxd-standard env var at the socket layer so every call
            # site (not just the CLI --usbmux option) reaches a remote/relocated
            # usbmuxd, e.g. usbmuxd exposed over TCP as HOST:PORT.
            usbmux_address = os.getenv("USBMUXD_SOCKET_ADDRESS")
        if usbmux_address is not None:
            if ":" in usbmux_address:
                hostname, port = usbmux_address.split(":")
                return (hostname, int(port)), socket.AF_INET
            return usbmux_address, socket.AF_UNIX
        return get_os_utils().usbmux_address

    @staticmethod
    async def create_usbmux_socket(usbmux_address: Optional[str] = None) -> socket.socket:
        address, family = MuxConnection._resolve_usbmux_address(usbmux_address)
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.get_running_loop().sock_connect(sock, address)
        except (ConnectionRefusedError, FileNotFoundError) as e:
            sock.close()
            raise ConnectionFailedToUsbmuxdError() from e
        except Exception:
            sock.close()
            raise
        return sock

    @staticmethod
    async def create(usbmux_address: Optional[str] = None):
        sock = await MuxConnection.create_usbmux_socket(usbmux_address=usbmux_address)
        try:
            probe_message = build_usbmuxd_request(
                UsbmuxdVersion.PLIST, UsbmuxdMessageType.PLIST, 1, plistlib.dumps({"MessageType": "ReadBUID"})
            )
            await asyncio.get_running_loop().sock_sendall(sock, probe_message)
            response = parse_usbmuxd_response(await MuxConnection._recv_packet(sock))
        finally:
            sock.close()

        sock = await MuxConnection.create_usbmux_socket(usbmux_address=usbmux_address)
        if response.header.version == UsbmuxdVersion.BINARY:
            return BinaryMuxConnection(sock)
        if response.header.version == UsbmuxdVersion.PLIST:
            return PlistMuxConnection(sock)
        sock.close()
        raise MuxVersionError(f"usbmuxd returned unsupported version: {response.header.version}")

    @staticmethod
    async def _recv_exactly(sock: socket.socket, size: int) -> bytes:
        data = b""
        loop = asyncio.get_running_loop()
        while len(data) < size:
            chunk = await loop.sock_recv(sock, size - len(data))
            if not chunk:
                raise MuxException("socket connection broken")
            data += chunk
        return data

    @staticmethod
    async def _recv_packet(sock: socket.socket) -> bytes:
        header = await MuxConnection._recv_exactly(sock, 4)
        size = struct.unpack("<L", header)[0]
        if size < 4:
            raise MuxException(f"Invalid usbmux packet size: {size}")
        payload = await MuxConnection._recv_exactly(sock, size - 4)
        return header + payload

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._connected = False
        self._tag: int = 1
        self.devices: list[MuxDevice] = []

    @abc.abstractmethod
    async def _connect(self, device_id: int, port: int):
        pass

    @abc.abstractmethod
    async def get_device_list(self, timeout: Optional[float] = None):
        pass

    @abc.abstractmethod
    async def listen(self):
        pass

    async def connect(self, device: MuxDevice, port: int) -> socket.socket:
        await self._connect(device.devid, socket.htons(port))
        self._connected = True
        return self._sock

    async def close(self):
        self._sock.close()

    def _assert_not_connected(self):
        if self._connected:
            raise MuxException("Mux is connected, cannot issue control packets")

    @abc.abstractmethod
    async def receive_device_state_update(self):
        pass

    def _raise_mux_exception(self, result: int, message: Optional[str] = None) -> NoReturn:
        exceptions: dict[int, type[MuxException]] = {
            int(UsbmuxdResult.BADCOMMAND): BadCommandError,
            int(UsbmuxdResult.BADDEV): BadDevError,
            int(UsbmuxdResult.CONNREFUSED): ConnectionFailedError,
            int(UsbmuxdResult.NOSUCHSERVICE): ConnectionFailedError,
            int(UsbmuxdResult.BADVERSION): MuxVersionError,
        }
        exception = exceptions.get(result, MuxException)
        raise exception(message)

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.close()


class BinaryMuxConnection(MuxConnection):
    def __init__(self, sock: socket.socket):
        super().__init__(sock)
        self._version: int = UsbmuxdVersion.BINARY

    async def get_device_list(self, timeout: Optional[float] = None):
        self._assert_not_connected()
        timeout = timeout or 0
        end = time.time() + timeout
        await self.listen()
        while time.time() < end:
            try:
                await asyncio.wait_for(self.receive_device_state_update(), timeout=end - time.time())
            except asyncio.TimeoutError:
                continue
            except OSError as e:
                await self.close()
                raise MuxException("Exception in listener socket") from e

    async def listen(self):
        await self._send_receive(UsbmuxdMessageType.LISTEN)

    async def _connect(self, device_id: int, port: int):
        await self._send_packet(UsbmuxdMessageType.CONNECT, build_usbmuxd_connect_payload(device_id, port))
        response = await self._receive_response()
        if not isinstance(response.data, UsbmuxdResultData):
            raise MuxException(f"unexpected message type received: {response}")
        result = response.data.result
        if result != UsbmuxdResult.OK:
            self._raise_mux_exception(
                result,
                f"failed to connect to device: {device_id} at port: {port}. reason: {result.name}",
            )

    async def _send_packet(self, message: int, payload: bytes = b"") -> None:
        self._assert_not_connected()
        await asyncio.get_running_loop().sock_sendall(
            self._sock, build_usbmuxd_request(self._version, message, self._tag, payload)
        )
        self._tag += 1

    async def _receive_response(self, expected_tag: Optional[int] = None) -> UsbmuxdResponse:
        self._assert_not_connected()
        response = parse_usbmuxd_response(await self._recv_packet(self._sock))
        if expected_tag and response.header.tag != expected_tag:
            raise MuxException(f"Reply tag mismatch: expected {expected_tag}, got {response.header.tag}")
        return response

    async def receive_device_state_update(self):
        response = await self._receive_response()
        if isinstance(response.data, UsbmuxdDeviceRecord):
            self._add_device(MuxDevice(response.data.device_id, response.data.serial_number, "USB"))
        elif isinstance(response.data, UsbmuxdRemoveData):
            self._remove_device(response.data.device_id)
        elif response.header.message == UsbmuxdMessageType.PAIRED:
            # Pairing state updates don't change the tracked device list.
            return
        else:
            raise MuxException(f"Invalid packet type received: {response}")

    async def _send_receive(self, message_type: UsbmuxdMessageType):
        await self._send_packet(message_type)
        response = await self._receive_response(self._tag - 1)
        if not isinstance(response.data, UsbmuxdResultData):
            raise MuxException(f"unexpected message type received: {response}")
        result = response.data.result
        if result != UsbmuxdResult.OK:
            self._raise_mux_exception(
                result,
                f"{message_type.name} failed: error {result.name}",
            )

    def _add_device(self, device: MuxDevice):
        self.devices.append(device)

    def _remove_device(self, device_id: int):
        self.devices = [device for device in self.devices if device.devid != device_id]


class PlistMuxConnection(BinaryMuxConnection):
    def __init__(self, sock: socket.socket):
        super().__init__(sock)
        self._version = UsbmuxdVersion.PLIST

    async def listen(self) -> None:
        await self._send_receive({"MessageType": "Listen"})

    async def get_pair_record(self, serial: str) -> dict[str, Any]:
        await self._send({"MessageType": "ReadPairRecord", "PairRecordID": serial})
        response = await self._receive(self._tag - 1)
        pair_record = response.get("PairRecordData")
        if pair_record is None:
            raise NotPairedError("device should be paired first")
        return plistlib.loads(pair_record)

    def _process_device_state(self, response: dict[str, Any]) -> None:
        if response["MessageType"] == "Attached":
            super()._add_device(
                MuxDevice(
                    response["DeviceID"],
                    response["Properties"]["SerialNumber"],
                    response["Properties"]["ConnectionType"],
                )
            )
        elif response["MessageType"] == "Detached":
            super()._remove_device(response["DeviceID"])
        elif response["MessageType"] == "Paired":
            # Pairing notifications can arrive while listening to state updates.
            return
        else:
            raise MuxException(f"Invalid packet type received: {response}")

    async def get_device_list(self, timeout: Optional[float] = None) -> None:
        self.devices = []
        await self._send({"MessageType": "ListDevices"})
        response = await self._receive(self._tag - 1)
        device_list = response.get("DeviceList")
        if device_list is None:
            raise MuxException(f"Got an invalid response from usbmux: {response}")
        for item in device_list:
            self._process_device_state(item)

    async def get_buid(self) -> str:
        await self._send({"MessageType": "ReadBUID"})
        return (await self._receive(self._tag - 1))["BUID"]

    async def save_pair_record(self, serial: str, device_id: int, record_data: bytes):
        await self._send_receive({
            "MessageType": "SavePairRecord",
            "PairRecordID": serial,
            "PairRecordData": record_data,
            "DeviceID": device_id,
        })

    async def _connect(self, device_id: int, port: int):
        await self._send_receive({"MessageType": "Connect", "DeviceID": device_id, "PortNumber": port})

    async def _send(self, data: dict[str, Any]):
        request: dict[str, Any] = {
            "ClientVersionString": "qt4i-usbmuxd",
            "ProgName": "pymobiledevice3",
            "kLibUSBMuxVersion": 3,
        }
        request.update(data)
        await self._send_packet(UsbmuxdMessageType.PLIST, plistlib.dumps(request))

    async def _receive(self, expected_tag: Optional[int] = None) -> dict[str, Any]:
        response = await self._receive_response(expected_tag=expected_tag)
        if not isinstance(response.data, bytes):
            raise MuxException(f"Received non-plist type {response}")
        return plistlib.loads(response.data)

    async def receive_device_state_update(self):
        response = await self._receive()
        self._process_device_state(response)

    # The plist protocol sends a whole message dict, unlike the binary base which takes an int/str
    # message type. This is an intentional protocol divergence between the two connection subclasses.
    async def _send_receive(self, data: dict[str, Any]):  # pyright: ignore[reportIncompatibleMethodOverride]
        await self._send(data)
        response = await self._receive(self._tag - 1)
        if response["MessageType"] != "Result":
            raise MuxException(f"got an invalid message: {response}")
        if response["Number"] != 0:
            self._raise_mux_exception(response["Number"], f"got an error message: {response}")


async def create_mux(usbmux_address: Optional[str] = None) -> MuxConnection:
    return await MuxConnection.create(usbmux_address=usbmux_address)


async def list_devices(usbmux_address: Optional[str] = None) -> list[MuxDevice]:
    mux = await create_mux(usbmux_address=usbmux_address)
    try:
        await mux.get_device_list(0.1)
        devices = mux.devices
    finally:
        await mux.close()
    return devices


async def wait_for_device_detach(
    serial: str, timeout: Optional[float] = None, usbmux_address: Optional[str] = None
) -> bool:
    """
    Wait until a device is no longer listed by usbmuxd.

    :param serial: UDID of the device to wait for.
    :param timeout: maximum time to wait in seconds, or ``None`` to wait indefinitely.
    :param usbmux_address: address of the usbmuxd daemon; the platform default if omitted.
    :returns: ``True`` once the device is gone, ``False`` if it was still listed when the timeout elapsed.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    while any(device.matches_udid(serial) for device in await list_devices(usbmux_address=usbmux_address)):
        if deadline is not None and time.monotonic() >= deadline:
            return False
        await asyncio.sleep(0.5)
    return True


async def select_device(
    udid: Optional[str] = None, connection_type: Optional[str] = None, usbmux_address: Optional[str] = None
) -> Optional[MuxDevice]:
    tmp = None
    for device in await list_devices(usbmux_address=usbmux_address):
        if connection_type is not None and device.connection_type != connection_type:
            continue
        if udid is not None and not device.matches_udid(udid):
            continue
        tmp = device
        if device.is_usb:
            return device
    return tmp


async def select_devices_by_connection_type(
    connection_type: str, usbmux_address: Optional[str] = None
) -> list[MuxDevice]:
    return [
        device
        for device in await list_devices(usbmux_address=usbmux_address)
        if device.connection_type == connection_type
    ]
