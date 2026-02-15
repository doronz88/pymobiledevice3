import abc
import asyncio
import plistlib
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional

from construct import (
    Const,
    CString,
    Enum,
    FixedSized,
    GreedyBytes,
    Int16ul,
    Int32ul,
    Padding,
    Prefixed,
    Struct,
    Switch,
    this,
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

usbmuxd_version = Enum(
    Int32ul,
    BINARY=0,
    PLIST=1,
)

usbmuxd_result = Enum(
    Int32ul,
    OK=0,
    BADCOMMAND=1,
    BADDEV=2,
    CONNREFUSED=3,
    NOSUCHSERVICE=4,
    BADVERSION=6,
)

usbmuxd_msgtype = Enum(
    Int32ul,
    RESULT=1,
    CONNECT=2,
    LISTEN=3,
    ADD=4,
    REMOVE=5,
    PAIRED=6,
    PLIST=8,
)

usbmuxd_header = Struct(
    "version" / usbmuxd_version,
    "message" / usbmuxd_msgtype,
    "tag" / Int32ul,
)

usbmuxd_request = Prefixed(
    Int32ul,
    Struct(
        "header" / usbmuxd_header,
        "data"
        / Switch(
            this.header.message,
            {
                usbmuxd_msgtype.CONNECT: Struct(
                    "device_id" / Int32ul,
                    "port" / Int16ul,
                    "reserved" / Const(0, Int16ul),
                ),
                usbmuxd_msgtype.PLIST: GreedyBytes,
            },
        ),
    ),
    includelength=True,
)

usbmuxd_device_record = Struct(
    "device_id" / Int32ul,
    "product_id" / Int16ul,
    "serial_number" / FixedSized(256, CString("ascii")),
    Padding(2),
    "location" / Int32ul,
)

usbmuxd_response = Prefixed(
    Int32ul,
    Struct(
        "header" / usbmuxd_header,
        "data"
        / Switch(
            this.header.message,
            {
                usbmuxd_msgtype.RESULT: Struct(
                    "result" / usbmuxd_result,
                ),
                usbmuxd_msgtype.ADD: usbmuxd_device_record,
                usbmuxd_msgtype.REMOVE: Struct(
                    "device_id" / Int32ul,
                ),
                usbmuxd_msgtype.PLIST: GreedyBytes,
            },
        ),
    ),
    includelength=True,
)


@dataclass
class MuxDevice:
    devid: int
    serial: str
    connection_type: str

    async def connect(self, port: int, usbmux_address: Optional[str] = None) -> socket.socket:
        mux = await create_mux(usbmux_address=usbmux_address)
        try:
            return await mux.connect(self, port)
        except Exception:
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
        except ConnectionRefusedError as e:
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
            probe_message = usbmuxd_request.build({
                "header": {"version": usbmuxd_version.PLIST, "message": usbmuxd_msgtype.PLIST, "tag": 1},
                "data": plistlib.dumps({"MessageType": "ReadBUID"}),
            })
            await asyncio.get_running_loop().sock_sendall(sock, probe_message)
            response = usbmuxd_response.parse(await MuxConnection._recv_packet(sock))
        finally:
            sock.close()

        sock = await MuxConnection.create_usbmux_socket(usbmux_address=usbmux_address)
        if response.header.version == usbmuxd_version.BINARY:
            return BinaryMuxConnection(sock)
        if response.header.version == usbmuxd_version.PLIST:
            return PlistMuxConnection(sock)
        sock.close()
        raise MuxVersionError(f"usbmuxd returned unsupported version: {response.version}")

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
        self._tag = 1
        self.devices = []

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
        self._sock.setblocking(True)
        return self._sock

    async def close(self):
        self._sock.close()

    def _assert_not_connected(self):
        if self._connected:
            raise MuxException("Mux is connected, cannot issue control packets")

    @abc.abstractmethod
    async def receive_device_state_update(self):
        pass

    def _raise_mux_exception(self, result: int, message: Optional[str] = None) -> None:
        exceptions = {
            int(usbmuxd_result.BADCOMMAND): BadCommandError,
            int(usbmuxd_result.BADDEV): BadDevError,
            int(usbmuxd_result.CONNREFUSED): ConnectionFailedError,
            int(usbmuxd_result.NOSUCHSERVICE): ConnectionFailedError,
            int(usbmuxd_result.BADVERSION): MuxVersionError,
        }
        exception = exceptions.get(result, MuxException)
        raise exception(message)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class BinaryMuxConnection(MuxConnection):
    def __init__(self, sock: socket.socket):
        super().__init__(sock)
        self._version = usbmuxd_version.BINARY

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
        await self._send_receive(usbmuxd_msgtype.LISTEN)

    async def _connect(self, device_id: int, port: int):
        await self._send({
            "header": {"version": self._version, "message": usbmuxd_msgtype.CONNECT, "tag": self._tag},
            "data": {"device_id": device_id, "port": port},
        })
        response = await self._receive()
        if response.header.message != usbmuxd_msgtype.RESULT:
            raise MuxException(f"unexpected message type received: {response}")
        if response.data.result != usbmuxd_result.OK:
            raise self._raise_mux_exception(
                int(response.data.result),
                f"failed to connect to device: {device_id} at port: {port}. reason: {response.data.result}",
            )

    async def _send(self, data: dict):
        self._assert_not_connected()
        await asyncio.get_running_loop().sock_sendall(self._sock, usbmuxd_request.build(data))
        self._tag += 1

    async def _receive(self, expected_tag: Optional[int] = None):
        self._assert_not_connected()
        response = usbmuxd_response.parse(await self._recv_packet(self._sock))
        if expected_tag and response.header.tag != expected_tag:
            raise MuxException(f"Reply tag mismatch: expected {expected_tag}, got {response.header.tag}")
        return response

    async def receive_device_state_update(self):
        response = await self._receive()
        if response.header.message == usbmuxd_msgtype.ADD:
            self._add_device(MuxDevice(response.data.device_id, response.data.serial_number, "USB"))
        elif response.header.message == usbmuxd_msgtype.REMOVE:
            self._remove_device(response.data.device_id)
        else:
            raise MuxException(f"Invalid packet type received: {response}")

    async def _send_receive(self, message_type: int):
        await self._send({"header": {"version": self._version, "message": message_type, "tag": self._tag}, "data": b""})
        response = await self._receive(self._tag - 1)
        if response.header.message != usbmuxd_msgtype.RESULT:
            raise MuxException(f"unexpected message type received: {response}")
        result = response.data.result
        if result != usbmuxd_result.OK:
            raise self._raise_mux_exception(int(result), f"{message_type} failed: error {result}")

    def _add_device(self, device: MuxDevice):
        self.devices.append(device)

    def _remove_device(self, device_id: int):
        self.devices = [device for device in self.devices if device.devid != device_id]


class PlistMuxConnection(BinaryMuxConnection):
    def __init__(self, sock: socket.socket):
        super().__init__(sock)
        self._version = usbmuxd_version.PLIST

    async def listen(self) -> None:
        await self._send_receive({"MessageType": "Listen"})

    async def get_pair_record(self, serial: str) -> dict:
        await self._send({"MessageType": "ReadPairRecord", "PairRecordID": serial})
        response = await self._receive(self._tag - 1)
        pair_record = response.get("PairRecordData")
        if pair_record is None:
            raise NotPairedError("device should be paired first")
        return plistlib.loads(pair_record)

    def _process_device_state(self, response):
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

    async def _send(self, data: dict):
        request = {"ClientVersionString": "qt4i-usbmuxd", "ProgName": "pymobiledevice3", "kLibUSBMuxVersion": 3}
        request.update(data)
        await super()._send({
            "header": {"version": self._version, "message": usbmuxd_msgtype.PLIST, "tag": self._tag},
            "data": plistlib.dumps(request),
        })

    async def _receive(self, expected_tag: Optional[int] = None) -> dict:
        response = await super()._receive(expected_tag=expected_tag)
        if response.header.message != usbmuxd_msgtype.PLIST:
            raise MuxException(f"Received non-plist type {response}")
        return plistlib.loads(response.data)

    async def receive_device_state_update(self):
        response = await self._receive()
        self._process_device_state(response)

    async def _send_receive(self, data: dict):
        await self._send(data)
        response = await self._receive(self._tag - 1)
        if response["MessageType"] != "Result":
            raise MuxException(f"got an invalid message: {response}")
        if response["Number"] != 0:
            raise self._raise_mux_exception(response["Number"], f"got an error message: {response}")


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
