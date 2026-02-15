import asyncio
import contextlib
import logging
import plistlib
import socket
import struct
from enum import Enum
from typing import Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import (
    ConnectionFailedError,
    ConnectionTerminatedError,
    NoDeviceConnectedError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.service_connection import ServiceConnection

CTRL_PORT = 0x43A  # 1082
CTRLCMD = b"BeginCtrl\0"
HELLOCMD = b"HelloConn\0"

FDR_SYNC_MSG = 0x1
FDR_PROXY_MSG = 0x105
FDR_PLIST_MSG = 0xBBAA
CHUNK_SIZE = 1048576

conn_port = None

logger = logging.getLogger(__name__)


class fdr_type(Enum):
    FDR_CTRL = 1
    FDR_CONN = 2


class FDRClient:
    SERVICE_PORT = CTRL_PORT
    ctrlprotoversion = 2

    def __init__(self, service: ServiceConnection) -> None:
        self.service = service
        self._conn_listener_task: Optional[asyncio.Task] = None

    @classmethod
    async def create(cls, type_: fdr_type, udid: Optional[str] = None) -> "FDRClient":
        device = await usbmux.select_device(udid)
        if device is None:
            if udid:
                raise ConnectionFailedError()
            raise NoDeviceConnectedError()

        logger.debug("connecting to FDR")
        if type_ == fdr_type.FDR_CTRL:
            service = await ServiceConnection.create_using_usbmux(
                device.serial, cls.SERVICE_PORT, connection_type="USB"
            )
        else:
            if conn_port is None:
                raise PyMobileDevice3Exception("FDR connection port is unavailable")
            service = await ServiceConnection.create_using_usbmux(device.serial, conn_port, connection_type="USB")

        client = cls(service)
        if type_ == fdr_type.FDR_CTRL:
            await client.ctrl_handshake()
        else:
            await client.sync_handshake()

        logger.debug("FDR connected")
        return client

    async def recv_plist(self) -> dict:
        return await self.service.recv_plist(endianity="<")

    async def send_recv_plist(self, plist: dict) -> dict:
        await self.service.send_plist(plist, endianity="<", fmt=plistlib.FMT_BINARY)
        return await self.service.recv_plist(endianity="<")

    async def ctrl_handshake(self) -> None:
        global conn_port

        logger.debug("About to do ctrl handshake")
        await self.service.sendall(CTRLCMD)

        if self.ctrlprotoversion != 2:
            raise NotImplementedError("TODO")

        req = {
            "Command": CTRLCMD,
            "CtrlProtoVersion": self.ctrlprotoversion,
        }
        resp = await self.send_recv_plist(req)
        conn_port = resp["ConnPort"]
        logger.debug(f"Ctrl handshake done (ConnPort = {conn_port})")

    async def sync_handshake(self) -> None:
        await self.service.sendall(HELLOCMD)

        if self.ctrlprotoversion != 2:
            raise NotImplementedError("TODO")

        reply = await self.recv_plist()
        cmd = reply["Command"]
        identifier = reply["Identifier"]

        if cmd != "HelloConn":
            raise PyMobileDevice3Exception("Did not receive HelloConn reply...")
        if identifier:
            logger.debug(f"got device identifier: {identifier}")

    async def handle_sync_cmd(self) -> None:
        await self.service.recvall(2)
        logger.debug("FDR connected in reply to sync message, starting command task")
        self._conn_listener_task = asyncio.create_task(run_fdr_listener(fdr_type.FDR_CONN), name="FDR-CONN")

    async def _proxy_service_to_host(self, host_socket: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while True:
            buf = await asyncio.to_thread(self.service.recv_sync, CHUNK_SIZE)
            if not buf:
                return
            await loop.sock_sendall(host_socket, buf)

    async def _proxy_host_to_service(self, host_socket: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while True:
            buf = await loop.sock_recv(host_socket, CHUNK_SIZE)
            if not buf:
                return
            await self.service.sendall(buf)

    async def handle_proxy_cmd(self) -> None:
        buf = await asyncio.to_thread(self.service.recv_sync, CHUNK_SIZE)
        logger.debug(f"got proxy command with {len(buf)} bytes")

        # acknowledge request and payload
        await self.service.sendall(struct.pack("<H", 5))
        if len(buf) < 3:
            logger.debug(f"FDR {self} proxy command data too short, retrying")
            return
        await self.service.sendall(buf)

        host = None
        port = None
        if buf[0] == 0 and buf[1] == 3:
            port = struct.unpack(">H", buf[-2:])[0]
            hostlen = buf[2]
            host = buf[3 : 3 + hostlen].decode()
            logger.debug(f"FDR {self} Proxy connect request to {host}:{port}")
        else:
            return

        host_socket = socket.socket()
        host_socket.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_connect(host_socket, (host, port))

        service_to_host = asyncio.create_task(self._proxy_service_to_host(host_socket), name="FDR-proxy-s2h")
        host_to_service = asyncio.create_task(self._proxy_host_to_service(host_socket), name="FDR-proxy-h2s")

        done, pending = await asyncio.wait({service_to_host, host_to_service}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            with contextlib.suppress(Exception):
                task.result()

        host_socket.close()
        await self.service.close()

    async def handle_plist_cmd(self) -> None:
        d = await self.recv_plist()
        command = d["Command"]

        if command == "Ping":
            await self.send_recv_plist({"Pong": True})
        else:
            logger.warning(f"FDR {self} received unknown plist command: {command}")

    async def poll_and_handle_message(self) -> None:
        cmd = struct.unpack("<H", await self.service.recvall(2))[0]
        handlers = {
            FDR_SYNC_MSG: self.handle_sync_cmd,
            FDR_PROXY_MSG: self.handle_proxy_cmd,
            FDR_PLIST_MSG: self.handle_plist_cmd,
        }
        handler = handlers.get(cmd)
        if handler is None:
            logger.warning(f"ignoring FDR message: {cmd}")
            return
        await handler()


async def run_fdr_listener(type_: fdr_type, udid: Optional[str] = None) -> None:
    client: Optional[FDRClient] = None
    closing_via_generator_exit = False
    try:
        client = await FDRClient.create(type_, udid=udid)
        logger.debug(f"FDR {client} waiting for message...")
        while True:
            await client.poll_and_handle_message()
    except GeneratorExit:
        # Coroutine finalization cannot perform async cleanup (no await allowed).
        closing_via_generator_exit = True
        if client is not None and client.service.socket is not None:
            with contextlib.suppress(Exception):
                client.service.socket.close()
        raise
    except ConnectionTerminatedError:
        pass
    finally:
        if client is not None and not closing_via_generator_exit:
            await client.service.close()
    logger.debug(f"FDR {client} terminating...")


def start_fdr_task(type_: fdr_type, udid: Optional[str] = None) -> asyncio.Task:
    return asyncio.create_task(run_fdr_listener(type_, udid=udid), name=f"FDR-{type_.name}")
