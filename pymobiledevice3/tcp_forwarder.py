import asyncio
import logging
import threading
from abc import abstractmethod
from typing import Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection


class TcpForwarderBase:
    """
    Allows forwarding local tcp connection into the device via a given lockdown connection
    """

    MAX_FORWARDED_CONNECTIONS = 200

    def __init__(self, src_port: int, listening_event: Optional[threading.Event] = None):
        """
        Initialize a new tcp forwarder

        :param src_port: tcp port to listen on
        :param enable_ssl: enable ssl wrapping for the transferred data
        :param listening_event: event to fire when the listening occurred
        """
        self.logger = logging.getLogger(__name__)
        self.src_port = src_port
        self.server: Optional[asyncio.AbstractServer] = None
        self.stopped = asyncio.Event()
        self.listening_event = listening_event
        self._connection_tasks: set[asyncio.Task] = set()

    async def start(self, address="127.0.0.1"):
        """forward each connection from given local machine port to remote device port"""
        self.server = await asyncio.start_server(
            self._handle_server_connection, address, self.src_port, backlog=self.MAX_FORWARDED_CONNECTIONS
        )
        if self.listening_event:
            self.listening_event.set()
        try:
            await self.stopped.wait()
        finally:
            self.logger.info("Closing everything")
            if self.server is not None:
                self.server.close()
                await self.server.wait_closed()
            tasks = list(self._connection_tasks)
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    @abstractmethod
    async def _establish_remote_connection(self) -> ServiceConnection:
        pass

    async def _pipe(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: str, direction: str
    ) -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                return
            writer.write(data)
            await writer.drain()
            self.logger.debug("%s %s bytes=%d", peer, direction, len(data))

    async def _handle_server_connection(self, local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter):
        """accept the connection from local machine and attempt to connect at remote"""
        peer = str(local_writer.get_extra_info("peername"))
        try:
            remote_connection = await self._establish_remote_connection()
            await remote_connection.start()
        except ConnectionFailedError:
            self.logger.error("failed to connect to remote endpoint")
            local_writer.close()
            await local_writer.wait_closed()
            return

        assert remote_connection.reader is not None
        assert remote_connection.writer is not None
        task = asyncio.current_task()
        if task is not None:
            self._connection_tasks.add(task)
        self.logger.info("connection established from %s", peer)
        try:
            client_to_remote = asyncio.create_task(
                self._pipe(local_reader, remote_connection.writer, peer, "client->remote")
            )
            remote_to_client = asyncio.create_task(
                self._pipe(remote_connection.reader, local_writer, peer, "remote->client")
            )
            done, pending = await asyncio.wait(
                {client_to_remote, remote_to_client},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for p in pending:
                p.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for d in done:
                exc = d.exception()
                if exc is not None and not isinstance(exc, ConnectionResetError):
                    self.logger.debug("connection %s ended with %r", peer, exc)
        finally:
            await remote_connection.close()
            local_writer.close()
            await local_writer.wait_closed()
            self.logger.info("connection %s was closed", peer)
            if task is not None:
                self._connection_tasks.discard(task)

    def stop(self):
        """stop forwarding"""
        self.stopped.set()


class UsbmuxTcpForwarder(TcpForwarderBase):
    """
    Allows forwarding local tcp connection into the device via a given lockdown connection
    """

    def __init__(
        self,
        serial: str,
        dst_port: int,
        src_port: int,
        listening_event: Optional[threading.Event] = None,
        usbmux_connection_type: Optional[str] = None,
        usbmux_address: Optional[str] = None,
    ):
        """
        Initialize a new tcp forwarder

        :param serial: device serial
        :param dst_port: tcp port to connect to each new connection via the supplied lockdown object
        :param src_port: tcp port to listen on
        :param listening_event: event to fire when the listening occurred
        :param usbmux_connection_type: preferred connection type
        :param usbmux_address: usbmuxd address
        """
        super().__init__(src_port, listening_event)
        self.serial = serial
        self.dst_port = dst_port
        self.usbmux_connection_type = usbmux_connection_type
        self.usbmux_address = usbmux_address

    async def _establish_remote_connection(self) -> ServiceConnection:
        # connect directly using usbmuxd
        mux_device = await usbmux.select_device(
            self.serial, connection_type=self.usbmux_connection_type, usbmux_address=self.usbmux_address
        )
        self.logger.debug("Selected device: %r", mux_device)
        if mux_device is None:
            raise ConnectionFailedError()
        sock = await mux_device.connect(self.dst_port, usbmux_address=self.usbmux_address)
        return ServiceConnection(sock, mux_device=mux_device)


class LockdownTcpForwarder(TcpForwarderBase):
    """
    Allows forwarding local tcp connection into the device via a given lockdown connection
    """

    def __init__(
        self,
        service_provider: LockdownServiceProvider,
        src_port: int,
        service_name: str,
        listening_event: Optional[threading.Event] = None,
    ):
        """
        Initialize a new tcp forwarder

        :param src_port: tcp port to listen on
        :param service_name: service name to connect to
        :param listening_event: event to fire when the listening occurred
        """
        super().__init__(src_port, listening_event)
        self.service_provider = service_provider
        self.service_name = service_name

    async def _establish_remote_connection(self) -> ServiceConnection:
        return await self.service_provider.start_lockdown_developer_service(self.service_name)
