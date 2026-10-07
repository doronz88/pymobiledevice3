import uuid
from typing import Any, Optional

from pymobiledevice3.exceptions import NotConnectedError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.service_connection import ServiceConnection


class OpenStdioSocketService:
    """
    A socket the device can attach to a process's standard input, output and error.

    Connecting yields an `identifier`. Pass it to `AppServiceService.launch_application` and the
    launched process reads its stdin from this socket and writes its stdout and stderr to it, through
    a pseudoterminal (so lines end in ``\\r\\n``). The device closes the socket when the process
    exits.

    The service speaks raw bytes, not RemoteXPC. Requires an RSD tunnel and a mounted
    DeveloperDiskImage. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.coredevice.openstdiosocket"

    def __init__(self, rsd: RemoteServiceDiscoveryService) -> None:
        """
        :param rsd: RSD provider used to reach the service.
        """
        self.rsd = rsd
        self._connection: Optional[ServiceConnection] = None
        self._identifier: Optional[uuid.UUID] = None

    @property
    def identifier(self) -> uuid.UUID:
        """The identifier a launch request uses to refer to this socket.

        :raises NotConnectedError: if accessed before ``connect()`` (or ``async with``) has run.
        """
        if self._identifier is None:
            raise NotConnectedError(f"{type(self).__name__} is not connected; call connect() first")
        return self._identifier

    @property
    def _service(self) -> ServiceConnection:
        if self._connection is None:
            raise NotConnectedError(f"{type(self).__name__} is not connected; call connect() first")
        return self._connection

    async def connect(self) -> None:
        self._connection = await self.rsd.create_service_connection(self.rsd.get_service_port(self.SERVICE_NAME))
        self._identifier = uuid.UUID(bytes=await self._connection.recvall(16))

    async def read(self, size: int = 4096) -> bytes:
        """
        Read what the process wrote to its stdout or stderr.

        :param size: maximum number of bytes to return.
        :returns: the available bytes, or ``b""`` once the process has exited.
        """
        return await self._service.recv_any(size)

    async def write(self, data: bytes) -> None:
        """
        Send bytes to the process's stdin.

        :param data: the bytes to send.
        """
        await self._service.sendall(data)

    async def close(self) -> None:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None

    async def __aenter__(self) -> "OpenStdioSocketService":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()
