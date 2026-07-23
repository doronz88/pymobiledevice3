import logging
from typing import Any, Optional

from pymobiledevice3.exceptions import NotConnectedError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection


class RemoteService:
    def __init__(self, rsd: RemoteServiceDiscoveryService, service_name: str):
        self.service_name = service_name
        self.rsd = rsd
        self._service: Optional[RemoteXPCConnection] = None
        self.logger = logging.getLogger(self.__module__)

    @property
    def service(self) -> RemoteXPCConnection:
        """The underlying RemoteXPC connection.

        :raises NotConnectedError: if accessed before ``connect()`` (or ``async with``) has run.
        """
        if self._service is None:
            raise NotConnectedError(f"{type(self).__name__} is not connected; call connect() first")
        return self._service

    async def connect(self) -> None:
        self._service = self.rsd.start_remote_service(self.service_name)
        await self._service.connect()

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        await self.close()

    async def close(self) -> None:
        # Tolerant of never-connected instances (e.g. connect() raised inside __aenter__).
        if self._service is not None:
            await self._service.close()
