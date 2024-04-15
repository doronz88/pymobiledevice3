import logging
from typing import Optional

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection


class RemoteService:
    def __init__(self, rsd: RemoteServiceDiscoveryService, service_name: str):
        self.service_name = service_name
        self.rsd = rsd
        self.service: Optional[RemoteXPCConnection] = None
        self.logger = logging.getLogger(self.__module__)

    async def connect(self) -> None:
        self.service = self.rsd.start_remote_service(self.service_name)
        await self.service.connect()

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self) -> None:
        await self.service.close()
