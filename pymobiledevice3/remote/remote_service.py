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

    def connect(self) -> None:
        self.service = self.rsd.start_remote_service(self.service_name)
        self.service.connect()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        self.service.close()
