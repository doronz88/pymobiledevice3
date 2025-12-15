import logging
from typing import Optional

from typing_extensions import Self

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection


class LockdownService:
    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        service_name: str,
        is_developer_service: bool = False,
        service: Optional[ServiceConnection] = None,
        include_escrow_bag: bool = False,
    ) -> None:
        """
        :param lockdown: server provider
        :param service_name: wrapped service name - will attempt
        :param is_developer_service: should DeveloperDiskImage be mounted before
        :param service: an established service connection object. If none, will attempt connecting to service_name
        """

        if service is None:
            start_service = (
                lockdown.start_lockdown_developer_service if is_developer_service else lockdown.start_lockdown_service
            )
            service = start_service(service_name, include_escrow_bag=include_escrow_bag)

        self.service_name: str = service_name
        self.lockdown: LockdownServiceProvider = lockdown
        self.service: ServiceConnection = service
        self.logger: logging.Logger = logging.getLogger(self.__module__)

    def __enter__(self) -> Self:
        return self

    async def __aenter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.service.aio_close()

    def close(self) -> None:
        self.service.close()
