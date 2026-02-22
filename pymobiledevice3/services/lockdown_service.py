import logging
from inspect import isawaitable
from typing import Optional

from typing_extensions import Self

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection


class _LazyServiceConnection:
    def __init__(self, owner: "LockdownService") -> None:
        self._owner = owner

    async def _get_conn(self) -> ServiceConnection:
        await self._owner.connect()
        if self._owner._service is None:
            raise ConnectionError("service is not connected")
        return self._owner._service

    def __getattr__(self, name: str):
        async def _call(*args, **kwargs):
            conn = await self._get_conn()
            attr = getattr(conn, name)
            result = attr(*args, **kwargs)
            if isawaitable(result):
                return await result
            return result

        return _call


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
        self._is_developer_service = is_developer_service
        self._include_escrow_bag = include_escrow_bag
        self.service_name: str = service_name
        self.lockdown: LockdownServiceProvider = lockdown
        self._service: Optional[ServiceConnection] = service
        self._service_proxy = _LazyServiceConnection(self)
        self.logger: logging.Logger = logging.getLogger(self.__module__)

    @property
    def service(self) -> ServiceConnection | _LazyServiceConnection:
        if self._service is not None:
            return self._service
        return self._service_proxy

    def __enter__(self) -> Self:
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self) -> None:
        if self._service is not None:
            await self._service.close()
            self._service = None

    async def connect(self) -> None:
        if self._service is not None:
            return
        start_service = (
            self.lockdown.start_lockdown_developer_service
            if self._is_developer_service
            else self.lockdown.start_lockdown_service
        )
        self._service = await start_service(self.service_name, include_escrow_bag=self._include_escrow_bag)
