import asyncio
import logging
from inspect import isawaitable
from typing import Optional, Union

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
    """
    Base class for all services that wrap a single lockdown service on the device.

    A subclass binds to a named lockdown service (``service_name``) and is constructed with a
    `LockdownServiceProvider` (a lockdown client
    or an RSD/tunnel provider) that knows how to reach the device. The underlying service
    connection is established lazily: it is opened on first use, on an explicit `connect`
    call, or on entering the async context manager, and is closed on `close` or on exit.

    Instances are intended to be used as async context managers::

        async with SomeService(lockdown) as service:
            ...

    :ivar service_name: name of the wrapped lockdown service.
    :ivar lockdown: service provider used to start the service and reach the device.
    :ivar logger: logger named after the subclass module.
    """

    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        service_name: str,
        is_developer_service: bool = False,
        service: Optional[ServiceConnection] = None,
        include_escrow_bag: bool = False,
    ) -> None:
        """
        :param lockdown: service provider used to start the service and communicate with the device.
        :param service_name: name of the lockdown service to wrap; started lazily on first connection.
        :param is_developer_service: when True, the service is started via the developer-service path,
            which requires the DeveloperDiskImage to be mounted.
        :param service: an already-established service connection. When provided, no connection is
            started; otherwise a connection to ``service_name`` is opened lazily.
        :param include_escrow_bag: when True, include the host escrow bag when starting the service.
        """
        self._is_developer_service = is_developer_service
        self._include_escrow_bag = include_escrow_bag
        self.service_name: str = service_name
        self.lockdown: LockdownServiceProvider = lockdown
        self._service: Optional[ServiceConnection] = service
        self._service_proxy = _LazyServiceConnection(self)
        self.logger: logging.Logger = logging.getLogger(self.__module__)
        # Shared Future: the first connect() call creates it; concurrent callers join it
        # instead of racing to call start_lockdown_service() multiple times.
        self._connect_future: Optional[asyncio.Future[None]] = None

    @property
    def service(self) -> Union[ServiceConnection, _LazyServiceConnection]:
        """
        The wrapped service connection.

        :returns: the established `ServiceConnection`
            if already connected, otherwise a lazy proxy that connects on first awaited use.
        """
        if self._service is not None:
            return self._service
        return self._service_proxy

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self) -> None:
        """Close the underlying service connection (if any) and reset connection state."""
        if self._service is not None:
            await self._service.close()
            self._service = None
        self._connect_future = None

    async def connect(self) -> None:
        """
        Start and connect the wrapped service if not already connected.

        Does nothing when a connection already exists. Concurrent callers share a single
        in-flight connection attempt rather than starting the service multiple times; on
        failure the attempt is reset so it may be retried.

        :raises StartServiceError: if the service fails to start.
        """
        if self._service is not None:
            return
        if self._connect_future is not None:
            return await self._connect_future
        fut = asyncio.get_running_loop().create_future()
        self._connect_future = fut
        start_service = (
            self.lockdown.start_lockdown_developer_service
            if self._is_developer_service
            else self.lockdown.start_lockdown_service
        )
        try:
            self._service = await start_service(self.service_name, include_escrow_bag=self._include_escrow_bag)
            fut.set_result(None)
        except BaseException as e:
            self._connect_future = None  # allow retry
            if isinstance(e, asyncio.CancelledError):
                fut.cancel()
            else:
                fut.set_exception(e)
            raise
