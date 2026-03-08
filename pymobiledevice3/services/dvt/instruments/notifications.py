import asyncio
import typing
from typing import Any

from pymobiledevice3.dtx import DTXService, dtx_method, dtx_on_dispatch, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class _NotificationsService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.mobilenotifications"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.events: asyncio.Queue[Any] = asyncio.Queue()

    @dtx_method("setApplicationStateNotificationsEnabled:", expects_reply=False)
    async def set_application_state_notifications_enabled_(self, enabled: bool) -> None: ...

    @dtx_method("setMemoryNotificationsEnabled:", expects_reply=False)
    async def set_memory_notifications_enabled_(self, enabled: bool) -> None: ...

    @dtx_on_dispatch
    async def _on_dispatch(self, selector: str, *args: Any) -> None:
        await self.events.put((selector, list(args)))

    @dtx_on_notification
    async def _on_notification(self, payload: Any) -> None:
        await self.events.put(payload)


class _NotificationsChannel(DtxService[_NotificationsService]):
    pass


class Notifications:
    IDENTIFIER = _NotificationsService.IDENTIFIER

    def __init__(self, dvt: DtxServiceProvider):
        self._provider = dvt
        self._channel: _NotificationsChannel | None = None

    async def _service_ref(self) -> _NotificationsService:
        if self._channel is None:
            self._channel = _NotificationsChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def __aenter__(self):
        service = await self._service_ref()
        await service.set_application_state_notifications_enabled_(True)
        await service.set_memory_notifications_enabled_(True)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        service = await self._service_ref()
        await service.set_application_state_notifications_enabled_(False)
        await service.set_memory_notifications_enabled_(False)

    async def __aiter__(self) -> typing.AsyncGenerator[Any, None]:
        while True:
            yield await (await self._service_ref()).events.get()
