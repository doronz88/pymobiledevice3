import asyncio
import typing
from typing import Any

from pymobiledevice3.dtx import DTXService, dtx_method, dtx_on_dispatch, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService


class NotificationsService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.mobilenotifications"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.events: asyncio.Queue[Any] = asyncio.Queue()

    def on_closed(self, reason: str = "") -> None:
        self.shutdown_queue(self.events)
        super().on_closed(reason)

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


class Notifications(DtxService[NotificationsService]):
    async def __aenter__(self):
        await self.connect()
        await self.service.set_application_state_notifications_enabled_(True)
        await self.service.set_memory_notifications_enabled_(True)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.service.set_application_state_notifications_enabled_(False)
        await self.service.set_memory_notifications_enabled_(False)

    async def __aiter__(self) -> typing.AsyncGenerator[Any, None]:
        while True:
            yield await self.service.events.get()
