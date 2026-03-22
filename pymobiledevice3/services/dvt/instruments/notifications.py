import asyncio
import typing
from contextlib import suppress
from typing import Any

from pymobiledevice3.dtx import DTXService, dtx_method, dtx_on_dispatch, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import ConnectionTerminatedError


class NotificationsService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.mobilenotifications"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.events: asyncio.Queue[Any] = asyncio.Queue()
        self.stop_exception: typing.Optional[Exception] = None

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

    async def aclose(self, reason: str, exc: typing.Optional[Exception] = None) -> None:
        self.stop_exception = exc
        self.events.shutdown()
        await super().aclose(reason, exc)


class Notifications(DtxService[NotificationsService]):
    async def __aenter__(self):
        await super().__aenter__()
        await self.service.set_application_state_notifications_enabled_(True)
        await self.service.set_memory_notifications_enabled_(True)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        with suppress(ConnectionTerminatedError):
            await self.service.set_application_state_notifications_enabled_(False)
            await self.service.set_memory_notifications_enabled_(False)
        await super().__aexit__(exc_type, exc_val, exc_tb)

    async def __aiter__(self) -> typing.AsyncGenerator[Any, None]:
        try:
            while True:
                yield await self.service.events.get()
        except asyncio.QueueShutDown:
            ex = self.service.stop_exception
        if ex is not None:
            raise ex
