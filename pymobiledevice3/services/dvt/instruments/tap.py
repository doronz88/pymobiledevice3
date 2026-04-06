from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from contextlib import suppress
from typing import Any, ClassVar, Literal, Optional, Union

from bpylist2 import archiver

from pymobiledevice3.dtx import DTXService, dtx_method, dtx_on_data, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import ConnectionTerminatedError

logger = logging.getLogger(__name__)

ReceivedMessageType = Union[Literal["notification"], Literal["data"]]


class TapService(DTXService):
    def __init__(self, ctx):
        super().__init__(ctx)
        self.stop_exception: Optional[Exception] = None
        self.messages: asyncio.Queue[tuple[ReceivedMessageType, Any]] = asyncio.Queue()

    @dtx_method("setConfig:", expects_reply=False)
    async def set_config_(self, config: dict) -> None: ...

    @dtx_method("start", expects_reply=False)
    async def start(self) -> None: ...

    @dtx_method("stop", expects_reply=False)
    async def stop(self) -> None: ...

    @dtx_on_data
    async def _on_data(self, payload: bytes) -> None:
        await self.messages.put(("data", payload))

    @dtx_on_notification
    async def _on_notification(self, payload: Any) -> None:
        await self.messages.put(("notification", payload))

    async def aclose(self, reason: str, exc: Optional[Exception] = None) -> None:
        self.stop_exception = exc
        self.messages.shutdown()
        await super().aclose(reason, exc)


class Tap(ABC, DtxService[TapService]):
    CHANNEL_IDENTIFIER: ClassVar[str]  # subclasses MUST define this

    @abstractmethod
    async def config(self) -> dict: ...

    def __enter__(self):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aenter__(self):
        await super().__aenter__()
        await self.service.set_config_(await self.config())
        await self.service.start()
        # first message is just kind of an ack
        msg = await self.service.messages.get()
        if msg[0] != "notification":
            self.logger.warning("Expected first message to be a notification, got %s, payload: %s", msg[0], msg[1])
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        with suppress(ConnectionTerminatedError):
            await self.service.stop()
            await super().__aexit__(exc_type, exc_val, exc_tb)

    async def messages(self) -> AsyncGenerator[tuple[ReceivedMessageType, Any], None]:
        """Yield raw messages from the TAP, including both notifications and data."""
        try:
            while True:
                msg = await self.service.messages.get()
                yield msg
        except asyncio.QueueShutDown:
            ex = self.service.stop_exception
            if ex is not None:
                raise ex from getattr(ex, "__cause__", None)

    async def notifications(self) -> AsyncGenerator[Any, None]:
        """Yield notification messages from the TAP, ignoring data messages."""
        async for kind, payload in self.messages():
            if kind == "notification":
                yield payload

    async def data(self) -> AsyncGenerator[bytes, None]:
        """Yield raw data messages from the TAP, ignoring notifications."""
        async for kind, payload in self.messages():
            if kind == "data":
                yield payload

    async def objects(self) -> AsyncGenerator[Any, None]:
        """Yield notifications and parse data messages as archived objects."""
        async for kind, payload in self.messages():
            if kind == "notification":
                yield payload
                continue
            try:
                yield archiver.unarchive(payload)
            except Exception as e:
                self.logger.error("Failed to unarchive TAP message: %s, payload=%r", e, payload[:100])

    __aiter__ = objects
