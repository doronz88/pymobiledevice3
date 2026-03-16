from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Any, Optional

from bpylist2 import archiver

from pymobiledevice3.dtx import DTXService, dtx_method, dtx_on_data, dtx_on_notification
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider


class TapService(DTXService):
    def __init__(self, ctx):
        super().__init__(ctx)
        self.messages: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()

    def on_closed(self, reason: str = "") -> None:
        self.shutdown_queue(self.messages)
        super().on_closed(reason)

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
        await self.messages.put(("plist", payload))


class TapChannel(DtxService[TapService]):
    def __init__(self, provider: DtxServiceProvider, channel_identifier: str):
        super().__init__(provider)
        self._channel_identifier = channel_identifier

    async def connect(self) -> None:
        await self.provider.connect()
        if self._service is not None:
            return
        self._service = await self._acquire_channel()

    async def _acquire_channel(self) -> TapService:
        return await self.provider.dtx.open_channel(self._channel_identifier, TapService)


class TapMessageChannel:
    def __init__(self, service: TapService):
        self._service = service

    async def receive_key_value(self) -> tuple[Any, Any]:
        kind, payload = await self._service.messages.get()
        if kind == "plist":
            return payload, []
        return payload, []

    async def receive_plist(self) -> Any:
        while True:
            kind, payload = await self._service.messages.get()
            if kind == "plist":
                return payload
            try:
                return archiver.unarchive(payload)
            except Exception:
                continue

    async def receive_message(self) -> bytes:
        kind, payload = await self._service.messages.get()
        if kind == "data":
            return payload
        if payload is None:
            return b""
        return archiver.archive(payload)


class Tap:
    IDENTIFIER: str

    def __init__(self, dvt: DtxServiceProvider, channel_name: str, config: dict) -> None:
        self._provider = dvt
        self._channel_name = channel_name
        self._config = config
        self._channel: Optional[TapChannel] = None
        self.channel: Optional[TapMessageChannel] = None

    async def _service_ref(self) -> TapService:
        if self._channel is None:
            self._channel = TapChannel(self._provider, self._channel_name)
        await self._channel.connect()
        return self._channel.service

    def __enter__(self):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aenter__(self):
        service = await self._service_ref()
        self.channel = TapMessageChannel(service)
        await service.set_config_(self._config)
        await service.start()
        # first message is just kind of an ack
        await self.channel.receive_plist()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await (await self._service_ref()).stop()

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        assert self.channel is not None
        while True:
            for message in await self.channel.receive_plist():
                yield message
