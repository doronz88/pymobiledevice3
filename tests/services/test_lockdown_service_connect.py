import asyncio
import contextlib
import gc
from typing import Any, cast
from unittest.mock import Mock

from pymobiledevice3.services.lockdown_service import LockdownService


async def test_failed_connect_leaves_no_unretrieved_future_exception() -> None:
    attempts = 0

    async def start_lockdown_service(*args: Any, **kwargs: Any) -> None:
        nonlocal attempts
        attempts += 1
        raise OSError("no route")  # a new exception each time, so nothing outlives the attempt

    lockdown = Mock(start_lockdown_service=start_lockdown_service)
    service = LockdownService(cast(Any, lockdown), "com.example.service")

    async def connect() -> None:
        with contextlib.suppress(OSError):
            await service.connect()

    loop = asyncio.get_running_loop()
    reported: list[str] = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _, context: reported.append(context["message"]))
    try:
        await connect()
        gc.collect()  # the warning is reported when the failed attempt's future is collected
    finally:
        loop.set_exception_handler(previous)
    assert reported == []

    # and the attempt is reset, so connecting again starts over
    await connect()
    assert attempts == 2
