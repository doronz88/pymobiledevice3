import asyncio

import pytest

from pymobiledevice3.dtx.service import DTXQueue, DTXService, QueueShutDown

pytestmark = pytest.mark.asyncio


def _service() -> DTXService:
    return object.__new__(DTXService)


async def test_dtx_queue_uses_native_asyncio_queue_when_shutdown_is_available() -> None:
    if hasattr(asyncio, "QueueShutDown"):
        assert DTXQueue is asyncio.Queue


async def test_shutdown_queue_wakes_pending_asyncio_queue_getters() -> None:
    queue = DTXQueue()
    task = asyncio.create_task(queue.get())
    await asyncio.sleep(0)

    _service().shutdown_queue(queue)

    with pytest.raises(QueueShutDown):
        await task


async def test_shutdown_queue_rejects_future_asyncio_queue_gets() -> None:
    queue = DTXQueue()

    _service().shutdown_queue(queue)

    with pytest.raises(QueueShutDown):
        await queue.get()


async def test_shutdown_queue_rejects_future_asyncio_queue_puts() -> None:
    queue = DTXQueue()

    _service().shutdown_queue(queue)

    with pytest.raises(QueueShutDown):
        await queue.put("event")


async def test_shutdown_queue_rejects_unsupported_queue() -> None:
    with pytest.raises(TypeError, match="does not support shutdown"):
        _service().shutdown_queue(object())


async def test_shutdown_queue_rejects_plain_asyncio_queue_on_python_without_native_shutdown() -> None:
    queue = asyncio.Queue()

    if hasattr(queue, "shutdown"):
        _service().shutdown_queue(queue)
    else:
        with pytest.raises(TypeError, match="does not support shutdown"):
            _service().shutdown_queue(queue)
