import asyncio
import queue
from contextlib import suppress
from typing import Optional

import pytest
from bpylist2 import archiver

from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.exceptions import ConnectionTerminatedError, DvtException, ExtractingStackshotError
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import (
    CoreProfileSessionTap,
)


@pytest.mark.asyncio
async def test_stackshot(dvt) -> None:
    """
    Test getting stackshot.
    """
    time_config = await CoreProfileSessionTap.get_time_config(dvt)
    async with CoreProfileSessionTap(dvt, time_config) as tap:
        data = await tap.get_stackshot()

    assert "Darwin Kernel" in data["osversion"]
    # Constant kernel task data.
    assert data["task_snapshots"][0]["task_snapshot"]["ts_pid"] == 0
    assert data["task_snapshots"][0]["task_snapshot"]["ts_p_comm"] == "kernel_task"


@pytest.mark.asyncio
async def test_staskshot_channel_closed(dvt: DtxServiceProvider) -> None:
    """
    Test that an exception is raised when the channel is closed while waiting for stackshot data.
    """
    producer_task: Optional[asyncio.Task] = None

    try:
        time_config = await CoreProfileSessionTap.get_time_config(dvt)

        async with CoreProfileSessionTap(dvt, time_config) as tap:
            chunk_queue = queue.Queue()  # FIXME: This should be an asyncio.Queue, but the tap expects a queue.Queue. Refactor the tap to use an asyncio.Queue and then update this test.
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            # wait for first chunks
            async def wait_not_empty():
                while chunk_queue.empty():
                    await asyncio.sleep(0.01)

            await asyncio.wait_for(wait_not_empty(), timeout=0.5)
            await (await tap._service_ref())._channel.cancel()
            try:
                await asyncio.wait_for(producer_task, timeout=0.5)
            except asyncio.TimeoutError:
                pytest.fail("Producer task did not finish in time after channel cancellation")
            except ConnectionTerminatedError:
                pass
            except Exception as e:
                pytest.fail(f"Unexpected exception raised: {e}")
    finally:
        if producer_task and not producer_task.done():
            producer_task.cancel()
            with suppress(asyncio.CancelledError):
                await producer_task


@pytest.mark.asyncio
async def test_stackshot_raises_on_start_failure_notice() -> None:
    class FakeChannel:
        async def receive_message(self):
            return archiver.archive({
                "k": 8,
                "status": 2147483648,
                "notice": "Failed to start the recording: _lockKPerf: could not lock kperf.",
            })

    tap = CoreProfileSessionTap(None, {})
    tap.channel = FakeChannel()

    with pytest.raises(DvtException, match="Failed to start the recording"):
        await tap.get_stackshot(timeout=0.1)


@pytest.mark.asyncio
async def test_stackshot_times_out_without_stackshot_data() -> None:
    class FakeChannel:
        async def receive_message(self):
            return archiver.archive({"k": 7, "sm": {}})

    tap = CoreProfileSessionTap(None, {})
    tap.channel = FakeChannel()

    with pytest.raises(ExtractingStackshotError, match="timed out waiting for stackshot data"):
        await tap.get_stackshot(timeout=0.01)
