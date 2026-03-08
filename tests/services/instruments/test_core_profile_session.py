import pytest
from bpylist2 import archiver

from pymobiledevice3.exceptions import DvtException, ExtractingStackshotError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import (
    CoreProfileSessionTap,
)


@pytest.mark.asyncio
async def test_stackshot(service_provider: LockdownServiceProvider, dvt) -> None:
    """
    Test getting stackshot.
    """
    _ = dvt
    async with DvtSecureSocketProxyService(lockdown=service_provider) as legacy_dvt:
        time_config = await CoreProfileSessionTap.get_time_config(legacy_dvt)
        async with CoreProfileSessionTap(legacy_dvt, time_config) as tap:
            data = await tap.get_stackshot()

    assert "Darwin Kernel" in data["osversion"]
    # Constant kernel task data.
    assert data["task_snapshots"][0]["task_snapshot"]["ts_pid"] == 0
    assert data["task_snapshots"][0]["task_snapshot"]["ts_p_comm"] == "kernel_task"


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
