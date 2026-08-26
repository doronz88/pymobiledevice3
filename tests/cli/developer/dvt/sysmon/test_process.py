import asyncio
import contextlib
import json
from io import StringIO
from typing import Any

import pytest
import pytest_asyncio

from pymobiledevice3.cli.developer.dvt.sysmon.process import (
    ProcessSelectionMode,
    _process_sort_key,
    _select_process_from_snapshot,
    iter_processes,
    sysmon_process_monitor_process_task,
    sysmon_process_monitor_threshold_task,
    sysmon_process_single_task,
)
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap

RELAUNCHABLE_BUNDLE_ID = "com.apple.mobilesafari"
RELAUNCHABLE_PROCESS_NAME = "MobileSafari"


@pytest_asyncio.fixture
async def process_snapshot(dvt) -> list[dict[str, Any]]:
    async with await Sysmontap.create(dvt) as sysmon:
        async for process_snapshot in iter_processes(sysmon):
            return process_snapshot

    pytest.fail("failed to collect an initialized process snapshot")


@pytest.mark.asyncio
async def test_iter_processes_yields_process_dicts(process_snapshot) -> None:
    assert len(process_snapshot) > 0
    assert isinstance(process_snapshot[0], dict)
    assert process_snapshot[0].get("pid")


@pytest.mark.asyncio
async def test_select_process_from_snapshot_filters_by_existing_pid(process_snapshot) -> None:
    process = process_snapshot[0]

    selected_process = _select_process_from_snapshot(
        process_snapshot, {"pid": [str(process["pid"])]}, ProcessSelectionMode.FIRST
    )

    assert selected_process.get("pid") == process.get("pid")


@pytest.mark.asyncio
async def test_select_process_from_snapshot_first_and_last_follow_sorted_order(
    process_snapshot,
) -> None:
    if len(process_snapshot) < 2:
        pytest.skip("requires at least two processes in the current snapshot")

    sorted_processes = sorted(process_snapshot, key=_process_sort_key)

    assert _select_process_from_snapshot(process_snapshot, {}, ProcessSelectionMode.FIRST) == sorted_processes[0]
    assert _select_process_from_snapshot(process_snapshot, {}, ProcessSelectionMode.LAST) == sorted_processes[-1]


@pytest.mark.asyncio
async def test_sysmon_process_single_task_writes_json_to_buffer(service_provider) -> None:
    out = StringIO()

    await sysmon_process_single_task(service_provider, keys=["pid", "name"], out=out)

    result = json.loads(out.getvalue())
    assert len(result) > 0
    assert result[0].get("pid")
    assert result[0].get("name")


@pytest.mark.asyncio
async def test_sysmon_process_monitor_threshold_task_writes_jsonl_to_buffer(service_provider) -> None:
    out = StringIO()

    await sysmon_process_monitor_threshold_task(service_provider, threshold=0.0, duration=500, keys=["pid"], out=out)

    lines = [line for line in out.getvalue().splitlines() if line.strip()]
    assert len(lines) > 0
    first_record = json.loads(lines[0])
    assert first_record.get("pid")


@pytest.mark.asyncio
async def test_sysmon_process_monitor_process_task_keep_monitoring_streams_by_filter(service_provider) -> None:
    out = StringIO()

    await sysmon_process_monitor_process_task(
        service_provider,
        filter_expressions=["name=SpringBoard"],
        duration=1500,
        choose=ProcessSelectionMode.LAST,
        keys=["pid", "name"],
        out=out,
        keep_monitoring=True,
    )

    records = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    assert len(records) > 0
    assert {record["name"] for record in records} == {"SpringBoard"}


async def _wait_for_monitored_pid(pid: int, out: StringIO, monitor_task: "asyncio.Task[None]") -> None:
    """Wait for `pid` to show up in the monitor's JSONL output, failing if monitoring stops first."""

    def emitted_pids() -> set[int]:
        return {json.loads(line)["pid"] for line in out.getvalue().splitlines() if line.strip()}

    deadline = asyncio.get_running_loop().time() + 30
    while asyncio.get_running_loop().time() < deadline:
        if pid in emitted_pids():
            return
        if monitor_task.done():
            # Surfaces a monitoring exception, and otherwise reports the early exit this test guards against.
            monitor_task.result()
            pytest.fail(f"monitoring stopped before pid {pid} was observed. Emitted pids: {sorted(emitted_pids())}")
        await asyncio.sleep(0.25)

    pytest.fail(f"pid {pid} was not observed within the timeout. Emitted pids: {sorted(emitted_pids())}")


@pytest.mark.asyncio
async def test_sysmon_process_monitor_process_task_keep_monitoring_reacquires_relaunched_process(
    dvt, service_provider
) -> None:
    out = StringIO()

    async with ProcessControl(dvt) as process_control:
        first_pid = await process_control.launch(RELAUNCHABLE_BUNDLE_ID)

        monitor_task = asyncio.create_task(
            sysmon_process_monitor_process_task(
                service_provider,
                filter_expressions=[f"name={RELAUNCHABLE_PROCESS_NAME}"],
                # Upper bound only. The test cancels the task as soon as the relaunched process is observed.
                duration=120000,
                choose=ProcessSelectionMode.LAST,
                keys=["pid", "name"],
                out=out,
                keep_monitoring=True,
            )
        )

        try:
            await _wait_for_monitored_pid(first_pid, out, monitor_task)

            # launch() kills the running instance first, so the app comes back under a fresh identity.
            second_pid = await process_control.launch(RELAUNCHABLE_BUNDLE_ID)
            assert second_pid != first_pid

            await _wait_for_monitored_pid(second_pid, out, monitor_task)
        finally:
            monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await monitor_task
