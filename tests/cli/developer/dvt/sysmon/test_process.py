import json
from io import StringIO

import pytest
import pytest_asyncio

from pymobiledevice3.cli.developer.dvt.sysmon.process import (
    ProcessSelectionMode,
    _process_sort_key,
    _select_process_from_snapshot,
    iter_initialized_processes,
    sysmon_process_monitor_threshold_task,
    sysmon_process_single_task,
)
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap


@pytest_asyncio.fixture
async def process_snapshot(dvt) -> list[dict]:
    async with await Sysmontap.create(dvt) as sysmon:
        async for process_snapshot in iter_initialized_processes(sysmon):
            return process_snapshot

    pytest.fail("failed to collect an initialized process snapshot")


@pytest.mark.asyncio
async def test_iter_initialized_processes_yields_process_dicts(process_snapshot) -> None:
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
