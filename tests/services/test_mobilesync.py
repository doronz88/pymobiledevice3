from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, call

import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.device_link import DeviceLink
from pymobiledevice3.services.mobilesync import (
    DATA_CLASS_VERSIONS,
    EMPTY_PARAMETER_STRING,
    MobileSyncError,
    MobileSyncService,
)

CALENDARS = "com.apple.Calendars"


def _service(tmp_path: Path, replies: list[Any]) -> tuple[MobileSyncService, AsyncMock]:
    connection = AsyncMock()
    connection.recv_plist = AsyncMock(side_effect=replies)
    sync = object.__new__(MobileSyncService)
    sync._service = connection
    sync._device_link = DeviceLink(connection, tmp_path)
    return sync, connection


@pytest.mark.asyncio
async def test_get_all_records_reads_every_batch_and_finishes(tmp_path: Path) -> None:
    calendar = {"com.apple.syncservices.RecordEntityName": "com.apple.calendars.Calendar"}
    event = {"com.apple.syncservices.RecordEntityName": "com.apple.calendars.Event"}
    sync, connection = _service(
        tmp_path,
        [
            ["SDMessageSyncDataClassWithComputer", CALENDARS, "", "anchor", "SDSyncTypeReset", 110, ""],
            ["SDMessageProcessChanges", CALENDARS, {"1/2": calendar}, True, EMPTY_PARAMETER_STRING],
            # an empty batch arrives as the empty-parameter string
            ["SDMessageProcessChanges", CALENDARS, EMPTY_PARAMETER_STRING, True, EMPTY_PARAMETER_STRING],
            ["SDMessageProcessChanges", CALENDARS, {"2/1": event}, False, EMPTY_PARAMETER_STRING],
            ["SDMessageDeviceReadyToReceiveChanges", CALENDARS],
            ["SDMessageDeviceFinishedSession", CALENDARS],
        ],
    )

    assert await sync.get_all_records(CALENDARS) == {"1/2": calendar, "2/1": event}
    ack = call(["SDMessageAcknowledgeChangesFromDevice", CALENDARS])
    assert connection.send_plist.await_args_list == [
        call([
            "SDMessageSyncDataClassWithDevice",
            CALENDARS,
            "---",
            "pymobiledevice3",
            DATA_CLASS_VERSIONS[CALENDARS],
            EMPTY_PARAMETER_STRING,
        ]),
        call(["SDMessageGetAllRecordsFromDevice", CALENDARS]),
        ack,
        ack,
        ack,
        call(["SDMessageFinishSessionOnDevice", CALENDARS]),
    ]


@pytest.mark.asyncio
async def test_refused_data_class_raises(tmp_path: Path) -> None:
    sync, _ = _service(
        tmp_path,
        [["SDMessageRefuseToSyncDataClassWithComputer", "com.apple.Notes", "No Data Store available for data class"]],
    )
    with pytest.raises(MobileSyncError, match="No Data Store"):
        await sync.get_all_records("com.apple.Notes", 105)


@pytest.mark.asyncio
async def test_device_cancel_raises(tmp_path: Path) -> None:
    sync, _ = _service(tmp_path, [["SDMessageCancelSession", CALENDARS, "busy"]])
    with pytest.raises(MobileSyncError, match="busy"):
        await sync.get_all_records(CALENDARS)


@pytest.mark.asyncio
@pytest.mark.parametrize("data_class", DATA_CLASS_VERSIONS)
async def test_get_all_records_on_device(lockdown: LockdownClient, data_class: str) -> None:
    async with MobileSyncService(lockdown) as sync:
        records = await sync.get_all_records(data_class)
    for record in records.values():
        assert record["com.apple.syncservices.RecordEntityName"].startswith("com.apple.")


@pytest.mark.asyncio
async def test_notes_is_refused_on_device(lockdown: LockdownClient) -> None:
    async with MobileSyncService(lockdown) as sync:
        with pytest.raises(MobileSyncError, match="No Data Store"):
            await sync.get_all_records("com.apple.Notes", 105)
