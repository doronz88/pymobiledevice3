import asyncio
import os
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import CoreDeviceError, DeviceFeatureNotSupportedError
from pymobiledevice3.remote.core_device.file_service import (
    FEATURE_FILE_SYSTEM_OPERATION,
    FEATURE_LIST_FILES,
    FEATURE_MONITOR_FILE_CHANGES,
    FEATURE_TRANSFER_FILES,
    Domain,
    FileChangeEvent,
    FileServiceService,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type


class FakeConnection:
    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.sent: list[dict[str, Any]] = []

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(request)
        return self._response


def make_file_service(features: list[str], response: dict[str, Any]) -> tuple[FileServiceService, FakeConnection]:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {
        "Properties": {"OSVersion": "26.0"},
        "Services": {FileServiceService.CTRL_SERVICE_NAME: {"Port": "1024", "Properties": {"Features": features}}},
    }
    rsd.udid = "udid"
    service = FileServiceService(rsd, Domain.TEMPORARY)
    service.session = "session-id"
    connection = FakeConnection(response)
    service._service = cast(RemoteXPCConnection, connection)
    return service, connection


@pytest.mark.asyncio
async def test_retrieve_directory_list_requires_the_listfiles_capability() -> None:
    service, connection = make_file_service([FEATURE_TRANSFER_FILES], {"FileList": []})

    with pytest.raises(DeviceFeatureNotSupportedError, match="listFiles"):
        await service.retrieve_directory_list(".")
    assert connection.sent == []


@pytest.mark.asyncio
async def test_retrieve_directory_list_sends_the_cmd_when_advertised() -> None:
    service, connection = make_file_service([FEATURE_LIST_FILES], {"FileList": ["a", "b"]})

    assert await service.retrieve_directory_list(".") == ["a", "b"]

    (request,) = connection.sent
    assert request["Cmd"] == "RetrieveDirectoryList"


@pytest.mark.asyncio
async def test_retrieve_file_requires_the_transferfiles_capability() -> None:
    service, connection = make_file_service([FEATURE_LIST_FILES], {})

    with pytest.raises(DeviceFeatureNotSupportedError, match="transferFiles"):
        await service.retrieve_file(".")
    assert connection.sent == []


@pytest.mark.asyncio
async def test_propose_empty_file_requires_the_transferfiles_capability() -> None:
    service, connection = make_file_service([FEATURE_LIST_FILES], {})

    with pytest.raises(DeviceFeatureNotSupportedError, match="transferFiles"):
        await service.propose_empty_file("file.txt")
    assert connection.sent == []


@pytest.mark.asyncio
async def test_file_system_operations_require_the_capability() -> None:
    service, connection = make_file_service([FEATURE_LIST_FILES], {"Response": 1})

    with pytest.raises(DeviceFeatureNotSupportedError, match="filesystemoperation"):
        await service.create_directory("dir")
    assert connection.sent == []


@pytest.mark.asyncio
async def test_rename_names_both_paths() -> None:
    service, connection = make_file_service([FEATURE_FILE_SYSTEM_OPERATION], {"Response": 1})

    await service.rename("old", "new")

    assert connection.sent == [
        {
            "Cmd": "FileSystemOperation",
            "OperationType": "Rename",
            "SessionID": "session-id",
            "OldPath": "old",
            "NewPath": "new",
        }
    ]


@pytest.mark.asyncio
async def test_get_attributes_decodes_the_json_reply() -> None:
    service, connection = make_file_service(
        [FEATURE_FILE_SYSTEM_OPERATION], {"Response": 1, "Attributes": b'{"fileType":"regular","size":5}'}
    )

    assert await service.get_attributes("file", follow_symlinks=False) == {"fileType": "regular", "size": 5}
    assert connection.sent[0]["FollowSymlinks"] is False


@pytest.mark.asyncio
async def test_file_io_uses_the_integer_types_the_device_decodes() -> None:
    # The device reads each of these with a fixed XPC integer type and silently treats the other
    # one as zero: a signed offset reads from the start, an unsigned length reads nothing.
    service, connection = make_file_service([FEATURE_FILE_SYSTEM_OPERATION], {"Response": 1, "FileDescriptor": 8})

    file_descriptor = await service.open_file("file", os.O_CREAT | os.O_RDWR, 0o600)
    await service.write_file(file_descriptor, 6, b"data")
    await service.truncate_file(file_descriptor, 3)

    open_request, write_request, truncate_request = connection.sent
    assert type(open_request["Flags"]) is XpcInt64Type and type(open_request["Mode"]) is XpcUInt64Type
    assert type(write_request["FileDescriptor"]) is XpcInt64Type and type(write_request["Offset"]) is XpcUInt64Type
    assert write_request["FileData"] == b"data"
    assert type(truncate_request["Length"]) is XpcInt64Type


@pytest.mark.asyncio
async def test_failed_operation_raises_with_the_device_message() -> None:
    service, _ = make_file_service(
        [FEATURE_FILE_SYSTEM_OPERATION],
        {"EncodedError": {"ErrorCode": 11001, "NSLocalizedDescription": "Failed to remove file at path: x"}},
    )

    with pytest.raises(CoreDeviceError, match="Failed to remove file at path: x"):
        await service.remove_file("x")


class MonitoringConnection(FakeConnection):
    def __init__(self, pushed: list[dict[str, Any]]) -> None:
        super().__init__({"Response": 1, "MonitoringID": "id"})
        self._pushed = pushed

    async def receive_response(self) -> dict[str, Any]:
        return self._pushed.pop(0)


@pytest.mark.asyncio
async def test_monitor_requests_this_domain_and_yields_events() -> None:
    service, _ = make_file_service([FEATURE_MONITOR_FILE_CHANGES], {})
    connection = MonitoringConnection([
        {
            "MonitoringEvents": [
                {"eventType": "created", "relativePath": "a.txt", "domain": 3},
                {"eventType": "renamed", "relativePath": "b.txt", "domain": 3, "domainIdentifier": "group.x"},
            ]
        }
    ])
    service._service = cast(RemoteXPCConnection, connection)

    events = []
    async for event in service.monitor(["Documents"]):
        events.append(event)
        if len(events) == 2:
            break

    request = connection.sent[0]
    assert request["Cmd"] == "MonitorFileEvents" and request["SessionID"] == "session-id"
    assert request["MonitoringConfig"] == {"domains": [3], "domainIdentifiers": [""], "relativePaths": ["Documents"]}
    # A signed domain crashes the device's decoder; the token must be a UUID string.
    assert type(request["MonitoringConfig"]["domains"][0]) is XpcUInt64Type
    assert len(request["MessageUUID"]) == 36
    assert events == [
        FileChangeEvent("created", "a.txt", Domain.TEMPORARY),
        FileChangeEvent("renamed", "b.txt", Domain.TEMPORARY, "group.x"),
    ]


@pytest.mark.asyncio
async def test_file_operations_and_monitoring_on_device(service_provider) -> None:
    """Create, write, rename and remove a file in the temporary domain while a monitor watches it."""
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("the file service requires an RSD tunnel")
    features = service_provider.get_service_features(FileServiceService.CTRL_SERVICE_NAME)
    if FEATURE_FILE_SYSTEM_OPERATION not in features or FEATURE_MONITOR_FILE_CHANGES not in features:
        pytest.skip("the mounted DeveloperDiskImage does not offer file-system operations and monitoring")
    name = "pymobiledevice3-test.bin"
    data = os.urandom(700 * 1024)

    # Every session is closed before the test ends: dtfileserviced stops answering new requests
    # once a client disappears with a session still open.
    async with FileServiceService(service_provider, Domain.TEMPORARY) as watcher:
        monitor = watcher.monitor()
        first_event = asyncio.ensure_future(monitor.__anext__())
        await asyncio.sleep(1)
        async with FileServiceService(service_provider, Domain.TEMPORARY) as files:
            await files.set_file_contents(name, data, mode=0o600)
            assert await files.get_file_contents(name) == data
            attributes = await files.get_attributes(name)
            assert (attributes["fileType"], attributes["size"], attributes["permissions"]) == (
                "regular",
                len(data),
                0o600,
            )
            await files.rename(name, name + ".renamed")
            await files.remove_file(name + ".renamed")
            with pytest.raises(CoreDeviceError):
                await files.remove_file(name + ".renamed")
        event = await asyncio.wait_for(first_event, 15)
        await monitor.aclose()

    assert event.event_type == "created" and event.relative_path == name and event.domain == Domain.TEMPORARY
