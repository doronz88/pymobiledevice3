from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import DeviceFeatureNotSupportedError
from pymobiledevice3.remote.core_device.file_service import (
    FEATURE_LIST_FILES,
    FEATURE_TRANSFER_FILES,
    Domain,
    FileServiceService,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection


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
