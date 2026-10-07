from typing import Any, cast

import pytest

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService
from pymobiledevice3.services.storage_mounter_bridge import StorageMounterBridgeError, StorageMounterBridgeService


class FakeConnection:
    def __init__(self, response: dict[str, Any]) -> None:
        self.sent: list[dict[str, Any]] = []
        self._response = response

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(request)
        return self._response


def _service(response: dict[str, Any]) -> tuple[StorageMounterBridgeService, FakeConnection]:
    connection = FakeConnection(response)
    service = StorageMounterBridgeService(cast(RemoteServiceDiscoveryService, object()))
    service._service = cast(RemoteXPCConnection, connection)
    return service, connection


@pytest.mark.asyncio
async def test_commands_are_wrapped_in_the_request_dictionary() -> None:
    service, connection = _service({"PersonalizationNonce": b"\x01" * 48})

    assert await service.query_nonce("DeveloperDiskImage") == b"\x01" * 48

    assert connection.sent == [
        {
            "XPCRequestDictionary": {
                "Command": "QueryNonce",
                "HostProcessName": "pymobiledevice3",
                "PersonalizedImageType": "DeveloperDiskImage",
            }
        }
    ]


@pytest.mark.asyncio
async def test_error_reply_raises() -> None:
    service, _ = _service({"Error": "InternalError", "DetailedError": "no cached manifest"})

    with pytest.raises(StorageMounterBridgeError, match="no cached manifest") as error:
        await service.invoke("QueryPersonalizationManifest")

    assert error.value.error == "InternalError"


@pytest.mark.asyncio
async def test_bridge_agrees_with_the_image_mounter_on_device(service_provider) -> None:
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("the storage mounter bridge requires an RSD tunnel")

    async with StorageMounterBridgeService(service_provider) as bridge:
        devices = await bridge.copy_devices()
        identifiers = await bridge.query_personalization_identifiers()
        assert isinstance(await bridge.query_developer_mode_status(), bool)
        assert len(await bridge.query_nonce()) > 0
    async with MobileImageMounterService(service_provider) as mounter:
        assert await mounter.copy_devices() == devices
        assert await mounter.query_personalization_identifiers() == identifiers
