from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import DeviceFeatureNotSupportedError
from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

APP_SERVICE = "com.apple.coredevice.appservice"


class FakeConnection:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(request)
        return {"CoreDevice.output": {"ok": True}}


def make_app_service(features: list[str]) -> tuple[AppServiceService, FakeConnection]:
    """An AppServiceService over a handshake advertising *features*, with a recording connection."""
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {
        "Properties": {"OSVersion": "26.0"},
        "Services": {APP_SERVICE: {"Port": "1024", "Properties": {"Features": features}}},
    }
    rsd.udid = "udid"
    service = AppServiceService(rsd)
    connection = FakeConnection()
    service._service = cast(RemoteXPCConnection, connection)
    return service, connection


@pytest.mark.asyncio
async def test_invoke_unadvertised_feature_raises_without_sending() -> None:
    service, connection = make_app_service(["com.apple.coredevice.feature.listapps"])
    with pytest.raises(DeviceFeatureNotSupportedError) as exc_info:
        await service.invoke("com.apple.coredevice.feature.streamapplist")
    assert exc_info.value.feature == "com.apple.coredevice.feature.streamapplist"
    assert connection.sent == []


@pytest.mark.asyncio
async def test_invoke_advertised_feature_sends_request() -> None:
    service, connection = make_app_service(["com.apple.coredevice.feature.listapps"])
    output = await service.invoke("com.apple.coredevice.feature.listapps")
    assert output == {"ok": True}
    assert len(connection.sent) == 1
    assert connection.sent[0]["CoreDevice.featureIdentifier"] == "com.apple.coredevice.feature.listapps"


@pytest.mark.asyncio
async def test_invoke_action_only_skips_feature_check() -> None:
    # Actions are not part of the advertised Features list, so they are never checked against it.
    service, connection = make_app_service(["com.apple.coredevice.feature.listapps"])
    output = await service.invoke(action_identifier="com.apple.coredevice.action.getuserinterfacestyle")
    assert output == {"ok": True}
    assert len(connection.sent) == 1


@pytest.mark.asyncio
async def test_stream_invoke_unadvertised_feature_raises_without_sending() -> None:
    service, connection = make_app_service(["com.apple.coredevice.feature.listapps"])
    stream = service.stream_invoke("com.apple.coredevice.feature.streamapplist")
    with pytest.raises(DeviceFeatureNotSupportedError):
        await stream.__anext__()
    assert connection.sent == []
