from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import CoreDeviceError, DeviceFeatureNotSupportedError
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


class FailingConnection:
    """A connection whose ``invoke`` reply carries a structured CoreDevice error."""

    def __init__(self, error: dict[str, Any]) -> None:
        self.error = error

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        return {"CoreDevice.error": self.error}


def _make_failing_app_service(error: dict[str, Any]) -> AppServiceService:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {
        "Properties": {"OSVersion": "26.0"},
        "Services": {
            APP_SERVICE: {"Port": "1024", "Properties": {"Features": ["com.apple.coredevice.feature.listapps"]}}
        },
    }
    rsd.udid = "udid"
    service = AppServiceService(rsd)
    service._service = cast(RemoteXPCConnection, FailingConnection(error))
    return service


# The exact ``CoreDevice.error`` payload the device returns for `startmediastream`
# when the microphone or camera is in use (captured on iPhone18,4 / iOS 27.0).
_MIC_IN_USE_ARCHIVE = (
    b"bplist00\xd4\x01\x02\x03\x04\x05\x06\x07\nX$versionY$archiverT$topX$objects\x12\x00\x01\x86\xa0_\x10\x0f"
    b"NSKeyedArchiver\xd1\x08\tTroot\x80\x01\xa5\x0b\x0c\x15\x16\x17U$null\xd3\r\x0e\x0f\x10\x12\x14WNS.keysZ"
    b"NS.objectsV$class\xa1\x11\x80\x02\xa1\x13\x80\x03\x80\x04_\x10\x16NSLocalizedDescription_\x104The device "
    b"microphone or camera is currently in use.\xd2\x18\x19\x1a\x1bZ$classnameX$classes\\NSDictionary\xa2\x1a"
    b"\x1cXNSObject\x00\x08\x00\x11\x00\x1a\x00$\x00)\x002\x007\x00I\x00L\x00Q\x00S\x00Y\x00_\x00f\x00n\x00y\x00"
    b"\x80\x00\x82\x00\x84\x00\x86\x00\x88\x00\x8a\x00\xa3\x00\xda\x00\xdf\x00\xea\x00\xf3\x01\x00\x01\x03\x00"
    b"\x00\x00\x00\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x1d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x01\x0c"
)


@pytest.mark.asyncio
async def test_invoke_surfaces_structured_core_device_error() -> None:
    service = _make_failing_app_service({
        "code": 9022,
        "domain": "com.apple.dt.CoreDeviceError",
        "userInfo": {"NSLocalizedDescription": "The device microphone or camera is currently in use."},
        "userInfoWithNSSecureCoding": _MIC_IN_USE_ARCHIVE,
    })
    with pytest.raises(CoreDeviceError) as exc_info:
        await service.invoke("com.apple.coredevice.feature.listapps")
    exc = exc_info.value
    assert exc.code == CoreDeviceError.MEDIA_STREAM_SENSOR_IN_USE
    assert exc.domain == "com.apple.dt.CoreDeviceError"
    assert exc.localized_description == "The device microphone or camera is currently in use."
    assert "currently in use" in str(exc)
    # The opaque archive must not leak into the message.
    assert "bplist00" not in str(exc)


@pytest.mark.asyncio
async def test_invoke_falls_back_to_archive_for_description() -> None:
    # No plain userInfo -- the description must be recovered from the NSKeyedArchiver blob.
    service = _make_failing_app_service({
        "code": 9022,
        "domain": "com.apple.dt.CoreDeviceError",
        "userInfoWithNSSecureCoding": _MIC_IN_USE_ARCHIVE,
    })
    with pytest.raises(CoreDeviceError) as exc_info:
        await service.invoke("com.apple.coredevice.feature.listapps")
    assert exc_info.value.localized_description == "The device microphone or camera is currently in use."


@pytest.mark.asyncio
async def test_invoke_unstructured_error_falls_back_to_raw_dump() -> None:
    service = _make_failing_app_service({})  # error present but empty
    with pytest.raises(CoreDeviceError) as exc_info:
        await service.invoke("com.apple.coredevice.feature.listapps")
    assert exc_info.value.code is None
