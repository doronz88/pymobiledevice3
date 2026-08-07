import asyncio
from collections import deque
from typing import Any, cast

import pytest

from pymobiledevice3.remote.core_device.app_service import FEATURE_LISTAPPS, FEATURE_STREAMAPPLIST, AppServiceService
from pymobiledevice3.remote.core_device.core_device_service import (
    STREAM_ELEMENTS_KEY,
    STREAM_FINISH_KEY,
    STREAM_INPUT_KEY,
    STREAM_PROXY_KEY,
    STREAM_PUSHING_KEY,
    STREAM_STATUS_KEY,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

APPS = [{"bundleIdentifier": "com.apple.Preferences"}, {"bundleIdentifier": "com.apple.mobilesafari"}]

EXPECTED_INPUT_KEYS = {
    "includeAppClips",
    "includeRemovableApps",
    "includeHiddenApps",
    "includeInternalApps",
    "includeDefaultApps",
    "requireContainerAccess",
    "includeAppGroupIdentifiers",
    "includeContainerPaths",
}


class FakeConnection:
    """Answers a plain invoke directly and a streaming invoke with pushed batches."""

    def __init__(self) -> None:
        self._request_lock = asyncio.Lock()
        self.sent: list[dict[str, Any]] = []
        self._stream_responses: deque[dict[str, Any]] = deque([
            {STREAM_STATUS_KEY: {STREAM_PUSHING_KEY: {STREAM_ELEMENTS_KEY: APPS}}},
            {STREAM_STATUS_KEY: {STREAM_FINISH_KEY: {}}},
        ])

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(request)
        return {"CoreDevice.output": APPS}

    async def send_request(self, request: dict[str, Any], wanting_reply: bool = False) -> None:
        self.sent.append(request)

    async def receive_response(self) -> dict[str, Any]:
        return self._stream_responses.popleft()


def make_app_service(features: list[str]) -> tuple[AppServiceService, FakeConnection]:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {
        "Properties": {"OSVersion": "26.0"},
        "Services": {AppServiceService.SERVICE_NAME: {"Port": "1024", "Properties": {"Features": features}}},
    }
    rsd.udid = "udid"
    service = AppServiceService(rsd)
    connection = FakeConnection()
    service._service = cast(RemoteXPCConnection, connection)
    return service, connection


@pytest.mark.asyncio
async def test_list_apps_uses_the_plain_feature_when_streaming_is_not_advertised() -> None:
    service, connection = make_app_service([FEATURE_LISTAPPS])

    assert await service.list_apps() == APPS

    (request,) = connection.sent
    assert request["CoreDevice.featureIdentifier"] == FEATURE_LISTAPPS
    assert set(request["CoreDevice.input"]) == EXPECTED_INPUT_KEYS


@pytest.mark.asyncio
async def test_list_apps_prefers_the_advertised_streaming_variant() -> None:
    # DDIs that advertise streamapplist never reply to a well-formed non-streaming listapps
    # request, so the same call must transparently collect from the streamed variant instead.
    service, connection = make_app_service([FEATURE_LISTAPPS, FEATURE_STREAMAPPLIST])

    assert await service.list_apps() == APPS

    (request,) = connection.sent
    assert request["CoreDevice.featureIdentifier"] == FEATURE_STREAMAPPLIST
    assert set(request["CoreDevice.input"][STREAM_INPUT_KEY]) == EXPECTED_INPUT_KEYS
    assert STREAM_PROXY_KEY in request["CoreDevice.input"]


@pytest.mark.asyncio
async def test_list_apps_forwards_filters_to_the_streamed_variant() -> None:
    service, connection = make_app_service([FEATURE_LISTAPPS, FEATURE_STREAMAPPLIST])

    await service.list_apps(include_default_apps=False, require_container_access=True)

    (request,) = connection.sent
    actual_input = request["CoreDevice.input"][STREAM_INPUT_KEY]
    assert actual_input["includeDefaultApps"] is False
    assert actual_input["requireContainerAccess"] is True
