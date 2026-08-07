import struct
from typing import Any, cast

import pytest

from pymobiledevice3.remote.core_device.icon_service import AppIcon, IconService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

SAMPLE_RESPONSE = {
    "appIconInfo": {
        "isAppIconPlaceholder": False,
        "pixelSize": [352.0, 352.0],
        "pngData": PNG_MAGIC + b"rest-of-png",
        "size": [176.0, 176.0],
        "scale": 2.0,
    }
}


def _service(response: dict[str, Any]) -> tuple[IconService, list[dict[str, Any]]]:
    """An IconService whose RemoteXPC connection records requests and replays *response*."""
    sent: list[dict[str, Any]] = []

    class FakeConnection:
        async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
            sent.append(request)
            return {"CoreDevice.output": response}

    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {
        "Properties": {"OSVersion": "26.0"},
        "Services": {
            IconService.SERVICE_NAME: {
                "Port": "1024",
                "Properties": {"Features": ["com.apple.coredevice.feature.fetchappicons"]},
            }
        },
    }
    service = IconService(rsd)
    service._service = cast(RemoteXPCConnection, FakeConnection())
    return service, sent


def test_service_name_is_iconservice() -> None:
    # Regression: fetchappicons used to be sent to com.apple.coredevice.appservice, which does
    # not advertise the feature and rejects the request.
    assert IconService.SERVICE_NAME == "com.apple.coredevice.iconservice"


@pytest.mark.asyncio
async def test_fetch_icon_parses_response() -> None:
    service, _ = _service(SAMPLE_RESPONSE)

    icon = await service.fetch_icon(bundle_identifier="com.apple.Preferences")

    assert icon == AppIcon(
        png_data=PNG_MAGIC + b"rest-of-png",
        pixel_size=(352.0, 352.0),
        size=(176.0, 176.0),
        scale=2.0,
        is_placeholder=False,
    )


@pytest.mark.asyncio
async def test_fetch_icon_sends_expected_input() -> None:
    service, sent = _service(SAMPLE_RESPONSE)

    await service.fetch_icon(bundle_identifier="com.apple.Preferences", width=176.0, height=176.0, scale=2.0)

    (request,) = sent
    assert request["CoreDevice.featureIdentifier"] == "com.apple.coredevice.feature.fetchappicons"
    assert request["CoreDevice.input"] == {
        "bundleIdentifier": "com.apple.Preferences",
        "appPath": None,
        "width": 176.0,
        "height": 176.0,
        "scale": 2.0,
        "allowPlaceholder": True,
    }


@pytest.mark.asyncio
async def test_fetch_icon_rounds_floats_to_float32() -> None:
    # FetchAppIconParams declares these as Swift Float; a Double that doesn't fit binary32 is
    # rejected by the daemon's decoder.
    service, sent = _service(SAMPLE_RESPONSE)

    await service.fetch_icon(bundle_identifier="com.apple.Preferences", width=0.1, height=0.1, scale=0.1)

    (request,) = sent
    for key in ("width", "height", "scale"):
        value = request["CoreDevice.input"][key]
        assert struct.unpack("<f", struct.pack("<f", value))[0] == value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"bundle_identifier": "com.apple.Preferences", "app_path": "/Applications/Preferences.app"},
    ],
)
async def test_fetch_icon_requires_exactly_one_specifier(kwargs: dict[str, Any]) -> None:
    service, _ = _service(SAMPLE_RESPONSE)

    with pytest.raises(ValueError):
        await service.fetch_icon(**kwargs)


@pytest.mark.asyncio
async def test_fetch_icon_from_device(service_provider) -> None:
    """Exercise the real service against a connected device."""
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("iconservice requires an RSD tunnel")

    async with IconService(service_provider) as icon_service:
        icon = await icon_service.fetch_icon(bundle_identifier="com.apple.Preferences", width=60.0, height=60.0)

    assert icon.png_data.startswith(PNG_MAGIC)
    assert not icon.is_placeholder
    assert icon.pixel_size[0] > 0 and icon.pixel_size[1] > 0
