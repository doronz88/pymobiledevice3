from typing import Any, Optional, cast

import pytest

from pymobiledevice3.exceptions import (
    ConnectionTerminatedError,
    DeveloperDiskImageServiceError,
    InvalidServiceError,
)
from pymobiledevice3.remote import ddi_services, remote_service
from pymobiledevice3.remote.remote_service import RemoteService, require_service
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.mobile_image_mounter import LATEST_DDI_BUILD_ID

SCREEN_CAPTURE = "com.apple.coredevice.screencaptureservice"


class FakeRsd:
    udid = "00008030-000215140A9A802E"
    product_version = "27.2.1"

    def get_service_port(self, name: str) -> int:
        raise InvalidServiceError(f"The device does not offer the {name} service.", self.udid, self.product_version)

    def start_remote_service(self, name: str) -> Any:
        self.get_service_port(name)


def _mounted_images(monkeypatch: pytest.MonkeyPatch, images: list[dict[str, Any]]) -> None:
    class FakeMounter:
        def __init__(self, lockdown: Any) -> None:
            pass

        async def __aenter__(self) -> "FakeMounter":
            return self

        async def __aexit__(self, *_: Any) -> None:
            pass

        async def copy_devices(self) -> list[dict[str, Any]]:
            return images

    monkeypatch.setattr(remote_service, "PersonalizedImageMounter", FakeMounter)


def _ddi(build: Optional[str]) -> dict[str, Any]:
    image: dict[str, Any] = {"DiskImageType": "Personalized", "MountPath": "/System/Developer"}
    if build is not None:
        image["PersonalizedImageVersionInfo"] = {"ProductBuildVersion": build}
    return image


async def _connect(name: str = SCREEN_CAPTURE) -> None:
    await RemoteService(cast(RemoteServiceDiscoveryService, FakeRsd()), name).connect()


@pytest.mark.asyncio
async def test_a_missing_ddi_service_says_no_ddi_is_mounted(monkeypatch: pytest.MonkeyPatch) -> None:
    _mounted_images(monkeypatch, [])

    with pytest.raises(DeveloperDiskImageServiceError) as e:
        await _connect()

    assert e.value.mounted_build is None
    assert SCREEN_CAPTURE in str(e.value)
    assert "none is mounted" in str(e.value)
    assert "mounter auto-mount" in str(e.value)


@pytest.mark.asyncio
async def test_a_missing_ddi_service_names_the_mounted_ddi_that_lacks_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # Issue #2197: an Xcode 26 DDI mounted on iOS 27 has no dtscreencaptured/dtuhidd, and the CLI
    # answered with a generic checklist that sent the user to `auto-mount` ("already mounted").
    _mounted_images(monkeypatch, [_ddi("17E5179g")])

    with pytest.raises(DeveloperDiskImageServiceError) as e:
        await _connect()

    assert e.value.mounted_build == "17E5179g"
    assert e.value.mounted_includes_service is False
    assert e.value.first_build == "27A5194q"
    assert e.value.last_build is None
    assert "(17E5179g) does not include it: DeveloperDiskImages include this service from 27A5194q on" in str(e.value)
    assert LATEST_DDI_BUILD_ID in str(e.value)
    assert "cryptex uninstall com.apple.MobileAsset.DDI" in str(e.value)
    assert "mounter umount-personalized" in str(e.value)


@pytest.mark.asyncio
async def test_a_missing_ddi_service_with_the_expected_ddi_does_not_blame_its_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mounted_images(monkeypatch, [_ddi(LATEST_DDI_BUILD_ID)])

    with pytest.raises(DeveloperDiskImageServiceError) as e:
        await _connect()

    assert e.value.mounted_includes_service is True
    assert f"({LATEST_DDI_BUILD_ID}) includes it" in str(e.value)


@pytest.mark.asyncio
async def test_a_mounted_ddi_of_a_build_the_table_does_not_know_is_not_accused(monkeypatch: pytest.MonkeyPatch) -> None:
    # Newer than the last DDI known to lack the service, older than the first known to have it
    _mounted_images(monkeypatch, [_ddi("17F100")])

    with pytest.raises(DeveloperDiskImageServiceError) as e:
        await _connect()

    assert e.value.mounted_includes_service is None
    assert "(17F100) may not include it" in str(e.value)


@pytest.mark.asyncio
async def test_a_service_older_than_the_mounted_ddi_is_not_blamed_on_its_build(monkeypatch: pytest.MonkeyPatch) -> None:
    _mounted_images(monkeypatch, [_ddi("17E5179g")])

    with pytest.raises(DeveloperDiskImageServiceError) as e:
        await _connect("com.apple.coredevice.appservice")

    assert e.value.mounted_includes_service is True


@pytest.mark.asyncio
async def test_a_service_the_latest_ddi_dropped_is_not_fixed_by_mounting_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # No DDI has dropped a service so far, but nothing stops a future one
    dropped = "com.apple.coredevice.dropped"
    monkeypatch.setitem(ddi_services.DDI_SERVICES, dropped, ("16B40", "17E5179g"))
    _mounted_images(monkeypatch, [_ddi(LATEST_DDI_BUILD_ID)])

    with pytest.raises(DeveloperDiskImageServiceError) as e:
        await _connect(dropped)

    assert (e.value.first_build, e.value.last_build) == ("16B40", "17E5179g")
    assert "from 16B40 to 17E5179g only" in str(e.value)
    assert "auto-mount" not in str(e.value)


@pytest.mark.asyncio
async def test_a_mounted_ddi_of_unknown_build_is_still_reported_as_mounted(monkeypatch: pytest.MonkeyPatch) -> None:
    _mounted_images(monkeypatch, [_ddi(None)])

    with pytest.raises(DeveloperDiskImageServiceError) as e:
        await _connect()

    assert e.value.mounted_build == ""
    assert "none is mounted" not in str(e.value)
    assert "(of an unknown build) may not include it" in str(e.value)


@pytest.mark.asyncio
async def test_a_missing_ddi_service_is_still_an_invalid_service_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _mounted_images(monkeypatch, [])

    with pytest.raises(InvalidServiceError) as e:
        await _connect()

    assert e.value.identifier == FakeRsd.udid
    assert e.value.product_version == FakeRsd.product_version


@pytest.mark.asyncio
async def test_a_missing_service_the_ddi_does_not_provide_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    _mounted_images(monkeypatch, [])

    with pytest.raises(InvalidServiceError) as e:
        await _connect("com.apple.security.cryptexd.remote")

    assert not isinstance(e.value, DeveloperDiskImageServiceError)


@pytest.mark.asyncio
async def test_a_failed_ddi_lookup_keeps_the_original_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenMounter:
        def __init__(self, lockdown: Any) -> None:
            pass

        async def __aenter__(self) -> "BrokenMounter":
            raise ConnectionTerminatedError()

        async def __aexit__(self, *_: Any) -> None:
            pass

    monkeypatch.setattr(remote_service, "PersonalizedImageMounter", BrokenMounter)

    with pytest.raises(InvalidServiceError) as e:
        await _connect()

    assert not isinstance(e.value, DeveloperDiskImageServiceError)


@pytest.mark.asyncio
async def test_require_service_explains_a_missing_ddi_service_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mounted_images(monkeypatch, [])

    with pytest.raises(DeveloperDiskImageServiceError, match="none is mounted"):
        await require_service(cast(RemoteServiceDiscoveryService, FakeRsd()), SCREEN_CAPTURE)


@pytest.mark.asyncio
async def test_require_service_passes_a_service_the_device_offers() -> None:
    class OfferingRsd(FakeRsd):
        def get_service_port(self, name: str) -> int:
            return 1024

    await require_service(cast(RemoteServiceDiscoveryService, OfferingRsd()), SCREEN_CAPTURE)
