from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.exceptions import NotMountedError, RSDRequiredError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services import mobile_image_mounter
from pymobiledevice3.services.cryptexd import DDI_CRYPTEX_IDENTIFIER, CryptexdService, InstalledCryptex
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService, PersonalizedImageMounter


@pytest.mark.asyncio
async def test_is_image_mounted_agrees_with_copy_devices(lockdown: LockdownClient) -> None:
    # Regression: LookupImage may return an empty ImageSignature for a mounted Personalized image,
    # making is_image_mounted() miss it and a subsequent MountImage fail with "already mounted"
    async with MobileImageMounterService(lockdown=lockdown) as mounter:
        mounted_types = {device.get("DiskImageType") for device in await mounter.copy_devices()}
        for image_type in ("Developer", "Personalized"):
            assert await mounter.is_image_mounted(image_type) == (image_type in mounted_types)


class _LegacyConnection:
    """mobile_storage_proxy as seen on legacy iOS (observed on iOS 12.5.7): LookupImage works,
    but an unknown command such as CopyDevices is answered with UnknownCommand and the daemon
    then hangs up the connection."""

    def __init__(self) -> None:
        self.hung_up = False
        self.commands: list[str] = []

    async def send_recv_plist(self, data: dict[str, Any]) -> dict[str, Any]:
        if self.hung_up:
            raise ConnectionResetError("Connection lost")
        command = data["Command"]
        self.commands.append(command)
        if command == "LookupImage":
            return {"ImagePresent": False}
        self.hung_up = True
        return {"Error": "UnknownCommand"}

    async def close(self) -> None:
        pass


class _LegacyLockdown:
    def __init__(self) -> None:
        self.connections: list[_LegacyConnection] = []

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        connection = _LegacyConnection()
        self.connections.append(connection)
        return cast(ServiceConnection, connection)


@pytest.mark.asyncio
async def test_is_image_mounted_survives_copy_devices_hangup() -> None:
    # Regression: the CopyDevices fallback left the mounter on a connection the legacy daemon
    # had hung up on, so the next command (e.g. upload_image's ReceiveBytes) failed with
    # ConnectionResetError('Connection lost')
    lockdown = _LegacyLockdown()
    mounter = MobileImageMounterService(lockdown=cast(LockdownServiceProvider, lockdown))
    assert not await mounter.is_image_mounted("Developer")

    # the next command must not run on the hung-up connection
    with pytest.raises(NotMountedError):
        await mounter.lookup_image("Developer")

    # and further mounted-checks must not provoke the hangup again
    assert not await mounter.is_image_mounted("Developer")
    copy_devices_sent = [
        command for connection in lockdown.connections for command in connection.commands if command == "CopyDevices"
    ]
    assert len(copy_devices_sent) == 1


def _rsd(cryptexd_features: Optional[list[str]]) -> RemoteServiceDiscoveryService:
    """An RSD whose handshake offers cryptexd advertising *cryptexd_features*, or no cryptexd at all."""
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    services: dict[str, Any] = {}
    if cryptexd_features is not None:
        services[CryptexdService.SERVICE_NAME] = {"Port": "1024", "Properties": {"Features": cryptexd_features}}
    rsd.peer_info = {"Properties": {"OSVersion": "27.0"}, "Services": services}
    return rsd


@pytest.mark.parametrize(
    ("features", "expected"),
    [
        (["CryptexInstall", "ReadIdentifiers"], True),
        # no advertisement is not evidence of a missing capability; the device stays the authority
        ([], True),
        (["ReadIdentifiers"], False),
        (None, False),
    ],
)
def test_uses_cryptex_image_over_rsd(features: Optional[list[str]], expected: bool) -> None:
    assert mobile_image_mounter.uses_cryptex_image(_rsd(features)) is expected


def test_uses_cryptex_image_never_over_plain_lockdown() -> None:
    # cryptexd is only reachable over an RSD tunnel
    lockdown = cast(LockdownServiceProvider, SimpleNamespace(product_version="27.0"))
    assert not mobile_image_mounter.uses_cryptex_image(lockdown)


class _AutoMountCalls:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[str] = []

        async def raise_if_cannot_mount(mounter: Any) -> None:
            self.calls.append("precheck")

        async def auto_install_ddi(cryptexd: Any, restore_dir: Any = None) -> InstalledCryptex:
            self.calls.append("cryptex")
            return InstalledCryptex(DDI_CRYPTEX_IDENTIFIER, "1")

        async def mount(mounter: Any, *args: Any, **kwargs: Any) -> None:
            self.calls.append("personalized")

        async def close(mounter: Any) -> None: ...

        monkeypatch.setattr(PersonalizedImageMounter, "raise_if_cannot_mount", raise_if_cannot_mount)
        monkeypatch.setattr(PersonalizedImageMounter, "mount", mount)
        monkeypatch.setattr(PersonalizedImageMounter, "close", close)
        monkeypatch.setattr(CryptexdService, "auto_install_ddi", auto_install_ddi)
        monkeypatch.setattr(mobile_image_mounter, "fetch_personalized_ddi", lambda: (Path(), Path(), Path()))


@pytest.mark.asyncio
async def test_auto_mount_installs_the_cryptex_ddi_over_rsd(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _AutoMountCalls(monkeypatch)

    await mobile_image_mounter.auto_mount(_rsd(["CryptexInstall"]))

    # the mounter still gates on already-mounted and developer mode before cryptexd installs
    assert recorder.calls == ["precheck", "cryptex"]


@pytest.mark.asyncio
async def test_auto_mount_falls_back_to_the_personalized_ddi(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _AutoMountCalls(monkeypatch)

    await mobile_image_mounter.auto_mount(_rsd(["ReadIdentifiers"]))

    assert recorder.calls == ["personalized"]


UDID = "00008030-000215140A9A802E"


def _usb_lockdown(product_version: str) -> LockdownServiceProvider:
    """A plain-lockdown provider: only what auto_mount reads before choosing an image."""
    return cast(LockdownServiceProvider, SimpleNamespace(product_version=product_version, udid=UDID))


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["17.4", "26.0", "27.2"])
async def test_auto_mount_requires_rsd_where_the_cryptex_is_the_ddi(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    # From CRYPTEX_IMAGE_MIN_VERSION the cryptex is the DDI; over plain lockdown auto_mount asks for
    # RSD, which the CLI answers by retrying over a no-root tunnel.
    recorder = _AutoMountCalls(monkeypatch)

    with pytest.raises(RSDRequiredError) as exc_info:
        await mobile_image_mounter.auto_mount(_usb_lockdown(version))

    assert exc_info.value.product_version == version
    assert exc_info.value.identifier == UDID
    assert recorder.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["17.0", "17.3.1"])
async def test_auto_mount_keeps_the_personalized_ddi_over_usb_below_the_cutoff(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    # iOS 17.0-17.3.1 has no no-root tunnel on Linux/Windows, so requiring RSD would break it
    recorder = _AutoMountCalls(monkeypatch)

    await mobile_image_mounter.auto_mount(_usb_lockdown(version))

    assert recorder.calls == ["personalized"]
