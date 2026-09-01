from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import NotMountedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService


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
