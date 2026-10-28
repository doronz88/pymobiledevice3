from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, call

import pytest

from pymobiledevice3.ca import create_keybag_file
from pymobiledevice3.exceptions import PasscodeSetError, ProfileError
from pymobiledevice3.services.mobile_config import MobileConfigService, WallpaperScreen

ACK = {"Status": "Acknowledged"}
TOKEN = b"\x01secret-unlock-token\x02"
PASSCODE_SET_REPLY = {
    "Status": "Error",
    "ErrorChain": [
        {
            "ErrorDomain": "MCInstallationErrorDomain",
            "ErrorCode": 4001,
            "LocalizedDescription": "The unlock token could not be retrieved.",
        },
        {
            "ErrorDomain": "DMCKeybagErrorDomain",
            "ErrorCode": 37002,
            "LocalizedDescription": "A passcode is set.",
        },
    ],
}


def _service(replies: list[Any]) -> tuple[MobileConfigService, AsyncMock]:
    connection = AsyncMock()
    connection.send_recv_plist = AsyncMock(side_effect=replies)
    service = object.__new__(MobileConfigService)
    service._service = connection
    return service, connection


@pytest.mark.asyncio
async def test_request_unlock_token_returns_the_token() -> None:
    service, connection = _service([{**ACK, "UnlockToken": TOKEN}])

    assert await service.request_unlock_token() == TOKEN
    assert connection.send_recv_plist.await_args_list == [call({"RequestType": "RequestUnlockToken"})]


@pytest.mark.asyncio
async def test_request_unlock_token_with_a_passcode_set_raises_passcode_set_error() -> None:
    service, _ = _service([PASSCODE_SET_REPLY])

    with pytest.raises(PasscodeSetError):
        await service.request_unlock_token()


@pytest.mark.asyncio
async def test_request_unlock_token_without_a_token_raises() -> None:
    service, _ = _service([ACK])

    with pytest.raises(ProfileError, match="no UnlockToken"):
        await service.request_unlock_token()


@pytest.mark.asyncio
async def test_clear_passcode_sends_the_token() -> None:
    service, connection = _service([ACK])

    await service.clear_passcode(TOKEN)

    assert connection.send_recv_plist.await_args_list == [call({"RequestType": "ClearPasscode", "UnlockToken": TOKEN})]


@pytest.mark.asyncio
async def test_clear_passcode_rejection_does_not_leak_the_token() -> None:
    service, _ = _service([
        {
            "Status": "Error",
            "UnlockToken": TOKEN,
            "ErrorChain": [{"ErrorDomain": "MCKeybagErrorDomain", "ErrorCode": 1, "LocalizedDescription": "Bad"}],
        }
    ])

    with pytest.raises(ProfileError) as exc_info:
        await service.clear_passcode(TOKEN)

    message = str(exc_info.value)
    assert "MCKeybagErrorDomain(1): Bad" in message
    assert "secret-unlock-token" not in message
    assert repr(TOKEN) not in message


@pytest.mark.asyncio
async def test_clear_restrictions_password() -> None:
    service, connection = _service([ACK])

    await service.clear_restrictions_password()

    assert connection.send_recv_plist.await_args_list == [call({"RequestType": "ClearRestrictionsPassword"})]


@pytest.mark.asyncio
async def test_unescalated_request_raises_profile_error() -> None:
    service, _ = _service([{"Status": "CommandFormatError"}])

    with pytest.raises(ProfileError, match="CommandFormatError"):
        await service.clear_restrictions_password()


@pytest.mark.asyncio
async def test_get_security_info_returns_the_security_info_dict() -> None:
    info = {"PasscodePresent": True, "PasscodeCompliant": True, "HardwareEncryptionCaps": 3}
    service, connection = _service([{**ACK, "SecurityInfo": info}])

    assert await service.get_security_info() == info
    assert connection.send_recv_plist.await_args_list == [call({"RequestType": "SecurityInfo"})]


@pytest.mark.asyncio
async def test_get_security_info_without_the_dict_raises() -> None:
    service, _ = _service([ACK])

    with pytest.raises(ProfileError, match="no SecurityInfo"):
        await service.get_security_info()


@pytest.mark.asyncio
async def test_set_wallpaper_sends_the_settings_item() -> None:
    service, connection = _service([{**ACK, "Settings": [{"Item": "Wallpaper", "Status": "Acknowledged"}]}])

    await service.set_wallpaper(b"\x89PNG", WallpaperScreen.BOTH)

    assert connection.send_recv_plist.await_args_list == [
        call({"RequestType": "Settings", "Settings": [{"Item": "Wallpaper", "Where": 3, "Image": b"\x89PNG"}]})
    ]


@pytest.mark.asyncio
async def test_set_wallpaper_defaults_to_the_home_screen() -> None:
    service, connection = _service([{**ACK, "Settings": [{"Status": "Acknowledged"}]}])

    await service.set_wallpaper(b"img")

    assert connection.send_recv_plist.await_args_list[0].args[0]["Settings"][0]["Where"] == 2


@pytest.mark.asyncio
async def test_set_wallpaper_rejected_item_raises() -> None:
    service, _ = _service([{**ACK, "Settings": [{"Item": "Wallpaper", "Status": "Error"}]}])

    with pytest.raises(ProfileError, match="rejected the wallpaper"):
        await service.set_wallpaper(b"img")


@pytest.mark.asyncio
async def test_set_wallpaper_without_item_status_raises() -> None:
    service, _ = _service([ACK])

    with pytest.raises(ProfileError, match="no item status"):
        await service.set_wallpaper(b"img")


@pytest.mark.asyncio
async def test_supervise_skips_the_newer_setup_panes(tmp_path: Path) -> None:
    keybag = tmp_path / "keybag"
    create_keybag_file(keybag, "org")
    service, connection = _service([ACK])

    await service.supervise("org", keybag)

    skip_setup = connection.send_recv_plist.await_args_list[0].args[0]["CloudConfiguration"]["SkipSetup"]
    assert {"AgeAssurance", "DeviceFeaturesTour", "OSShowcase"} <= set(skip_setup)
    assert len(skip_setup) == len(set(skip_setup))
