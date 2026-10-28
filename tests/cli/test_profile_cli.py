import json
import stat
import sys
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

from pymobiledevice3.cli import profile as profile_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.mobile_config import WallpaperScreen

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())
TOKEN = b"\x01unlock-token\x02"


class _FakeMobileConfigService:
    calls: ClassVar[list[tuple[str, Any]]] = []

    def __init__(self, lockdown: Any) -> None:
        pass

    async def __aenter__(self) -> "_FakeMobileConfigService":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    async def escalate(self, keybag_file: Path) -> None:
        self.calls.append(("escalate", keybag_file))

    async def request_unlock_token(self) -> bytes:
        self.calls.append(("request_unlock_token", None))
        return TOKEN

    async def clear_passcode(self, unlock_token: bytes) -> None:
        self.calls.append(("clear_passcode", unlock_token))

    async def clear_restrictions_password(self) -> None:
        self.calls.append(("clear_restrictions_password", None))

    async def get_security_info(self) -> dict[str, Any]:
        self.calls.append(("get_security_info", None))
        return {"PasscodePresent": False}

    async def set_wallpaper(self, image: bytes, screen: WallpaperScreen) -> None:
        self.calls.append(("set_wallpaper", (image, screen)))


@pytest.fixture(autouse=True)
def _fake_service(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeMobileConfigService.calls = []
    monkeypatch.setattr(profile_module, "MobileConfigService", _FakeMobileConfigService)


def test_request_unlock_token_escalates_and_writes_a_private_file(tmp_path: Path) -> None:
    keybag = tmp_path / "keybag"
    output = tmp_path / "token"

    profile_module.profile_request_unlock_token(_FAKE_SERVICE_PROVIDER, keybag, output)

    assert _FakeMobileConfigService.calls == [("escalate", keybag), ("request_unlock_token", None)]
    assert output.read_bytes() == TOKEN
    if sys.platform != "win32":  # Windows has no POSIX permission bits
        assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_clear_passcode_escalates_and_sends_the_saved_token(tmp_path: Path) -> None:
    keybag = tmp_path / "keybag"
    token = tmp_path / "token"
    token.write_bytes(TOKEN)

    profile_module.profile_clear_passcode(_FAKE_SERVICE_PROVIDER, keybag, token)

    assert _FakeMobileConfigService.calls == [("escalate", keybag), ("clear_passcode", TOKEN)]


def test_clear_restrictions_password_escalates(tmp_path: Path) -> None:
    keybag = tmp_path / "keybag"

    profile_module.profile_clear_restrictions_password(_FAKE_SERVICE_PROVIDER, keybag)

    assert _FakeMobileConfigService.calls == [("escalate", keybag), ("clear_restrictions_password", None)]


def test_security_info_escalates_and_prints_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    keybag = tmp_path / "keybag"

    profile_module.profile_security_info(_FAKE_SERVICE_PROVIDER, keybag)

    assert _FakeMobileConfigService.calls == [("escalate", keybag), ("get_security_info", None)]
    assert json.loads(capsys.readouterr().out) == {"PasscodePresent": False}


def test_set_wallpaper_escalates_and_sends_the_image(tmp_path: Path) -> None:
    keybag = tmp_path / "keybag"
    image = tmp_path / "wallpaper.png"
    image.write_bytes(b"\x89PNG")

    profile_module.profile_set_wallpaper(_FAKE_SERVICE_PROVIDER, keybag, image, "lock")

    assert _FakeMobileConfigService.calls == [
        ("escalate", keybag),
        ("set_wallpaper", (b"\x89PNG", WallpaperScreen.LOCK)),
    ]
