import inspect
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pymobiledevice3.cli import springboard as cli
from pymobiledevice3.exceptions import ConnectionTerminatedError, WallpaperImageUnavailableError
from pymobiledevice3.services.springboard import SpringBoardServicesService


class _FakeConnection:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = responses
        self.requests: list[dict[str, Any]] = []
        self.closed = False

    async def send_recv_plist(self, request: dict[str, Any]) -> Any:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    async def close(self) -> None:
        self.closed = True


def _service(connection: _FakeConnection) -> SpringBoardServicesService:
    service = SpringBoardServicesService.__new__(SpringBoardServicesService)
    service._service = cast(Any, connection)
    service._connect_future = None
    return service


@pytest.mark.asyncio
async def test_get_wallpaper_pngdata() -> None:
    connection = _FakeConnection([{"pngData": b"png"}])
    assert await _service(connection).get_wallpaper_pngdata() == b"png"
    assert connection.requests == [{"command": "getHomeScreenWallpaperPNGData"}]


@pytest.mark.asyncio
async def test_get_wallpaper_pngdata_without_stored_image() -> None:
    # springboardservicesrelay disconnects instead of replying when the wallpaper has no stored image
    connection = _FakeConnection([ConnectionTerminatedError()])
    service = _service(connection)
    with pytest.raises(WallpaperImageUnavailableError):
        await service.get_wallpaper_pngdata()
    assert connection.closed
    assert service._service is None  # the next request reconnects


@pytest.mark.asyncio
async def test_cli_falls_back_to_preview(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    calls = []

    class _Service:
        def __init__(self, lockdown: Any) -> None:
            pass

        async def __aenter__(self) -> "_Service":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

        async def get_wallpaper_pngdata(self) -> bytes:
            raise WallpaperImageUnavailableError()

        async def get_wallpaper_preview_image(self, name: str) -> bytes:
            calls.append(name)
            return b"preview"

    monkeypatch.setattr(cli, "SpringBoardServicesService", _Service)
    out = tmp_path / "wallpaper.png"
    await inspect.unwrap(cli.springboard_wallpaper_home_screen)(cast(Any, SimpleNamespace()), out)
    assert calls == ["homescreen"]
    assert out.read_bytes() == b"preview"
