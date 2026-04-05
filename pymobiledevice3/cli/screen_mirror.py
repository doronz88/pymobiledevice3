from __future__ import annotations

from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command

cli = InjectingTyper(
    name="screen-mirror",
    help="Mirror the device screen to a browser (30-60 fps over USB on macOS, ~4 fps fallback).",
)


@cli.command("screen-mirror")
@async_command
async def screen_mirror(
    service_provider: ServiceProviderDep,
    host: Annotated[str, typer.Option(help="Bind address (use 0.0.0.0 to expose on the LAN).")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="HTTP port for the browser viewer.")] = 8080,
    fps: Annotated[float, typer.Option(help="Frame-rate cap (AVFoundation delivers up to 60 fps).")] = 60.0,
    jpeg_quality: Annotated[int, typer.Option(help="JPEG quality 1-100 (higher = sharper, more bandwidth).")] = 60,
) -> None:
    """
    Mirror the device screen to a browser.

    On macOS over USB, uses the same CoreMediaIO/QuickTime capture mechanism
    as QuickTime Player — 30-60 fps.  The first run will prompt for Camera
    permission (granted to your terminal app).

    Over WiFi or on non-macOS, falls back to the accessibility daemon (~4 fps).

    \b
    Prerequisites
    * Device paired and trusted
    * pip install aiohttp
    * pip install pyobjc-framework-AVFoundation pyobjc-framework-CoreMediaIO
      pyobjc-framework-Quartz      (macOS 60 fps capture, optional)
    """
    from pymobiledevice3.services.screen_mirror import ScreenMirrorService

    async with ScreenMirrorService(
        service_provider,
        host=host,
        port=port,
        fps_cap=fps,
        jpeg_quality=jpeg_quality,
    ) as svc:
        await svc.serve()
