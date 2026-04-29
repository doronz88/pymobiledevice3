from __future__ import annotations

from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command

cli = InjectingTyper(
    name="screen-mirror",
    help="Mirror the device screen to a browser (30-60 fps over USB, ~4 fps fallback).",
)


@cli.command("screen-mirror")
@async_command
async def screen_mirror(
    service_provider: ServiceProviderDep,
    host: Annotated[str, typer.Option(help="Bind address (use 0.0.0.0 to expose on the LAN).")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="HTTP port for the browser viewer.")] = 8080,
    fps: Annotated[float, typer.Option(help="Frame-rate cap (AVFoundation delivers up to 60 fps).")] = 60.0,
    jpeg_quality: Annotated[int, typer.Option(help="JPEG quality 1-100 (higher = sharper, more bandwidth).")] = 60,
    backend: Annotated[str, typer.Option(
        help="Force a specific capture backend. "
             "auto = pick by platform (cmio on macOS, libusb elsewhere). "
             "One of: auto, cmio, libusb."
    )] = "auto",
    redact: Annotated[bool, typer.Option(
        "--redact",
        help="Scrub hostname, UDIDs, AVFoundation UUIDs, and user-set device "
             "names from log output so the log is safe to share publicly. "
             "Default: full-detail logs (best for local debugging).",
    )] = False,
) -> None:
    """
    Mirror the device screen to a browser via the unified Valeria capture
    service (CoreMediaIO on macOS, libusb on Linux/Windows).

    \b
    Prerequisites
    * Device paired and trusted
    * macOS: Screen Recording TCC granted to your terminal app
    * pip install pymobiledevice3[screen-mirror]
    """
    from pymobiledevice3.services.screen_mirror import ScreenMirrorService, install_pii_log_filter

    if redact:
        install_pii_log_filter()

    async with ScreenMirrorService(
        service_provider,
        host=host,
        port=port,
        fps_cap=fps,
        jpeg_quality=jpeg_quality,
        backend=backend,
    ) as svc:
        await svc.serve()
