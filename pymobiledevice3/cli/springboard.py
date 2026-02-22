from pathlib import Path
from typing import Annotated, Literal

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.springboard import SpringBoardServicesService
from pymobiledevice3.utils import start_ipython_shell

SHELL_USAGE = """
Use `service` to access the service features
"""


cli = InjectingTyper(
    name="springboard",
    help="Interact with SpringBoard UI (icons, wallpapers, orientation, shell).",
    no_args_is_help=True,
)
state_cli = InjectingTyper(
    name="state",
    help="Icon state operations.",
    no_args_is_help=True,
)
cli.add_typer(state_cli)


@state_cli.command("get")
@async_command
async def state_get(service_provider: ServiceProviderDep) -> None:
    """Fetch the current icon layout/state."""
    print_json(await SpringBoardServicesService(lockdown=service_provider).get_icon_state())


@cli.command("shell")
def springboard_shell(service_provider: ServiceProviderDep) -> None:
    """Open an IPython shell bound to SpringBoardServicesService."""
    service = SpringBoardServicesService(lockdown=service_provider)
    start_ipython_shell(
        header=SHELL_USAGE,
        user_ns={
            "service": service,
        },
    )


@cli.command("icon")
@async_command
async def springboard_icon(service_provider: ServiceProviderDep, bundle_id: str, out: Path) -> None:
    """Save an app's icon PNG to the given path."""
    out.write_bytes(await SpringBoardServicesService(lockdown=service_provider).get_icon_pngdata(bundle_id))


@cli.command("orientation")
@async_command
async def springboard_orientation(service_provider: ServiceProviderDep) -> None:
    """Print current screen orientation."""
    print(await SpringBoardServicesService(lockdown=service_provider).get_interface_orientation())


@cli.command("wallpaper-home-screen")
@async_command
async def springboard_wallpaper_home_screen(service_provider: ServiceProviderDep, out: Path) -> None:
    """Save the homescreen wallpaper PNG to the given path."""
    out.write_bytes(await SpringBoardServicesService(lockdown=service_provider).get_wallpaper_pngdata())


@cli.command("wallpaper-preview-image")
@async_command
async def springboard_wallpaper_preview_image(
    service_provider: ServiceProviderDep,
    wallpaper_name: Literal["homescreen", "lockscreen"],
    out: Path,
    reload: Annotated[
        bool,
        typer.Option(
            "--reload",
            "-r",
            help="reload icon state before fetching image",
        ),
    ] = False,
) -> None:
    """Save the preview image for the homescreen or lockscreen wallpaper (optionally reload state first)."""
    async with SpringBoardServicesService(lockdown=service_provider) as springboard_service:
        if reload:
            await springboard_service.reload_icon_state()
        out.write_bytes(await springboard_service.get_wallpaper_preview_image(wallpaper_name))


@cli.command("homescreen-icon-metrics")
@async_command
async def springboard_homescreen_icon_metrics(service_provider: ServiceProviderDep) -> None:
    """Print homescreen icon spacing/metrics."""
    async with SpringBoardServicesService(lockdown=service_provider) as springboard_service:
        print_json(await springboard_service.get_homescreen_icon_metrics())
