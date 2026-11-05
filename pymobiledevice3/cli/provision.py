import logging
from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.safe_paths import device_file_path
from pymobiledevice3.services.misagent import MisagentService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="provision",
    help="Install, list, export and remove provisioning profiles (.mobileprovision).",
    no_args_is_help=True,
)


@cli.command("install")
@async_command
async def provision_install(
    service_provider: ServiceProviderDep,
    profile: Annotated[Path, typer.Argument(help="Provisioning profile file (.mobileprovision).")],
) -> None:
    """Install a provisioning profile on the device."""
    with profile.open("rb") as profile_file:
        await MisagentService(lockdown=service_provider).install(profile_file)


@cli.command("remove")
@async_command
async def provision_remove(
    service_provider: ServiceProviderDep,
    profile_id: Annotated[str, typer.Argument(help="UUID of the profile to remove (see `provision list`).")],
) -> None:
    """Remove an installed provisioning profile."""
    await MisagentService(lockdown=service_provider).remove(profile_id)


@cli.command("clear")
@async_command
async def provision_clear(service_provider: ServiceProviderDep) -> None:
    """Remove every installed provisioning profile (no confirmation)."""
    for profile in await MisagentService(lockdown=service_provider).copy_all():
        await MisagentService(lockdown=service_provider).remove(profile.plist["UUID"])


@cli.command("list")
@async_command
async def provision_list(service_provider: ServiceProviderDep) -> None:
    """Print the installed provisioning profiles (UUID, name, expiration, ...)."""
    print_json([p.plist for p in await MisagentService(lockdown=service_provider).copy_all()])


@cli.command("dump")
@async_command
async def provision_dump(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(
            file_okay=False, dir_okay=True, exists=True, help="Existing directory to save the profiles into."
        ),
    ],
) -> None:
    """Save every installed provisioning profile as OUT/<UUID>.mobileprovision."""
    for profile in await MisagentService(lockdown=service_provider).copy_all():
        path = device_file_path(Path(out), profile.plist["UUID"], ".mobileprovision")
        logger.info(f"downloading {path.name}")
        path.write_bytes(profile.buf)
