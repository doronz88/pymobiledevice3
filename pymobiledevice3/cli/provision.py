import logging
from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.misagent import MisagentService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="provision",
    help="Manage installed provision profiles",
    no_args_is_help=True,
)


@cli.command("install")
@async_command
async def provision_install(service_provider: ServiceProviderDep, profile: Path) -> None:
    """install a provision profile (.mobileprovision file)"""
    with profile.open("rb") as profile_file:
        await MisagentService(lockdown=service_provider).install(profile_file)


@cli.command("remove")
@async_command
async def provision_remove(service_provider: ServiceProviderDep, profile_id: str) -> None:
    """remove a provision profile"""
    await MisagentService(lockdown=service_provider).remove(profile_id)


@cli.command("clear")
@async_command
async def provision_clear(service_provider: ServiceProviderDep) -> None:
    """remove all provision profiles"""
    for profile in await MisagentService(lockdown=service_provider).copy_all():
        await MisagentService(lockdown=service_provider).remove(profile.plist["UUID"])


@cli.command("list")
@async_command
async def provision_list(service_provider: ServiceProviderDep) -> None:
    """list installed provision profiles"""
    print_json([p.plist for p in await MisagentService(lockdown=service_provider).copy_all()])


@cli.command("dump")
@async_command
async def provision_dump(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(file_okay=False, dir_okay=True, exists=True),
    ],
) -> None:
    """dump installed provision profiles to specified location"""
    for profile in await MisagentService(lockdown=service_provider).copy_all():
        filename = f"{profile.plist['UUID']}.mobileprovision"
        logger.info(f"downloading {filename}")
        (Path(out) / filename).write_bytes(profile.buf)
