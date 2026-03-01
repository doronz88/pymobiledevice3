from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.services.afc import AfcService, AfcShell

cli = InjectingTyper(
    name="afc",
    help="Browse, push, and pull files via the AFC service (/var/mobile/Media).",
    no_args_is_help=True,
)


@cli.command("shell")
def afc_shell(service_provider: ServiceProviderDep) -> None:
    """Open an interactive AFC shell rooted at /var/mobile/Media."""
    AfcShell.create(service_provider)


@cli.command("pull")
@async_command
async def afc_pull(
    service_provider: ServiceProviderDep,
    remote_file: Path,
    local_file: Path,
    ignore_errors: Annotated[
        bool,
        typer.Option(
            "--ignore-errors",
            "-i",
            help="Continue downloading even if some files error (best-effort pull).",
        ),
    ],
) -> None:
    """Download a remote path under /var/mobile/Media to the local filesystem."""
    async with AfcService(lockdown=service_provider) as afc:
        await afc.pull(str(remote_file), str(local_file), ignore_errors=ignore_errors)


@cli.command("push")
@async_command
async def afc_push(service_provider: ServiceProviderDep, local_file: Path, remote_file: Path) -> None:
    """Upload a local file into /var/mobile/Media."""
    async with AfcService(lockdown=service_provider) as afc:
        await afc.push(str(local_file), str(remote_file))


@cli.command("ls")
@async_command
async def afc_ls(
    service_provider: ServiceProviderDep,
    remote_file: Path,
    recursive: Annotated[
        bool,
        typer.Option("--recursive", "-r", help="Recurse into subdirectories when listing."),
    ] = False,
) -> None:
    """List files under /var/mobile/Media (optionally recursively)."""
    async with AfcService(lockdown=service_provider) as afc:
        async for path in afc.dirlist(str(remote_file), -1 if recursive else 1):
            print(path)


@cli.command("rm")
@async_command
async def afc_rm(service_provider: ServiceProviderDep, remote_file: Path) -> None:
    """Delete a file under /var/mobile/Media."""
    async with AfcService(lockdown=service_provider) as afc:
        await afc.rm(str(remote_file))
