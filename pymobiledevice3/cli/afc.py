from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep
from pymobiledevice3.services.afc import AfcService, AfcShell

cli = InjectingTyper(
    name="afc",
    help="Manage device multimedia files",
    no_args_is_help=True,
)


@cli.command("shell")
def afc_shell(service_provider: ServiceProviderDep) -> None:
    """open an AFC shell rooted at /var/mobile/Media"""
    AfcShell.create(service_provider)


@cli.command("pull")
def afc_pull(
    service_provider: ServiceProviderDep,
    remote_file: Path,
    local_file: Path,
    ignore_errors: Annotated[
        bool,
        typer.Option(
            "--ignore-errors",
            "-i",
            help="Ignore AFC pull errors",
        ),
    ],
) -> None:
    """pull remote file from /var/mobile/Media"""
    AfcService(lockdown=service_provider).pull(str(remote_file), str(local_file), ignore_errors=ignore_errors)


@cli.command("push")
def afc_push(service_provider: ServiceProviderDep, local_file: Path, remote_file: Path) -> None:
    """push local file into /var/mobile/Media"""
    AfcService(lockdown=service_provider).push(str(local_file), str(remote_file))


@cli.command("ls")
def afc_ls(
    service_provider: ServiceProviderDep,
    remote_file: Path,
    recursive: Annotated[
        bool,
        typer.Option("--recursive", "-r"),
    ] = False,
) -> None:
    """perform a dirlist rooted at /var/mobile/Media"""
    for path in AfcService(lockdown=service_provider).dirlist(str(remote_file), -1 if recursive else 1):
        print(path)


@cli.command("rm")
def afc_rm(service_provider: ServiceProviderDep, remote_file: Path) -> None:
    """remove a file rooted at /var/mobile/Media"""
    AfcService(lockdown=service_provider).rm(str(remote_file))
