import logging
from pathlib import Path
from typing import Annotated, Literal

import typer
from tqdm import tqdm
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="backup2",
    help="Create, inspect, and restore MobileBackup2 backups.",
    no_args_is_help=True,
)


SourceOption = Annotated[
    str,
    typer.Option(help="The UDID of the source device."),
]
PasswordOption = Annotated[
    str,
    typer.Option(
        "--password",
        "-p",
        help="Backup password.",
    ),
]
BackupDirectoryArg = Annotated[
    Path,
    typer.Argument(
        exists=True,
        file_okay=False,
    ),
]
BackupDirectoryOption = Annotated[
    Path,
    typer.Option(
        "--backup-directory",
        "-b",
        exists=True,
        file_okay=False,
    ),
]


@cli.command()
@async_command
async def backup(
    service_provider: ServiceProviderDep,
    backup_directory: BackupDirectoryArg,
    full: Annotated[
        bool,
        typer.Option(
            help="Whether to do a full backup. If full is True, any previous backup attempts will be discarded.",
        ),
    ] = False,
) -> None:
    """
    Backup device.

    All backup data will be written to BACKUP_DIRECTORY, under a directory named with the device's udid.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        with tqdm(total=100, dynamic_ncols=True) as pbar:

            def update_bar(percentage) -> None:
                pbar.n = percentage
                pbar.refresh()

            await backup_client.backup(full=full, backup_directory=str(backup_directory), progress_callback=update_bar)


@cli.command()
@async_command
async def restore(
    service_provider: ServiceProviderDep,
    backup_directory: BackupDirectoryArg,
    system: Annotated[
        bool,
        typer.Option(help="Restore system files."),
    ] = False,
    reboot: Annotated[
        bool,
        typer.Option(help="Reboot the device when done."),
    ] = True,
    copy: Annotated[
        bool,
        typer.Option(help="Create a copy of backup folder before restoring."),
    ] = False,
    settings: Annotated[
        bool,
        typer.Option(help="Restore device settings."),
    ] = True,
    remove: Annotated[
        bool,
        typer.Option(help="Remove items which aren't being restored."),
    ] = False,
    skip_apps: Annotated[
        bool,
        typer.Option(help="Do not trigger re-installation of apps after restore."),
    ] = False,
    password: PasswordOption = "",
    source: SourceOption = "",
) -> None:
    """
    Restore a backup to a device.

    The backup will be restored from a directory with the device udid under BACKUP_DIRECTORY.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        with tqdm(total=100, dynamic_ncols=True) as pbar:

            def update_bar(percentage) -> None:
                pbar.n = percentage
                pbar.refresh()

            await backup_client.restore(
                backup_directory=str(backup_directory),
                progress_callback=update_bar,
                system=system,
                reboot=reboot,
                copy=copy,
                settings=settings,
                remove=remove,
                password=password,
                source=source,
                skip_apps=skip_apps,
            )


@cli.command()
@async_command
async def info(
    service_provider: ServiceProviderDep, backup_directory: BackupDirectoryArg, source: SourceOption = ""
) -> None:
    """
    Print information about a backup.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        print(await backup_client.info(backup_directory=str(backup_directory), source=source))


@cli.command("list")
@async_command
async def list_(
    service_provider: ServiceProviderDep, backup_directory: BackupDirectoryArg, source: SourceOption = ""
) -> None:
    """
    List all file in the backup in a CSV format.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        print(await backup_client.list(backup_directory=str(backup_directory), source=source))


@cli.command()
@async_command
async def unback(
    service_provider: ServiceProviderDep,
    backup_directory: BackupDirectoryArg,
    password: PasswordOption = "",
    source: SourceOption = "",
) -> None:
    """
    Convert all files in the backup to the correct directory hierarchy.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        await backup_client.unback(backup_directory=str(backup_directory), password=password, source=source)


@cli.command()
@async_command
async def extract(
    service_provider: ServiceProviderDep,
    domain_name: str,
    relative_path: str,
    backup_directory: BackupDirectoryArg,
    password: PasswordOption = "",
    source: SourceOption = "",
) -> None:
    """
    Extract a file from the backup.

    The file that belongs to the domain DOMAIN_NAME and located on the device in the path RELATIVE_PATH,
    will be extracted to the BACKUP_DIRECTORY.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        await backup_client.extract(
            domain_name, relative_path, backup_directory=str(backup_directory), password=password, source=source
        )


@cli.command()
@async_command
async def encryption(
    service_provider: ServiceProviderDep,
    *,
    backup_directory: BackupDirectoryOption = Path("."),
    mode: Annotated[
        Literal["on", "off"],
        typer.Argument(case_sensitive=False),
    ],
    password: str,
) -> None:
    """
    Set backup encryption on / off.

    When on, PASSWORD will be the new backup password.
    When off, PASSWORD is the current backup password.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        should_encrypt = mode.lower() == "on"
        if should_encrypt == backup_client.will_encrypt:
            logger.error("Encryption already " + ("on!" if should_encrypt else "off!"))
            return
        if should_encrypt:
            await backup_client.change_password(str(backup_directory), new=password)
        else:
            await backup_client.change_password(str(backup_directory), old=password)


@cli.command()
@async_command
async def change_password(
    service_provider: ServiceProviderDep,
    old_password: str,
    new_password: str,
    backup_directory: BackupDirectoryOption = Path("."),
) -> None:
    """
    Change the backup password.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        if not backup_client.will_encrypt:
            logger.error("Encryption is not turned on!")
            return
        await backup_client.change_password(str(backup_directory), old=old_password, new=new_password)


@cli.command()
@async_command
async def erase_device(service_provider: ServiceProviderDep, backup_directory: BackupDirectoryArg) -> None:
    """
    Erase all data on the device.
    """
    async with Mobilebackup2Service(service_provider) as backup_client:
        await backup_client.erase_device(str(backup_directory))
