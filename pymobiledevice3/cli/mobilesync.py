import json
import plistlib
from pathlib import Path
from typing import Annotated, Literal

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.mobilesync import MobileSyncService

cli = InjectingTyper(
    name="mobilesync",
    help="Read and change contacts, calendars, Safari bookmarks and mail accounts (com.apple.mobilesync)",
    no_args_is_help=True,
)

DataClass = Literal["contacts", "calendars", "bookmarks", "mail-accounts"]

DATA_CLASSES = {
    "contacts": "com.apple.Contacts",
    "calendars": "com.apple.Calendars",
    "bookmarks": "com.apple.Bookmarks",
    "mail-accounts": "com.apple.MailAccounts",
}


@cli.callback()
def callback() -> None:
    # Force subgroup
    pass


@cli.command("dump")
@async_command
async def mobilesync_dump(
    service_provider: ServiceProviderDep,
    data_class: Annotated[DataClass, typer.Argument()],
) -> None:
    """Print every record of a data class, keyed by record identifier."""
    async with MobileSyncService(service_provider) as sync:
        print_json(await sync.get_all_records(DATA_CLASSES[data_class]))


@cli.command("push")
@async_command
async def mobilesync_push(
    service_provider: ServiceProviderDep,
    data_class: Annotated[DataClass, typer.Argument()],
    changes: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """
    Add or modify records from a JSON or plist file, keyed by record identifier.

    A key that is an existing record identifier (as printed by `dump`) modifies that record; any other key adds
    a new record. Use a plist for records with dates (calendar events). Prints the identifiers the device
    assigned to added records.
    """
    data = plistlib.loads(changes.read_bytes()) if changes.suffix == ".plist" else json.loads(changes.read_text())
    async with MobileSyncService(service_provider) as sync:
        print_json(await sync.push_changes(DATA_CLASSES[data_class], data))


@cli.command("delete")
@async_command
async def mobilesync_delete(
    service_provider: ServiceProviderDep,
    data_class: Annotated[DataClass, typer.Argument()],
    identifiers: Annotated[list[str], typer.Argument()],
) -> None:
    """Delete records by record identifier (as printed by `dump`)."""
    async with MobileSyncService(service_provider) as sync:
        await sync.push_changes(DATA_CLASSES[data_class], dict.fromkeys(identifiers))
