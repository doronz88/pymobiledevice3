from typing import Annotated, Literal

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.mobilesync import MobileSyncService

cli = InjectingTyper(
    name="mobilesync",
    help="Read contacts, calendars, Safari bookmarks and mail accounts (com.apple.mobilesync)",
    no_args_is_help=True,
)

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
    data_class: Annotated[Literal["contacts", "calendars", "bookmarks", "mail-accounts"], typer.Argument()],
) -> None:
    """Print every record of a data class, keyed by record identifier."""
    async with MobileSyncService(service_provider) as sync:
        print_json(await sync.get_all_records(DATA_CLASSES[data_class]))
