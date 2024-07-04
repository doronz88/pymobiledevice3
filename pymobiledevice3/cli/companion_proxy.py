import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.companion import CompanionProxyService


@click.group()
def cli() -> None:
    pass


@cli.group()
def companion() -> None:
    """ List paired "companion" devices """
    pass


@companion.command('list', cls=Command)
def companion_list(service_provider: LockdownClient):
    """ list all paired companion devices """
    print_json(CompanionProxyService(service_provider).list(), default=lambda x: '<non-serializable>')
