import logging

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.amfi import AmfiService

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group()
def amfi() -> None:
    """ Enable developer-mode or query its state """
    pass


@amfi.command(cls=Command)
def reveal_developer_mode(service_provider: LockdownClient):
    """ reveal developer mode option in device's UI """
    AmfiService(service_provider).reveal_developer_mode_option_in_ui()


@amfi.command(cls=Command)
def enable_developer_mode(service_provider: LockdownClient):
    """ enable developer mode """
    AmfiService(service_provider).enable_developer_mode()


@amfi.command(cls=Command)
def developer_mode_status(service_provider: LockdownClient):
    """ query developer mode status """
    print_json(service_provider.developer_mode_status)
