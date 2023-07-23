import logging

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.amfi import AmfiService

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ amfi cli """
    pass


@cli.group()
def amfi():
    """ amfi options """
    pass


@amfi.command(cls=Command)
def enable_developer_mode(service_provider: LockdownClient):
    """ enable developer mode """
    AmfiService(service_provider).enable_developer_mode()


@amfi.command(cls=Command)
@click.option('--color/--no-color', default=True)
def developer_mode_status(service_provider: LockdownClient, color):
    """ query developer mode status """
    print_json(service_provider.developer_mode_status, colored=color)
