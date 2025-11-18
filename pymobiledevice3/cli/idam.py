import logging

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.idam import IDAMService

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group("idam")
def idam() -> None:
    """
    Access IDAM (Inter-Device Audio and MIDI) configuration

    For more info refer to:
    <https://www.youtube.com/watch?v=IXmP938brnc>
    """
    pass


@idam.command(cls=Command)
def configuration_inquiry(service_provider: LockdownServiceProvider) -> None:
    """Inquiry IDAM configuration"""
    with IDAMService(service_provider) as idam:
        print_json(idam.configuration_inquiry())


@idam.command(cls=Command)
def enable(service_provider: LockdownServiceProvider) -> None:
    """Enable IDAM"""
    with IDAMService(service_provider) as idam:
        idam.set_idam_configuration(True)


@idam.command(cls=Command)
def disable(service_provider: LockdownServiceProvider) -> None:
    """Disable IDAM"""
    with IDAMService(service_provider) as idam:
        idam.set_idam_configuration(False)
