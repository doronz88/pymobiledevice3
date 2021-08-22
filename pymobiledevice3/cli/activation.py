import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.mobile_activation import MobileActivationService


@click.group()
def cli():
    """ cli """
    pass


@cli.group()
def activation():
    """ activation options """
    pass


@activation.command(cls=Command)
def state(lockdown):
    """ Get current activation state """
    print(MobileActivationService(lockdown).state)


@activation.command(cls=Command)
@click.option('--offline', is_flag=True, help='Allow to send and receive requests manually')
def activate(lockdown, offline):
    """ Activate device """
    MobileActivationService(lockdown, offline).activate()


@activation.command(cls=Command)
def deactivate(lockdown):
    """ Deactivate device """
    MobileActivationService(lockdown).deactivate()
