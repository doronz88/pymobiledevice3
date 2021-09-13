import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
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
def state(lockdown: LockdownClient):
    """ Get current activation state """
    print(MobileActivationService(lockdown).state)


@activation.command(cls=Command)
@click.option('--offline', is_flag=True, help='Allow to send and receive requests manually')
@click.option('--now', is_flag=True, help='when --offline is used, dont wait for next nonce cycle')
def activate(lockdown: LockdownClient, offline, now):
    """ Activate device """
    MobileActivationService(lockdown, offline, now).activate()


@activation.command(cls=Command)
def deactivate(lockdown: LockdownClient):
    """ Deactivate device """
    MobileActivationService(lockdown).deactivate()
