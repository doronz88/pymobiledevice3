import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.power_assertion import PowerAssertionService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.command('power-assertion', cls=Command)
@click.argument('type', type=click.Choice(
    ['AMDPowerAssertionTypeWirelessSync', 'PreventUserIdleSystemSleep', 'PreventSystemSleep']))
@click.argument('name')
@click.argument('timeout', type=click.INT)
@click.argument('details', required=False)
def power_assertion(lockdown: LockdownClient, type, name, timeout, details):
    """ Create a power assertion (wraps IOPMAssertionCreateWithName()) """
    PowerAssertionService(lockdown).create_power_assertion(type, name, timeout, details)
