import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.afc import AfcShell


@click.group()
def cli():
    """ apps cli """
    pass


@cli.command(cls=Command)
@click.argument('action', type=click.Choice(['flush', 'shell']))
def crash(lockdown, action):
    """ crash utils """
    if action == 'flush':
        ack = b'ping\x00'
        assert ack == lockdown.start_service('com.apple.crashreportmover').recvall(len(ack))
    elif action == 'shell':
        AfcShell(lockdown=lockdown, afcname='com.apple.crashreportcopymobile').cmdloop()
