from pprint import pprint

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.os_trace import OsTraceService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.command(cls=Command)
def ps(lockdown):
    """ show process list """
    pprint(OsTraceService(lockdown=lockdown).get_pid_list())
