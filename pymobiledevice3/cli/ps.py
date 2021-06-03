import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.services.os_trace import OsTraceService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.command(cls=Command)
@click.option('--nocolor', is_flag=True)
def ps(lockdown, nocolor):
    """ show process list """
    print_json(OsTraceService(lockdown=lockdown).get_pid_list(), colored=not nocolor)
