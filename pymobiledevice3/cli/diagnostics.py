from pprint import pprint

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.diagnostics import DiagnosticsService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def diagnostics():
    """ diagnostics options """
    pass


@diagnostics.command('restart', cls=Command)
def diagnostics_restart(lockdown):
    """ restart device """
    DiagnosticsService(lockdown=lockdown).restart()


@diagnostics.command('shutdown', cls=Command)
def diagnostics_shutdown(lockdown):
    """ shutdown device """
    DiagnosticsService(lockdown=lockdown).shutdown()


@diagnostics.command('sleep', cls=Command)
def diagnostics_sleep(lockdown):
    """ put device into sleep """
    DiagnosticsService(lockdown=lockdown).sleep()


@diagnostics.command('info', cls=Command)
def diagnostics_info(lockdown):
    """ get diagnostics info """
    pprint(DiagnosticsService(lockdown=lockdown).info())


@diagnostics.command('ioregistry', cls=Command)
@click.option('--plane')
@click.option('--name')
@click.option('--ioclass')
def diagnostics_ioregistry(lockdown, plane, name, ioclass):
    """ get ioregistry info """
    pprint(DiagnosticsService(lockdown=lockdown).ioregistry(plane=plane, name=name, ioclass=ioclass))


@diagnostics.command('mg', cls=Command)
@click.argument('keys', nargs=-1, default=None)
def diagnostics_mg(lockdown, keys):
    """ get MobileGestalt key values from given list. If empty, return all known. """
    pprint(DiagnosticsService(lockdown=lockdown).mobilegestalt(keys=keys))
