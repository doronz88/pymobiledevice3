import logging
import time
from pprint import pprint

import click
from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.diagnostics import DiagnosticsService

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def diagnostics():
    """ diagnostics options """
    pass


@diagnostics.command('restart', cls=Command)
def diagnostics_restart(lockdown: LockdownClient):
    """ restart device """
    DiagnosticsService(lockdown=lockdown).restart()


@diagnostics.command('shutdown', cls=Command)
def diagnostics_shutdown(lockdown: LockdownClient):
    """ shutdown device """
    DiagnosticsService(lockdown=lockdown).shutdown()


@diagnostics.command('sleep', cls=Command)
def diagnostics_sleep(lockdown: LockdownClient):
    """ put device into sleep """
    DiagnosticsService(lockdown=lockdown).sleep()


@diagnostics.command('info', cls=Command)
@click.option('--color/--no-color', default=True)
def diagnostics_info(lockdown: LockdownClient, color):
    """ get diagnostics info """
    print_json(DiagnosticsService(lockdown=lockdown).info(), colored=color)


@diagnostics.command('ioregistry', cls=Command)
@click.option('--plane')
@click.option('--name')
@click.option('--ioclass')
def diagnostics_ioregistry(lockdown: LockdownClient, plane, name, ioclass):
    """ get ioregistry info """
    pprint(DiagnosticsService(lockdown=lockdown).ioregistry(plane=plane, name=name, ioclass=ioclass))


@diagnostics.command('mg', cls=Command)
@click.argument('keys', nargs=-1, default=None)
def diagnostics_mg(lockdown: LockdownClient, keys):
    """ get MobileGestalt key values from given list. If empty, return all known. """
    pprint(DiagnosticsService(lockdown=lockdown).mobilegestalt(keys=keys))


@diagnostics.group('battery')
def diagnostics_battery():
    """ battery options """
    pass


@diagnostics_battery.command('single', cls=Command)
@click.option('--color/--no-color', default=True)
def diagnostics_battery_single(lockdown: LockdownClient, color):
    """ get single snapshot of battery data """
    raw_info = DiagnosticsService(lockdown=lockdown).get_battery()
    print_json(raw_info, colored=color)


@diagnostics_battery.command('monitor', cls=Command)
def diagnostics_battery_monitor(lockdown: LockdownClient):
    """ monitor battery usage """
    diagnostics = DiagnosticsService(lockdown=lockdown)
    while True:
        raw_info = diagnostics.get_battery()
        info = {
            'InstantAmperage': raw_info.get('InstantAmperage'),
            'Temperature': raw_info.get('Temperature'),
            'Voltage': raw_info.get('Voltage'),
            'IsCharging': raw_info.get('IsCharging'),
            'CurrentCapacity': raw_info.get('CurrentCapacity'),
        }
        logger.info(info)
        time.sleep(1)
