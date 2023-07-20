import logging
import time

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
def diagnostics_restart(service_provider: LockdownClient):
    """ restart device """
    DiagnosticsService(lockdown=service_provider).restart()


@diagnostics.command('shutdown', cls=Command)
def diagnostics_shutdown(service_provider: LockdownClient):
    """ shutdown device """
    DiagnosticsService(lockdown=service_provider).shutdown()


@diagnostics.command('sleep', cls=Command)
def diagnostics_sleep(service_provider: LockdownClient):
    """ put device into sleep """
    DiagnosticsService(lockdown=service_provider).sleep()


@diagnostics.command('info', cls=Command)
@click.option('--color/--no-color', default=True)
def diagnostics_info(service_provider: LockdownClient, color):
    """ get diagnostics info """
    print_json(DiagnosticsService(lockdown=service_provider).info(), colored=color)


@diagnostics.command('ioregistry', cls=Command)
@click.option('--plane')
@click.option('--name')
@click.option('--ioclass')
@click.option('--color/--no-color', default=True)
def diagnostics_ioregistry(service_provider: LockdownClient, plane, name, ioclass, color):
    """ get ioregistry info """
    print_json(DiagnosticsService(lockdown=service_provider).ioregistry(plane=plane, name=name, ioclass=ioclass),
               colored=color)


@diagnostics.command('mg', cls=Command)
@click.argument('keys', nargs=-1, default=None)
@click.option('--color/--no-color', default=True)
def diagnostics_mg(service_provider: LockdownClient, keys, color):
    """ get MobileGestalt key values from given list. If empty, return all known. """
    print_json(DiagnosticsService(lockdown=service_provider).mobilegestalt(keys=keys), colored=color)


@diagnostics.group('battery')
def diagnostics_battery():
    """ battery options """
    pass


@diagnostics_battery.command('single', cls=Command)
@click.option('--color/--no-color', default=True)
def diagnostics_battery_single(service_provider: LockdownClient, color):
    """ get single snapshot of battery data """
    raw_info = DiagnosticsService(lockdown=service_provider).get_battery()
    print_json(raw_info, colored=color)


@diagnostics_battery.command('monitor', cls=Command)
def diagnostics_battery_monitor(service_provider: LockdownClient):
    """ monitor battery usage """
    diagnostics = DiagnosticsService(lockdown=service_provider)
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
