import logging
import time

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.diagnostics import DiagnosticsService

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group()
def diagnostics() -> None:
    """ Reboot/Shutdown device or access other diagnostics services """
    pass


@diagnostics.command('restart', cls=Command)
def diagnostics_restart(service_provider: LockdownClient):
    """ Restart device """
    DiagnosticsService(lockdown=service_provider).restart()


@diagnostics.command('shutdown', cls=Command)
def diagnostics_shutdown(service_provider: LockdownClient):
    """ Shutdown device """
    DiagnosticsService(lockdown=service_provider).shutdown()


@diagnostics.command('sleep', cls=Command)
def diagnostics_sleep(service_provider: LockdownClient):
    """ Put device into sleep """
    DiagnosticsService(lockdown=service_provider).sleep()


@diagnostics.command('info', cls=Command)
def diagnostics_info(service_provider: LockdownClient):
    """ Get diagnostics info """
    print_json(DiagnosticsService(lockdown=service_provider).info())


@diagnostics.command('ioregistry', cls=Command)
@click.option('--plane')
@click.option('--name')
@click.option('--ioclass')
def diagnostics_ioregistry(service_provider: LockdownClient, plane, name, ioclass):
    """ Get ioregistry info """
    print_json(DiagnosticsService(lockdown=service_provider).ioregistry(plane=plane, name=name, ioclass=ioclass))


@diagnostics.command('mg', cls=Command)
@click.argument('keys', nargs=-1, default=None)
def diagnostics_mg(service_provider: LockdownClient, keys):
    """ Get MobileGestalt key values from given list. If empty, return all known. """
    print_json(DiagnosticsService(lockdown=service_provider).mobilegestalt(keys=keys))


@diagnostics.group('battery')
def diagnostics_battery():
    """ Battery options """
    pass


@diagnostics_battery.command('single', cls=Command)
def diagnostics_battery_single(service_provider: LockdownClient):
    """ get single snapshot of battery data """
    raw_info = DiagnosticsService(lockdown=service_provider).get_battery()
    print_json(raw_info)


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


@diagnostics.command('wifi', cls=Command)
def diagnostics_wifi(service_provider: LockdownServiceProvider) -> None:
    """ Query WiFi info from IORegistry """
    raw_info = DiagnosticsService(lockdown=service_provider).get_wifi()
    print_json(raw_info)
