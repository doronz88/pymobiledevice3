import logging
import time
from pprint import pprint

import click
from pymobiledevice3.cli.cli_common import MyCommand, print_json
from pymobiledevice3.services.diagnostics import DiagnosticsService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def diagnostics():
    """ diagnostics options """
    pass


@diagnostics.command('restart', cls=MyCommand)
def diagnostics_restart(lockdown):
    """ restart device """
    DiagnosticsService(lockdown=lockdown).restart()


@diagnostics.command('shutdown', cls=MyCommand)
def diagnostics_shutdown(lockdown):
    """ shutdown device """
    DiagnosticsService(lockdown=lockdown).shutdown()


@diagnostics.command('sleep', cls=MyCommand)
def diagnostics_sleep(lockdown):
    """ put device into sleep """
    DiagnosticsService(lockdown=lockdown).sleep()


@diagnostics.command('info', cls=MyCommand)
@click.option('--color/--no-color', default=True)
def diagnostics_info(lockdown, color):
    """ get diagnostics info """
    print_json(DiagnosticsService(lockdown=lockdown).info(), colored=color)


@diagnostics.command('ioregistry', cls=MyCommand)
@click.option('--plane')
@click.option('--name')
@click.option('--ioclass')
def diagnostics_ioregistry(lockdown, plane, name, ioclass):
    """ get ioregistry info """
    pprint(DiagnosticsService(lockdown=lockdown).ioregistry(plane=plane, name=name, ioclass=ioclass))


@diagnostics.command('mg', cls=MyCommand)
@click.argument('keys', nargs=-1, default=None)
def diagnostics_mg(lockdown, keys):
    """ get MobileGestalt key values from given list. If empty, return all known. """
    pprint(DiagnosticsService(lockdown=lockdown).mobilegestalt(keys=keys))


@diagnostics.group('battery')
def diagnostics_battery():
    """ battery options """
    pass


@diagnostics_battery.command('single', cls=MyCommand)
@click.option('--color/--no-color', default=True)
def diagnostics_battery_single(lockdown, color):
    """ get single snapshot of battery data """
    raw_info = DiagnosticsService(lockdown=lockdown).get_battery()
    print_json(raw_info, colored=color)


@diagnostics_battery.command('monitor', cls=MyCommand)
def diagnostics_battery_monitor(lockdown):
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
        logging.info(info)
        time.sleep(1)
