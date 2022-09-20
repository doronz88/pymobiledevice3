import logging

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobile_config import MobileConfigService

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group('profile')
def profile_group():
    """ profile options """
    pass


@profile_group.command('list', cls=Command)
def profile_list(lockdown: LockdownClient):
    """ list installed profiles """
    print_json(MobileConfigService(lockdown=lockdown).get_profile_list())


@profile_group.command('install', cls=Command)
@click.argument('profiles', nargs=-1, type=click.File('rb'))
def profile_install(lockdown: LockdownClient, profiles):
    """ install given profiles """
    service = MobileConfigService(lockdown=lockdown)
    for profile in profiles:
        logger.info(f'installing {profile.name}')
        service.install_profile(profile.read())


@profile_group.command('cloud-configuration', cls=Command)
@click.option('--color/--no-color', default=True)
def profile_cloud_configuration(lockdown: LockdownClient, color):
    """ get cloud configuration """
    print_json(MobileConfigService(lockdown=lockdown).get_cloud_configuration(), colored=color)


@profile_group.command('store', cls=Command)
@click.argument('profiles', nargs=-1, type=click.File('rb'))
def profile_store(lockdown: LockdownClient, profiles):
    """ store profile """
    service = MobileConfigService(lockdown=lockdown)
    for profile in profiles:
        logger.info(f'storing {profile.name}')
        service.store_profile(profile.read())


@profile_group.command('remove', cls=Command)
@click.argument('name')
def profile_remove(lockdown: LockdownClient, name):
    """ remove profile by name """
    MobileConfigService(lockdown=lockdown).remove_profile(name)


@profile_group.command('set-wifi-power', cls=Command)
@click.argument('state', type=click.Choice(['on', 'off']), required=False)
def profile_set_wifi_power(lockdown: LockdownClient, state):
    """ change Wi-Fi power state """
    MobileConfigService(lockdown=lockdown).set_wifi_power_state(state == 'on')
