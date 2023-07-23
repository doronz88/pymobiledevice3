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
def profile_list(service_provider: LockdownClient):
    """ list installed profiles """
    print_json(MobileConfigService(lockdown=service_provider).get_profile_list())


@profile_group.command('install', cls=Command)
@click.argument('profiles', nargs=-1, type=click.File('rb'))
def profile_install(service_provider: LockdownClient, profiles):
    """ install given profiles """
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f'installing {profile.name}')
        service.install_profile(profile.read())


@profile_group.command('install-silent', cls=Command)
@click.option('--keystore', type=click.File('rb'), required=True,
              help="A PKCS#12 keystore containing the certificate and private key which can supervise the device.")
@click.option('--keystore-password', prompt=True, required=True, hide_input=True,
              help="The password for the PKCS#12 keystore.")
@click.argument('profiles', nargs=-1, type=click.File('rb'))
def profile_install_silent(service_provider: LockdownClient, profiles, keystore, keystore_password):
    """ install given profiles without user interaction (requires the device to be supervised) """
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f'installing {profile.name}')
        service.install_profile_silent(
            profile.read(), keystore.read(), keystore_password)


@profile_group.command('cloud-configuration', cls=Command)
@click.option('--color/--no-color', default=True)
def profile_cloud_configuration(service_provider: LockdownClient, color):
    """ get cloud configuration """
    print_json(MobileConfigService(lockdown=service_provider).get_cloud_configuration(), colored=color)


@profile_group.command('store', cls=Command)
@click.argument('profiles', nargs=-1, type=click.File('rb'))
def profile_store(service_provider: LockdownClient, profiles):
    """ store profile """
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f'storing {profile.name}')
        service.store_profile(profile.read())


@profile_group.command('remove', cls=Command)
@click.argument('name')
def profile_remove(service_provider: LockdownClient, name):
    """ remove profile by name """
    MobileConfigService(lockdown=service_provider).remove_profile(name)


@profile_group.command('set-wifi-power', cls=Command)
@click.argument('state', type=click.Choice(['on', 'off']), required=False)
def profile_set_wifi_power(service_provider: LockdownClient, state):
    """ change Wi-Fi power state """
    MobileConfigService(lockdown=service_provider).set_wifi_power_state(state == 'on')
