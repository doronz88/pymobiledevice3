import json
import logging

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobile_config import MobileConfigService

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group('profile')
def profile_group() -> None:
    """ Managed installed profiles or install SSL certificates """
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
@click.argument('config', type=click.File('rb'), required=False)
def profile_cloud_configuration(service_provider: LockdownClient, config):
    """ get/set cloud configuration """
    if not config:
        print_json(MobileConfigService(lockdown=service_provider).get_cloud_configuration())
    else:
        config_json = json.load(config)
        logger.info(f'applying cloud configuration {config_json}')
        MobileConfigService(lockdown=service_provider).set_cloud_configuration(config_json)
        logger.info('applied cloud configuration')


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


@profile_group.command('erase-device', cls=Command)
@click.option('--preserve-data-plan/--no-preserve-data-plan', default=True, help='Preserves eSIM / data plan after erase')
@click.option('--disallow-proximity-setup/--no-disallow-proximity-setup', default=False,
              help='Disallows to setup the erased device from nearby devices')
def profile_erase_device(service_provider: LockdownClient, preserve_data_plan: bool, disallow_proximity_setup: bool):
    """ erase device """
    logger.info(f'erasing device with preserve_data_plan: {preserve_data_plan}, '
                f'disallow_proximity_setup: {disallow_proximity_setup}')
    MobileConfigService(lockdown=service_provider).erase_device(preserve_data_plan, disallow_proximity_setup)
    logger.info('erased device')
