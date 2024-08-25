import logging
import plistlib
import tempfile
from pathlib import Path
from typing import IO, List

import click
from typing_extensions import Optional

from pymobiledevice3.ca import create_keybag_file
from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.mobile_activation import MobileActivationService
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
@click.argument('certificate', type=click.Path(exists=True, dir_okay=False, file_okay=True))
@click.argument('profiles', nargs=-1, type=click.File('rb'))
def profile_install_silent(certificate: str, service_provider: LockdownServiceProvider, profiles: List[IO]) -> None:
    """ install given profiles without user interaction (requires the device to be supervised) """
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f'installing {profile.name}')
        service.install_profile_silent(certificate, profile.read())


@profile_group.command('cloud-configuration', cls=Command)
@click.argument('config', type=click.File('rb'), required=False)
def profile_cloud_configuration(service_provider: LockdownClient, config):
    """ get/set cloud configuration """
    if not config:
        print_json(MobileConfigService(lockdown=service_provider).get_cloud_configuration())
    else:
        config_json = plistlib.load(config)
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
@click.option('--preserve-data-plan/--no-preserve-data-plan', default=True,
              help='Preserves eSIM / data plan after erase')
@click.option('--disallow-proximity-setup/--no-disallow-proximity-setup', default=False,
              help='Disallows to setup the erased device from nearby devices')
def profile_erase_device(service_provider: LockdownClient, preserve_data_plan: bool, disallow_proximity_setup: bool):
    """ erase device """
    logger.info(f'Erasing device with preserve_data_plan: {preserve_data_plan}, '
                f'disallow_proximity_setup: {disallow_proximity_setup}')
    MobileConfigService(lockdown=service_provider).erase_device(preserve_data_plan, disallow_proximity_setup)
    logger.info('Erased device')


@profile_group.command('create-keybag')
@click.argument('keybag', type=click.Path(file_okay=True, dir_okay=False, exists=False))
@click.argument('organization')
def profile_create_keybag(keybag: str, organization: str) -> None:
    """ Create keybag storing certificate and private key """
    create_keybag_file(Path(keybag), organization)


@profile_group.command('supervise', cls=Command)
@click.argument('organization')
@click.option('--keybag', type=click.Path(file_okay=True, dir_okay=False, exists=True))
def profile_supervise(service_provider: LockdownServiceProvider, organization: str, keybag: Optional[str]) -> None:
    """ supervise device """
    if MobileActivationService(service_provider).state == 'Unactivated':
        logger.info('Activating device')
        MobileActivationService(service_provider).activate()
        logger.info('Device has been successfully activated')
    logger.info('Supervising device')
    if keybag is None:
        with tempfile.TemporaryDirectory() as temp_dir:
            keybag = Path(temp_dir) / 'keybag'
            create_keybag_file(keybag, organization)
            MobileConfigService(lockdown=service_provider).supervise(organization, keybag)
    else:
        MobileConfigService(lockdown=service_provider).supervise(organization, Path(keybag))

    logger.info('Device has been successfully supervised')
