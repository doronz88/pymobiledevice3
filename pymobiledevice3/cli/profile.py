import logging

import click

from pymobiledevice3.cli.cli_common import MyCommand, print_json
from pymobiledevice3.services.mobile_config import MobileConfigService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group('profile')
def profile_group():
    """ profile options """
    pass


@profile_group.command('list', cls=MyCommand)
def profile_list(lockdown):
    """ list installed profiles """
    print_json(MobileConfigService(lockdown=lockdown).get_profile_list())


@profile_group.command('install', cls=MyCommand)
@click.argument('profiles', nargs=-1, type=click.File('rb'))
def profile_install(lockdown, profiles):
    """ install given profiles """
    service = MobileConfigService(lockdown=lockdown)
    for profile in profiles:
        logging.info(f'installing {profile.name}')
        service.install_profile(profile.read())


@profile_group.command('remove', cls=MyCommand)
@click.argument('name')
def profile_remove(lockdown, name):
    """ remove profile by name """
    print_json(MobileConfigService(lockdown=lockdown).remove_profile(name))
