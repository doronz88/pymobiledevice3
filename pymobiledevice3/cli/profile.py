from pprint import pprint

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.mobile_config import MobileConfigService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group('profile')
def profile_group():
    """ profile options """
    pass


@profile_group.command('list', cls=Command)
def profile_list(lockdown):
    """ list installed profiles """
    pprint(MobileConfigService(lockdown=lockdown).get_profile_list())


@profile_group.command('install', cls=Command)
@click.argument('profile', type=click.File('rb'))
def profile_install(lockdown, profile):
    """ install given profile file """
    pprint(MobileConfigService(lockdown=lockdown).install_profile(profile.read()))


@profile_group.command('remove', cls=Command)
@click.argument('name')
def profile_remove(lockdown, name):
    """ remove profile by name """
    pprint(MobileConfigService(lockdown=lockdown).remove_profile(name))
