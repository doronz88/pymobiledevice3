import plistlib

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.misagent import MisagentService


@click.group()
def cli():
    """ privision cli """
    pass


@cli.group()
def provision():
    """ privision options """
    pass


@provision.command('install', cls=Command)
@click.argument('profile', type=click.File('rb'))
def provision_install(lockdown: LockdownClient, profile):
    """ install a provision profile (.mobileprovision file) """
    MisagentService(lockdown=lockdown).install(profile)


@provision.command('remove', cls=Command)
@click.argument('profile_id')
def provision_install(lockdown: LockdownClient, profile_id):
    """ remove a provision profile """
    MisagentService(lockdown=lockdown).remove(profile_id)


@provision.command('list', cls=Command)
@click.option('--color/--no-color', default=True)
def provision_list(lockdown: LockdownClient, color):
    """ list installed provision profiles """
    provision_profiles_raw = MisagentService(lockdown=lockdown).copy_all()
    provision_profiles = []

    for p in provision_profiles_raw:
        xml = b'<?xml' + p.split(b'<?xml', 1)[1]
        xml = xml.split(b'</plist>')[0] + b'</plist>'
        provision_profiles.append(plistlib.loads(xml))

    print_json(provision_profiles, colored=color)
