import logging
from pathlib import Path

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.misagent import MisagentService

logger = logging.getLogger(__name__)


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
def provision_remove(lockdown: LockdownClient, profile_id):
    """ remove a provision profile """
    MisagentService(lockdown=lockdown).remove(profile_id)


@provision.command('clear', cls=Command)
def provision_clear(lockdown: LockdownClient):
    """ remove all provision profiles """
    for profile in MisagentService(lockdown=lockdown).copy_all():
        MisagentService(lockdown=lockdown).remove(profile.plist['UUID'])


@provision.command('list', cls=Command)
@click.option('--color/--no-color', default=True)
def provision_list(lockdown: LockdownClient, color):
    """ list installed provision profiles """
    print_json([p.plist for p in MisagentService(lockdown=lockdown).copy_all()], colored=color)


@provision.command('dump', cls=Command)
@click.argument('out', type=click.Path(file_okay=False, dir_okay=True, exists=True))
def provision_dump(lockdown: LockdownClient, out):
    """ dump installed provision profiles to specified location """
    for profile in MisagentService(lockdown=lockdown).copy_all():
        filename = f'{profile.plist["UUID"]}.mobileprovision'
        logger.info(f'downloading {filename}')
        (Path(out) / filename).write_bytes(profile.buf)
