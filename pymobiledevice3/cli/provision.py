import logging
from pathlib import Path

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.misagent import MisagentService

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ provision cli """
    pass


@cli.group()
def provision():
    """ provision options """
    pass


@provision.command('install', cls=Command)
@click.argument('profile', type=click.File('rb'))
def provision_install(service_provider: LockdownClient, profile):
    """ install a provision profile (.mobileprovision file) """
    MisagentService(lockdown=service_provider).install(profile)


@provision.command('remove', cls=Command)
@click.argument('profile_id')
def provision_remove(service_provider: LockdownClient, profile_id):
    """ remove a provision profile """
    MisagentService(lockdown=service_provider).remove(profile_id)


@provision.command('clear', cls=Command)
def provision_clear(service_provider: LockdownClient):
    """ remove all provision profiles """
    for profile in MisagentService(lockdown=service_provider).copy_all():
        MisagentService(lockdown=service_provider).remove(profile.plist['UUID'])


@provision.command('list', cls=Command)
def provision_list(service_provider: LockdownClient):
    """ list installed provision profiles """
    print_json([p.plist for p in MisagentService(lockdown=service_provider).copy_all()])


@provision.command('dump', cls=Command)
@click.argument('out', type=click.Path(file_okay=False, dir_okay=True, exists=True))
def provision_dump(service_provider: LockdownClient, out):
    """ dump installed provision profiles to specified location """
    for profile in MisagentService(lockdown=service_provider).copy_all():
        filename = f'{profile.plist["UUID"]}.mobileprovision'
        logger.info(f'downloading {filename}')
        (Path(out) / filename).write_bytes(profile.buf)
