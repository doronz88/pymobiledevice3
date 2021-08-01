import click

from pymobiledevice3.cli.cli_common import Command, print_json
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
def provision_install(lockdown, profile):
    """ install a provision profile (.mobileprovision file) """
    MisagentService(lockdown=lockdown).install(profile)


@provision.command('remove', cls=Command)
@click.argument('profile_id')
def provision_install(lockdown, profile_id):
    """ remove a provision profile """
    MisagentService(lockdown=lockdown).remove(profile_id)


@provision.command('list', cls=Command)
@click.option('--color/--no-color', default=True)
def provision_list(lockdown, color):
    """ list installed provision profiles """
    print_json(MisagentService(lockdown=lockdown).copy_all(), colored=color)
