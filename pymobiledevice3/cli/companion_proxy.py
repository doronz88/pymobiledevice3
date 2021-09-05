import click

from pymobiledevice3.cli.cli_common import MyCommand, print_json
from pymobiledevice3.services.companion import CompanionProxyService


@click.group()
def cli():
    """ companion cli """
    pass


@cli.group()
def companion():
    """ companion options """
    pass


@companion.command('list', cls=MyCommand)
@click.option('--color/--no-color', default=True)
def companion_list(lockdown, color):
    """ list all paired companion devices """
    print_json(CompanionProxyService(lockdown).list(), colored=color, default=lambda x: '<non-serializable>')
