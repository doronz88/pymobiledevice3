from typing import List

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def apps():
    """ application options """
    pass


@apps.command('list', cls=Command)
@click.option('app_type', '-t', '--type', type=click.Choice(['System', 'User', 'Hidden', 'Any']), default='Any',
              help='include only applications of given type')
@click.option('--calculate-sizes/--no-calculate-size', default=False)
def apps_list(service_provider: LockdownServiceProvider, app_type: str, calculate_sizes: bool) -> None:
    """ list installed apps """
    print_json(InstallationProxyService(lockdown=service_provider).get_apps(application_type=app_type,
                                                                            calculate_sizes=calculate_sizes))


@apps.command('query', cls=Command)
@click.argument('bundle_identifiers', nargs=-1)
@click.option('--calculate-sizes/--no-calculate-size', default=False)
def apps_query(service_provider: LockdownServiceProvider, bundle_identifiers: List[str], calculate_sizes: bool) -> None:
    """ query installed apps """
    print_json(InstallationProxyService(lockdown=service_provider)
               .get_apps(calculate_sizes=calculate_sizes, bundle_identifiers=bundle_identifiers))


@apps.command('uninstall', cls=Command)
@click.argument('bundle_id')
def uninstall(service_provider: LockdownClient, bundle_id):
    """ uninstall app by given bundle_id """
    InstallationProxyService(lockdown=service_provider).uninstall(bundle_id)


@apps.command('install', cls=Command)
@click.argument('ipa_or_app_path', type=click.Path(exists=True))
def install(service_provider: LockdownServiceProvider, ipa_or_app_path: str) -> None:
    """ install given .ipa/.app """
    InstallationProxyService(lockdown=service_provider).install_from_local(ipa_or_app_path)


@apps.command('afc', cls=Command)
@click.option('--documents', is_flag=True)
@click.argument('bundle_id')
def afc(service_provider: LockdownClient, bundle_id: str, documents: bool):
    """ open an AFC shell for given bundle_id, assuming its profile is installed """
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id, documents_only=documents).shell()
