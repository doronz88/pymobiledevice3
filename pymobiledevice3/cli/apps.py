import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
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
@click.option('--color/--no-color', default=True)
@click.option('-u', '--user', is_flag=True, help='include user apps')
@click.option('-s', '--system', is_flag=True, help='include system apps')
@click.option('--hidden', is_flag=True, help='include hidden apps')
def apps_list(service_provider: LockdownClient, color, user, system, hidden):
    """ list installed apps """
    app_types = []
    if user:
        app_types.append('User')
    if system:
        app_types.append('System')
    if hidden:
        app_types.append('Hidden')
    print_json(InstallationProxyService(lockdown=service_provider).get_apps(app_types), colored=color)


@apps.command('uninstall', cls=Command)
@click.argument('bundle_id')
def uninstall(service_provider: LockdownClient, bundle_id):
    """ uninstall app by given bundle_id """
    InstallationProxyService(lockdown=service_provider).uninstall(bundle_id)


@apps.command('install', cls=Command)
@click.argument('ipa_path', type=click.Path(exists=True))
def install(service_provider: LockdownClient, ipa_path):
    """ install given .ipa """
    InstallationProxyService(lockdown=service_provider).install_from_local(ipa_path)


@apps.command('afc', cls=Command)
@click.option('--documents', is_flag=True)
@click.argument('bundle_id')
def afc(service_provider: LockdownClient, bundle_id: str, documents: bool):
    """ open an AFC shell for given bundle_id, assuming its profile is installed """
    HouseArrestService(lockdown=service_provider).shell(bundle_id, documents_only=documents)
