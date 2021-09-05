import click

from pymobiledevice3.cli.cli_common import MyCommand, print_json
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


@apps.command('list', cls=MyCommand)
@click.option('--color/--no-color', default=True)
@click.option('-u', '--user', is_flag=True, help='include user apps')
@click.option('-s', '--system', is_flag=True, help='include system apps')
def apps_list(lockdown, color, user, system):
    """ list installed apps """
    app_types = []
    if user:
        app_types.append('User')
    if system:
        app_types.append('System')
    print_json(InstallationProxyService(lockdown=lockdown).get_apps(app_types), colored=color)


@apps.command('uninstall', cls=MyCommand)
@click.argument('bundle_id')
def uninstall(lockdown, bundle_id):
    """ uninstall app by given bundle_id """
    InstallationProxyService(lockdown=lockdown).uninstall(bundle_id)


@apps.command('install', cls=MyCommand)
@click.argument('ipa_path', type=click.Path(exists=True))
def install(lockdown, ipa_path):
    """ install given .ipa """
    InstallationProxyService(lockdown=lockdown).install_from_local(ipa_path)


@apps.command('afc', cls=MyCommand)
@click.argument('bundle_id')
def afc(lockdown, bundle_id):
    """ open an AFC shell for given bundle_id, assuming its profile is installed """
    HouseArrestService(lockdown=lockdown).shell(bundle_id)
