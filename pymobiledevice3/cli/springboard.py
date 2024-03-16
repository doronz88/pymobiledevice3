import click
import IPython

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.springboard import SpringBoardServicesService

SHELL_USAGE = '''
Use `service` to access the service features
'''


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def springboard():
    """ springboard options """
    pass


@springboard.group()
def state():
    """ icons state options """
    pass


@state.command('get', cls=Command)
def state_get(service_provider: LockdownClient):
    """ get icon state """
    print_json(SpringBoardServicesService(lockdown=service_provider).get_icon_state())


@springboard.command('shell', cls=Command)
def springboard_shell(service_provider: LockdownClient):
    """ open a shell to communicate with SpringBoardServicesService """
    service = SpringBoardServicesService(lockdown=service_provider)
    IPython.embed(
        header=SHELL_USAGE,
        user_ns={
            'service': service,
        })


@springboard.command('icon', cls=Command)
@click.argument('bundle_id')
@click.argument('out', type=click.File('wb'))
def springboard_icon(service_provider: LockdownClient, bundle_id, out):
    """ get application's icon """
    out.write(SpringBoardServicesService(lockdown=service_provider).get_icon_pngdata(bundle_id))


@springboard.command('orientation', cls=Command)
def springboard_orientation(service_provider: LockdownClient):
    """ get screen orientation """
    print(SpringBoardServicesService(lockdown=service_provider).get_interface_orientation())


@springboard.command('wallpaper', cls=Command)
@click.argument('out', type=click.File('wb'))
def springboard_wallpaper(service_provider: LockdownClient, out):
    """ get wallpapaer """
    out.write(SpringBoardServicesService(lockdown=service_provider).get_wallpaper_pngdata())
