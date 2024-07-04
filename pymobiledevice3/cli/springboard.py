from typing import IO

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
    pass


@cli.group()
def springboard():
    """ Access device UI """
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


@springboard.command('wallpaper-home-screen', cls=Command)
@click.argument('out', type=click.File('wb'))
def springboard_wallpaper_home_screen(service_provider: LockdownClient, out: IO) -> None:
    """ get homescreen wallpaper """
    out.write(SpringBoardServicesService(lockdown=service_provider).get_wallpaper_pngdata())


@springboard.command('wallpaper-preview-image', cls=Command)
@click.argument('wallpaper-name', type=click.Choice(['homescreen', 'lockscreen']))
@click.argument('out', type=click.File('wb'))
@click.option('-r', '--reload', is_flag=True, help='reload icon state before fetching image')
def springboard_wallpaper_preview_image(service_provider: LockdownClient, wallpaper_name: str, out: IO,
                                        reload: bool) -> None:
    """ get the preview image of either the homescreen or the lockscreen """
    with SpringBoardServicesService(lockdown=service_provider) as springboard_service:
        if reload:
            springboard_service.reload_icon_state()
        out.write(springboard_service.get_wallpaper_preview_image(wallpaper_name))
