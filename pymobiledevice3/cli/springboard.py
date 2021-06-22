import logging

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.springboard import SpringBoardServicesService


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
@click.option('--color/--no-color', default=True)
def state_get(lockdown, color):
    """ get icon state """
    print_json(SpringBoardServicesService(lockdown=lockdown).get_icon_state(), colored=color)


@springboard.command('icon', cls=Command)
@click.argument('bundle_id')
@click.argument('out', type=click.File('wb'))
def springboard_icon(lockdown, bundle_id, out):
    """ get application's icon """
    out.write(SpringBoardServicesService(lockdown=lockdown).get_icon_pngdata(bundle_id))


@springboard.command('orientation', cls=Command)
def springboard_orientation(lockdown):
    """ get screen orientation """
    print(SpringBoardServicesService(lockdown=lockdown).get_interface_orientation())


@springboard.command('wallpaper', cls=Command)
@click.argument('out', type=click.File('wb'))
def springboard_wallpaper(lockdown, out):
    """ get wallpapaer """
    out.write(SpringBoardServicesService(lockdown=lockdown).get_wallpaper_pngdata())
