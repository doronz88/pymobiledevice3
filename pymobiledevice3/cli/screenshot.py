import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.screenshot import ScreenshotService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.command(cls=Command)
@click.argument('out', type=click.File('wb'))
def screenshot(lockdown, out):
    """ take a screenshot in PNG format """
    out.write(ScreenshotService(lockdown=lockdown).take_screenshot())
