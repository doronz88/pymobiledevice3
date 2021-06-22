import click

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import print_json
from pymobiledevice3.lockdown import LockdownClient


@click.group()
def cli():
    """ list-devices group """
    pass


@cli.command('list-devices')
@click.option('--color/--no-color', default=True)
def list_devices(color):
    """ list connected devices """
    mux = usbmux.USBMux()
    mux.process()
    connected_devices = []
    for device in mux.devices:
        udid = device.serial
        lockdown = LockdownClient(udid)
        connected_devices.append(lockdown.all_values)

    print_json(connected_devices, colored=color, default=lambda x: '<non-serializable>')
