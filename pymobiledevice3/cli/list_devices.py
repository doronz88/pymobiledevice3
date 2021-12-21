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
@click.option('-u', '--usb', is_flag=True, help='show only usb devices')
def list_devices(color, usb):
    """ list connected devices """
    connected_devices = []
    for device in usbmux.list_devices():
        udid = device.serial

        if usb:
            if ':' in udid:
                continue

        lockdown = LockdownClient(udid, autopair=False)
        connected_devices.append(lockdown.all_values)

    print_json(connected_devices, colored=color)
