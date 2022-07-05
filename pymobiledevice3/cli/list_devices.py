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
@click.option('-n', '--network', is_flag=True, help='show only network devices')
def list_devices(color, usb, network):
    """ list connected devices """
    connected_devices = []
    for device in usbmux.list_devices():
        udid = device.serial

        if usb and not device.is_usb:
            continue

        if network and not device.is_network:
            continue

        lockdown = LockdownClient(udid, autopair=False, connection_type=device.connection_type)
        connected_devices.append(lockdown.short_info)

    print_json(connected_devices, colored=color)
