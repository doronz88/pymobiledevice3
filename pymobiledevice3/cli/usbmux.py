import logging
import tempfile

import click

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import USBMUX_OPTION_HELP, print_json
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.tcp_forwarder import UsbmuxTcpForwarder

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ usbmuxd cli """
    pass


@cli.group('usbmux')
def usbmux_cli():
    """ usbmuxd options """
    pass


@usbmux_cli.command('forward')
@click.option('usbmux_address', '--usbmux', help=USBMUX_OPTION_HELP)
@click.argument('src_port', type=click.IntRange(1, 0xffff))
@click.argument('dst_port', type=click.IntRange(1, 0xffff))
@click.option('--serial', help='device serial number')
@click.option('-d', '--daemonize', is_flag=True)
def usbmux_forward(usbmux_address: str, src_port: int, dst_port: int, serial: str, daemonize: bool):
    """ forward tcp port """
    forwarder = UsbmuxTcpForwarder(serial, dst_port, src_port, usbmux_address=usbmux_address)

    if daemonize:
        try:
            from daemonize import Daemonize
        except ImportError:
            raise NotImplementedError('daemonizing is only supported on unix platforms')

        with tempfile.NamedTemporaryFile('wt') as pid_file:
            daemon = Daemonize(app=f'forwarder {src_port}->{dst_port}', pid=pid_file.name, action=forwarder.start)
            daemon.start()
    else:
        forwarder.start()


@usbmux_cli.command('list')
@click.option('usbmux_address', '--usbmux', help=USBMUX_OPTION_HELP)
@click.option('--color/--no-color', default=True)
@click.option('-u', '--usb', is_flag=True, help='show only usb devices')
@click.option('-n', '--network', is_flag=True, help='show only network devices')
def usbmux_list(usbmux_address: str, color: bool, usb: bool, network: bool) -> None:
    """ list connected devices """
    connected_devices = []
    for device in usbmux.list_devices(usbmux_address=usbmux_address):
        udid = device.serial

        if usb and not device.is_usb:
            continue

        if network and not device.is_network:
            continue

        lockdown = create_using_usbmux(udid, autopair=False, connection_type=device.connection_type,
                                       usbmux_address=usbmux_address)
        connected_devices.append(lockdown.short_info)

    print_json(connected_devices, colored=color)
