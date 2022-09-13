import click
import logging
import tempfile
from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.tcp_forwarder import TcpForwarder

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ usbmuxd cli """
    pass


@cli.group('usbmux')
def usbmux_cli():
    """ usbmuxd options """
    pass


@usbmux_cli.command('forward', cls=Command)
@click.argument('src_port', type=click.IntRange(1, 0xffff))
@click.argument('dst_port', type=click.IntRange(1, 0xffff))
@click.option('-d', '--daemonize', is_flag=True)
def usbmux_forward(lockdown: LockdownClient, src_port, dst_port, daemonize):
    """ forward tcp port """
    forwarder = TcpForwarder(lockdown, src_port, dst_port)

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
@click.option('--color/--no-color', default=True)
@click.option('-u', '--usb', is_flag=True, help='show only usb devices')
@click.option('-n', '--network', is_flag=True, help='show only network devices')
def usbmux_list(color, usb, network):
    """ list connected devices """
    connected_devices = []
    for device in usbmux.list_devices():
        udid = device.serial

        if usb and not device.is_usb:
            continue

        if network and not device.is_network:
            continue

        lockdown = LockdownClient(udid, autopair=False, usbmux_connection_type=device.connection_type)
        connected_devices.append(lockdown.short_info)

    print_json(connected_devices, colored=color)
