import logging
import tempfile
from typing import Annotated, Optional

import click
import typer

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import USBMUX_OPTION_HELP, BaseCommand, print_json
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.tcp_forwarder import UsbmuxTcpForwarder

logger = logging.getLogger(__name__)

cli = typer.Typer(no_args_is_help=True, add_completion=False, help='List devices or forward a TCP port')


@cli.command('forward', cls=BaseCommand)
@click.argument('src_port', type=click.IntRange(1, 0xffff))
@click.argument('dst_port', type=click.IntRange(1, 0xffff))
@click.option('--serial', help='device serial number')
@click.option('-d', '--daemonize', is_flag=True)
@click.option('usbmux_address', '--usbmux', help=USBMUX_OPTION_HELP)
def usbmux_forward(src_port: int, dst_port: int, serial: str, daemonize: bool = False,
                   usbmux_address: Optional[str] = None) -> None:
    """ Forward tcp port """
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


@cli.command('list', cls=BaseCommand)
def usbmux_list(usbmux_address: Annotated[Optional[str], typer.Option(help=USBMUX_OPTION_HELP)] = None,
                usb: Annotated[bool, typer.Option(help='Show only USB devices')] = False,
                network: Annotated[bool, typer.Option(help='Show only network devices')] = False,
                ) -> None:
    """ List connected devices """
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

    print_json(connected_devices)
