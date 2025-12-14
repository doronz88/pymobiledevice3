import logging
import tempfile
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import USBMUX_OPTION_HELP, print_json
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.tcp_forwarder import UsbmuxTcpForwarder

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="usbmux",
    help="Inspect usbmuxd-connected devices and forward TCP ports to them.",
    no_args_is_help=True,
)


@cli.command("forward")
def usbmux_forward(
    src_port: Annotated[
        int,
        typer.Argument(min=1, max=0xFFFF),
    ],
    dst_port: Annotated[
        int,
        typer.Argument(min=1, max=0xFFFF),
    ],
    *,
    usbmux_address: Annotated[
        Optional[str],
        typer.Option(
            "--usbmux",
            help=USBMUX_OPTION_HELP,
        ),
    ] = None,
    serial: Annotated[
        str,
        typer.Option(help="Device serial/UDID to forward traffic to."),
    ],
    daemonize: Annotated[
        bool,
        typer.Option("--daemonize", "-d", help="Run the forwarder in the background."),
    ] = False,
) -> None:
    """Forward a local TCP port to the device via usbmuxd."""
    forwarder = UsbmuxTcpForwarder(serial, dst_port, src_port, usbmux_address=usbmux_address)

    if daemonize:
        try:
            from daemonize import Daemonize
        except ImportError as e:
            raise NotImplementedError("daemonizing is only supported on unix platforms") from e

        with tempfile.NamedTemporaryFile("wt") as pid_file:
            daemon = Daemonize(app=f"forwarder {src_port}->{dst_port}", pid=pid_file.name, action=forwarder.start)
            daemon.start()
    else:
        forwarder.start()


@cli.command("list")
def usbmux_list(
    usbmux_address: Annotated[
        Optional[str],
        typer.Option(
            "--usbmux",
            help=USBMUX_OPTION_HELP,
        ),
    ] = None,
    usb: Annotated[
        bool,
        typer.Option(
            "--usb",
            "-u",
            help="show only USB devices",
        ),
    ] = False,
    network: Annotated[
        bool,
        typer.Option(
            "--network",
            "-n",
            help="show only network devices",
        ),
    ] = False,
) -> None:
    """List devices known to usbmuxd (USB and Wi-Fi)."""
    connected_devices = []
    for device in usbmux.list_devices(usbmux_address=usbmux_address):
        udid = device.serial

        if usb and not device.is_usb:
            continue

        if network and not device.is_network:
            continue

        lockdown = create_using_usbmux(
            udid, autopair=False, connection_type=device.connection_type, usbmux_address=usbmux_address
        )
        connected_devices.append(lockdown.short_info)

    print_json(connected_devices)
