import asyncio
import logging
import os
from typing import Optional

import click
from cryptography.hazmat.primitives.asymmetric import rsa

from pymobiledevice3.cli.cli_common import UDID_ENV_VAR, print_json, prompt_device_list, set_verbosity
from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.remote.core_device_tunnel_service import create_core_device_tunnel_service
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService, \
    get_remoted_device, get_remoted_devices

logger = logging.getLogger(__name__)


class RemoteCommand(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('hostname', '--udid'), envvar=UDID_ENV_VAR, callback=self.udid,
                         help=f'Device unique identifier. You may pass {UDID_ENV_VAR} environment variable to pass this'
                              f' option as well'),
            click.Option(('verbosity', '-v', '--verbose'), count=True, callback=set_verbosity, expose_value=False),
        ]

    @staticmethod
    def udid(ctx, param: str, value: str) -> Optional[str]:
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return

        if value is not None:
            return get_remoted_device(udid=value).hostname

        device_options = get_remoted_devices()
        if len(device_options) == 0:
            raise NoDeviceConnectedError()
        elif len(device_options) == 1:
            return device_options[0].hostname

        return prompt_device_list(device_options).hostname


@click.group()
def cli():
    """ remote cli """
    pass


@cli.group('remote')
def remote_cli():
    """ remote options """
    pass


@remote_cli.command('rsd-info', cls=RemoteCommand)
@click.option('--color/--no-color', default=True)
def rsd_info(hostname: str, color: bool):
    """ show info extracted from RSD peer """
    with RemoteServiceDiscoveryService((hostname, RSD_PORT)) as rsd:
        print_json(rsd.peer_info, colored=color)


@remote_cli.command('create-listener', cls=RemoteCommand)
@click.option('-p', '--protocol', type=click.Choice(['quic', 'udp']))
@click.option('--color/--no-color', default=True)
def create_listener(hostname: str, protocol: str, color: bool):
    """ start a remote listener """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with RemoteServiceDiscoveryService((hostname, RSD_PORT)) as rsd:
        with create_core_device_tunnel_service(rsd, autopair=True) as service:
            print_json(service.create_listener(private_key, protocol=protocol), colored=color)


@remote_cli.command('start-quic-tunnel', cls=RemoteCommand)
@click.option('--color/--no-color', default=True)
def start_quic_tunnel(hostname: str, color: bool):
    """ start quic tunnel """
    logger.critical('This is a WIP command. Will only print the required parameters for the quic connection')
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with RemoteServiceDiscoveryService((hostname, RSD_PORT)) as rsd:
        with create_core_device_tunnel_service(rsd, autopair=True) as service:
            print_json(asyncio.run(service.start_quic_tunnel(private_key)), colored=color)
