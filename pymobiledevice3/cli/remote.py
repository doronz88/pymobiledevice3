import asyncio
import logging

import click
from cryptography.hazmat.primitives.asymmetric import rsa

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.remote.core_device_tunnel_service import create_core_device_tunnel_service
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ remote cli """
    pass


@cli.group('remote')
def remote_cli():
    """ remote options """
    pass


@remote_cli.command('rsd-info', cls=Command)
@click.option('--color/--no-color', default=True)
def rsd_info(service_provider: RemoteServiceDiscoveryService, color: bool):
    """ show info extracted from RSD peer """
    print_json(service_provider.peer_info, colored=color)


@remote_cli.command('create-listener', cls=Command)
@click.option('-p', '--protocol', type=click.Choice(['quic', 'udp']))
@click.option('--color/--no-color', default=True)
def create_listener(service_provider: RemoteServiceDiscoveryService, protocol: str, color: bool):
    """ start a remote listener """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with create_core_device_tunnel_service(service_provider, autopair=True) as service:
        print_json(service.create_listener(private_key, protocol=protocol), colored=color)


@remote_cli.command('start-quic-tunnel', cls=Command)
@click.option('--color/--no-color', default=True)
def start_quic_tunnel(service_provider: RemoteServiceDiscoveryService, color: bool):
    """ start quic tunnel """
    logger.critical('This is a WIP command. Will only print the required parameters for the quic connection')
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with create_core_device_tunnel_service(service_provider, autopair=True) as service:
        print_json(asyncio.run(service.start_quic_tunnel(private_key)), colored=color)
