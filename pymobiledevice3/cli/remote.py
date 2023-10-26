import asyncio
import logging
from typing import List, TextIO

import click

from pymobiledevice3.cli.cli_common import RSDCommand, print_json, prompt_device_list
from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.remote.bonjour import get_remoted_addresses
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService
from pymobiledevice3.remote.utils import stop_remoted

logger = logging.getLogger(__name__)

try:
    from pymobiledevice3.remote.core_device_tunnel_service import start_quic_tunnel
except ImportError:
    start_quic_tunnel = None
    logger.warning(
        'start_quic_tunnel failed to be imported. Some feature may not work.\n'
        'You can debug this by trying the import yourself:\n\n'
        'from pymobiledevice3.remote.core_device_tunnel_service import create_core_device_tunnel_service')


def get_device_list() -> List[RemoteServiceDiscoveryService]:
    result = []
    with stop_remoted():
        for address in get_remoted_addresses():
            rsd = RemoteServiceDiscoveryService((address, RSD_PORT))
            try:
                rsd.connect()
            except ConnectionRefusedError:
                continue
            result.append(rsd)
    return result


@click.group()
def cli():
    """ remote cli """
    pass


@cli.group('remote')
def remote_cli():
    """ remote options """
    pass


@remote_cli.command('browse')
@click.option('--color/--no-color', default=True)
def browse(color: bool):
    """ browse devices using bonjour """
    devices = []
    for rsd in get_device_list():
        devices.append({'address': rsd.service.address[0],
                        'port': RSD_PORT,
                        'UniqueDeviceID': rsd.peer_info['Properties']['UniqueDeviceID'],
                        'ProductType': rsd.peer_info['Properties']['ProductType'],
                        'OSVersion': rsd.peer_info['Properties']['OSVersion']})
    print_json(devices, colored=color)


@remote_cli.command('rsd-info', cls=RSDCommand)
@click.option('--color/--no-color', default=True)
def rsd_info(service_provider: RemoteServiceDiscoveryService, color: bool):
    """ show info extracted from RSD peer """
    print_json(service_provider.peer_info, colored=color)


async def tunnel_task(service_provider: RemoteServiceDiscoveryService, secrets: TextIO,
                      script_mode: bool = False) -> None:
    if start_quic_tunnel is None:
        raise NotImplementedError('failed to start the QUIC tunnel on your platform')

    async with start_quic_tunnel(service_provider, secrets=secrets) as tunnel_result:
        if script_mode:
            print(f'{tunnel_result.address} {tunnel_result.port}')
        else:
            if secrets is not None:
                print(click.style('Secrets: ', bold=True, fg='magenta') +
                      click.style(secrets.name, bold=True, fg='white'))
            print(click.style('UDID: ', bold=True, fg='yellow') +
                  click.style(service_provider.udid, bold=True, fg='white'))
            print(click.style('ProductType: ', bold=True, fg='yellow') +
                  click.style(service_provider.product_type, bold=True, fg='white'))
            print(click.style('ProductVersion: ', bold=True, fg='yellow') +
                  click.style(service_provider.product_version, bold=True, fg='white'))
            print(click.style('Interface: ', bold=True, fg='yellow') +
                  click.style(tunnel_result.interface, bold=True, fg='white'))
            print(click.style('RSD Address: ', bold=True, fg='yellow') +
                  click.style(tunnel_result.address, bold=True, fg='white'))
            print(click.style('RSD Port: ', bold=True, fg='yellow') +
                  click.style(tunnel_result.port, bold=True, fg='white'))
            print(click.style('Use the follow connection option:\n', bold=True, fg='yellow') +
                  click.style(f'--rsd {tunnel_result.address} {tunnel_result.port}', bold=True, fg='cyan'))

        while True:
            # wait user input while the asyncio tasks execute
            await asyncio.sleep(.5)


@remote_cli.command('start-quic-tunnel')
@click.option('--udid', help='UDID for a specific device to look for')
@click.option('--secrets', type=click.File('wt'), help='TLS keyfile for decrypting with Wireshark')
@click.option('--script-mode', is_flag=True,
              help='Show only HOST and port number to allow easy parsing from external shell scripts')
def cli_start_quic_tunnel(udid: str, secrets: TextIO, script_mode: bool):
    """ start quic tunnel """
    devices = get_device_list()
    if not devices:
        # no devices were found
        raise NoDeviceConnectedError()
    if len(devices) == 1:
        # only one device found
        rsd = devices[0]
    else:
        # several devices were found
        if udid is None:
            # show prompt if non explicitly selected
            rsd = prompt_device_list(devices)
        else:
            rsd = [device for device in devices if device.udid == udid]
            if len(rsd) > 0:
                rsd = rsd[0]
            else:
                raise NoDeviceConnectedError()

    if udid is not None and rsd.udid != udid:
        raise NoDeviceConnectedError()

    try:
        asyncio.run(tunnel_task(rsd, secrets, script_mode), debug=True)
    except RuntimeError:
        pass


@remote_cli.command('service', cls=RSDCommand)
@click.argument('service_name')
def cli_service(service_provider: RemoteServiceDiscoveryService, service_name: str):
    """ start an ipython shell for interacting with given service """
    with service_provider.start_remote_service(service_name) as service:
        service.shell()
