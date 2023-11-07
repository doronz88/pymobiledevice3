import asyncio
import logging
import sys
import tempfile
from functools import partial
from typing import List, TextIO

import click

from pymobiledevice3.cli.cli_common import RSDCommand, print_json, prompt_device_list, sudo_required
from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.remote.bonjour import get_remoted_addresses
from pymobiledevice3.remote.module_imports import MAX_IDLE_TIMEOUT, start_quic_tunnel, verify_tunnel_imports
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService
from pymobiledevice3.remote.utils import TUNNELD_DEFAULT_ADDRESS, stop_remoted
from pymobiledevice3.tunneld import TunneldRunner

logger = logging.getLogger(__name__)


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


@remote_cli.command('tunneld')
@click.option('--host', default=TUNNELD_DEFAULT_ADDRESS[0])
@click.option('--port', type=click.INT, default=TUNNELD_DEFAULT_ADDRESS[1])
@click.option('-d', '--daemonize', is_flag=True)
@sudo_required
def cli_tunneld(host: str, port: int, daemonize: bool):
    """ Start Tunneld service for remote tunneling """
    if not verify_tunnel_imports():
        return
    tunneld_runner = partial(TunneldRunner.create, host, port)
    if daemonize:
        try:
            from daemonize import Daemonize
        except ImportError:
            raise NotImplementedError('daemonizing is only supported on unix platforms')
        with tempfile.NamedTemporaryFile('wt') as pid_file:
            daemon = Daemonize(app=f'Tunneld {host}:{port}', pid=pid_file.name,
                               action=tunneld_runner)
            logger.info(f'starting Tunneld {host}:{port}')
            daemon.start()
    else:
        tunneld_runner()


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


async def tunnel_task(
        service_provider: RemoteServiceDiscoveryService, secrets: TextIO,
        script_mode: bool = False, max_idle_timeout: float = MAX_IDLE_TIMEOUT) -> None:
    if start_quic_tunnel is None:
        raise NotImplementedError('failed to start the QUIC tunnel on your platform')

    async with start_quic_tunnel(service_provider, secrets=secrets, max_idle_timeout=max_idle_timeout) as tunnel_result:
        logger.info('tunnel created')
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
        sys.stdout.flush()

        await tunnel_result.client.wait_closed()
        logger.info('tunnel was closed')


@remote_cli.command('start-quic-tunnel')
@click.option('--udid', help='UDID for a specific device to look for')
@click.option('--secrets', type=click.File('wt'), help='TLS keyfile for decrypting with Wireshark')
@click.option('--script-mode', is_flag=True,
              help='Show only HOST and port number to allow easy parsing from external shell scripts')
@click.option('--max-idle-timeout', type=click.FLOAT, default=MAX_IDLE_TIMEOUT,
              help='Maximum QUIC idle time (ping interval)')
@sudo_required
def cli_start_quic_tunnel(udid: str, secrets: TextIO, script_mode: bool, max_idle_timeout: float):
    """ start quic tunnel """
    if not verify_tunnel_imports():
        return
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

    asyncio.run(tunnel_task(rsd, secrets, script_mode, max_idle_timeout=max_idle_timeout), debug=True)


@remote_cli.command('service', cls=RSDCommand)
@click.argument('service_name')
def cli_service(service_provider: RemoteServiceDiscoveryService, service_name: str):
    """ start an ipython shell for interacting with given service """
    with service_provider.start_remote_service(service_name) as service:
        service.shell()
