import asyncio
import dataclasses
import logging
import sys
import tempfile
from functools import partial
from typing import List, Mapping, Optional, TextIO

import click

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remotepairing_manual_pairing
from pymobiledevice3.cli.cli_common import BaseCommand, RSDCommand, print_json, prompt_device_list, sudo_required, \
    user_requested_colored_output
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.pair_records import PAIRING_RECORD_EXT, get_remote_pairing_record_filename
from pymobiledevice3.remote.common import ConnectionType, TunnelProtocol
from pymobiledevice3.remote.module_imports import MAX_IDLE_TIMEOUT, start_tunnel, verify_tunnel_imports
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService
from pymobiledevice3.remote.tunnel_service import RemotePairingManualPairingService, get_core_device_tunnel_services, \
    get_remote_pairing_tunnel_services
from pymobiledevice3.remote.utils import get_rsds
from pymobiledevice3.tunneld import TUNNELD_DEFAULT_ADDRESS, TunneldRunner

logger = logging.getLogger(__name__)


async def browse_rsd(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[Mapping]:
    devices = []
    for rsd in await get_rsds(timeout):
        devices.append({'address': rsd.service.address[0],
                        'port': RSD_PORT,
                        'UniqueDeviceID': rsd.peer_info['Properties']['UniqueDeviceID'],
                        'ProductType': rsd.peer_info['Properties']['ProductType'],
                        'OSVersion': rsd.peer_info['Properties']['OSVersion']})
    return devices


async def browse_remotepairing(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[Mapping]:
    devices = []
    for remotepairing in await get_remote_pairing_tunnel_services(timeout):
        devices.append({'address': remotepairing.hostname,
                        'port': remotepairing.port,
                        'identifier': remotepairing.remote_identifier})
    return devices


async def cli_browse(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> None:
    print_json({
        'usb': await browse_rsd(timeout),
        'wifi': await browse_remotepairing(timeout),
    })


@click.group()
def cli() -> None:
    pass


@cli.group('remote')
def remote_cli() -> None:
    """ Create RemoteXPC tunnels """
    pass


@remote_cli.command('tunneld', cls=BaseCommand)
@click.option('--host', default=TUNNELD_DEFAULT_ADDRESS[0])
@click.option('--port', type=click.INT, default=TUNNELD_DEFAULT_ADDRESS[1])
@click.option('-d', '--daemonize', is_flag=True)
@click.option('-p', '--protocol', type=click.Choice([e.value for e in TunnelProtocol]),
              default=TunnelProtocol.QUIC.value)
@click.option('--usb/--no-usb', default=True, help='Enable usb monitoring')
@click.option('--wifi/--no-wifi', default=True, help='Enable wifi monitoring')
@click.option('--usbmux/--no-usbmux', default=True, help='Enable usbmux monitoring')
@click.option('--mobdev2/--no-mobdev2', default=True, help='Enable mobdev2 monitoring')
@sudo_required
def cli_tunneld(
        host: str, port: int, daemonize: bool, protocol: str, usb: bool, wifi: bool, usbmux: bool,
        mobdev2: bool) -> None:
    """ Start Tunneld service for remote tunneling """
    if not verify_tunnel_imports():
        return
    protocol = TunnelProtocol(protocol)
    tunneld_runner = partial(TunneldRunner.create, host, port, protocol=protocol, usb_monitor=usb, wifi_monitor=wifi,
                             usbmux_monitor=usbmux, mobdev2_monitor=mobdev2)
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


@remote_cli.command('browse', cls=BaseCommand)
@click.option('--timeout', type=click.FLOAT, default=DEFAULT_BONJOUR_TIMEOUT, help='Bonjour timeout (in seconds)')
def browse(timeout: float) -> None:
    """ browse RemoteXPC devices using bonjour """
    asyncio.run(cli_browse(timeout), debug=True)


@remote_cli.command('rsd-info', cls=RSDCommand)
def rsd_info(service_provider: RemoteServiceDiscoveryService):
    """ show info extracted from RSD peer """
    print_json(service_provider.peer_info)


async def tunnel_task(
        service, secrets: Optional[TextIO] = None, script_mode: bool = False,
        max_idle_timeout: float = MAX_IDLE_TIMEOUT, protocol: TunnelProtocol = TunnelProtocol.QUIC) -> None:
    async with start_tunnel(
            service, secrets=secrets, max_idle_timeout=max_idle_timeout, protocol=protocol) as tunnel_result:
        logger.info('tunnel created')
        if script_mode:
            print(f'{tunnel_result.address} {tunnel_result.port}')
        else:
            if user_requested_colored_output():
                if secrets is not None:
                    print(click.style('Secrets: ', bold=True, fg='magenta') +
                          click.style(secrets.name, bold=True, fg='white'))
                print(click.style('Identifier: ', bold=True, fg='yellow') +
                      click.style(service.remote_identifier, bold=True, fg='white'))
                print(click.style('Interface: ', bold=True, fg='yellow') +
                      click.style(tunnel_result.interface, bold=True, fg='white'))
                print(click.style('Protocol: ', bold=True, fg='yellow') +
                      click.style(tunnel_result.protocol, bold=True, fg='white'))
                print(click.style('RSD Address: ', bold=True, fg='yellow') +
                      click.style(tunnel_result.address, bold=True, fg='white'))
                print(click.style('RSD Port: ', bold=True, fg='yellow') +
                      click.style(tunnel_result.port, bold=True, fg='white'))
                print(click.style('Use the follow connection option:\n', bold=True, fg='yellow') +
                      click.style(f'--rsd {tunnel_result.address} {tunnel_result.port}', bold=True, fg='cyan'))
            else:
                if secrets is not None:
                    print(f'Secrets: {secrets.name}')
                print(f'Identifier: {service.remote_identifier}')
                print(f'Interface: {tunnel_result.interface}')
                print(f'Protocol: {tunnel_result.protocol}')
                print(f'RSD Address: {tunnel_result.address}')
                print(f'RSD Port: {tunnel_result.port}')
                print(f'Use the follow connection option:\n'
                      f'--rsd {tunnel_result.address} {tunnel_result.port}')
        sys.stdout.flush()
        await tunnel_result.client.wait_closed()
        logger.info('tunnel was closed')


async def start_tunnel_task(
        connection_type: ConnectionType, secrets: TextIO, udid: Optional[str] = None, script_mode: bool = False,
        max_idle_timeout: float = MAX_IDLE_TIMEOUT, protocol: TunnelProtocol = TunnelProtocol.QUIC) -> None:
    if start_tunnel is None:
        raise NotImplementedError('failed to start the tunnel on your platform')
    get_tunnel_services = {
        connection_type.USB: get_core_device_tunnel_services,
        connection_type.WIFI: get_remote_pairing_tunnel_services,
    }
    tunnel_services = await get_tunnel_services[connection_type](udid=udid)
    if not tunnel_services:
        # no devices were found
        raise NoDeviceConnectedError()
    if len(tunnel_services) == 1 or udid is not None:
        # only one device found
        service = tunnel_services[0]
    else:
        # several devices were found, show prompt if none explicitly selected
        service = prompt_device_list(tunnel_services)

    await tunnel_task(service, secrets=secrets, script_mode=script_mode, max_idle_timeout=max_idle_timeout,
                      protocol=protocol)


@remote_cli.command('start-tunnel', cls=BaseCommand)
@click.option('-t', '--connection-type', type=click.Choice([e.value for e in ConnectionType], case_sensitive=False),
              default=ConnectionType.USB.value)
@click.option('--udid', help='UDID for a specific device to look for')
@click.option('--secrets', type=click.File('wt'), help='TLS keyfile for decrypting with Wireshark')
@click.option('--script-mode', is_flag=True,
              help='Show only HOST and port number to allow easy parsing from external shell scripts')
@click.option('--max-idle-timeout', type=click.FLOAT, default=MAX_IDLE_TIMEOUT,
              help='Maximum QUIC idle time (ping interval)')
@click.option('-p', '--protocol',
              type=click.Choice([e.value for e in TunnelProtocol], case_sensitive=False),
              default=TunnelProtocol.QUIC.value)
@sudo_required
def cli_start_tunnel(
        connection_type: ConnectionType, udid: Optional[str], secrets: TextIO, script_mode: bool,
        max_idle_timeout: float, protocol: str) -> None:
    """ start tunnel """
    if not verify_tunnel_imports():
        return
    asyncio.run(
        start_tunnel_task(
            ConnectionType(connection_type), secrets, udid, script_mode, max_idle_timeout=max_idle_timeout,
            protocol=TunnelProtocol(protocol)), debug=True)


@dataclasses.dataclass
class RemotePairingManualPairingDevice:
    ip: str
    port: int
    device_name: str
    identifier: str


async def start_remote_pair_task(device_name: str) -> None:
    if start_tunnel is None:
        raise NotImplementedError('failed to start the tunnel on your platform')

    devices: List[RemotePairingManualPairingDevice] = []
    for answer in await browse_remotepairing_manual_pairing():
        current_device_name = answer.properties[b'name'].decode()

        if device_name is not None and current_device_name != device_name:
            continue

        for ip in answer.ips:
            devices.append(RemotePairingManualPairingDevice(ip=ip, port=answer.port, device_name=current_device_name,
                                                            identifier=answer.properties[b'identifier'].decode()))

    if len(devices) > 0:
        device = prompt_device_list(devices)
    else:
        logger.error('No devices were found during bonjour browse')
        return

    async with RemotePairingManualPairingService(device.identifier, device.ip, device.port) as service:
        await service.connect(autopair=True)


@remote_cli.command('pair', cls=BaseCommand)
@click.option('--name', help='Device name for a specific device to look for')
def cli_pair(name: Optional[str]) -> None:
    """ start remote pairing for devices which allow """
    asyncio.run(start_remote_pair_task(name), debug=True)


@remote_cli.command('delete-pair', cls=BaseCommand)
@click.argument('udid')
@sudo_required
def cli_delete_pair(udid: str):
    """ delete a pairing record """
    pair_record_path = get_home_folder() / f'{get_remote_pairing_record_filename(udid)}.{PAIRING_RECORD_EXT}'
    pair_record_path.unlink()


async def cli_service_task(service_provider: RemoteServiceDiscoveryService, service_name: str) -> None:
    async with service_provider.start_remote_service(service_name) as service:
        service.shell()


@remote_cli.command('service', cls=RSDCommand)
@click.argument('service_name')
def cli_service(service_provider: RemoteServiceDiscoveryService, service_name: str) -> None:
    """ start an ipython shell for interacting with given service """
    asyncio.run(cli_service_task(service_provider, service_name), debug=True)
