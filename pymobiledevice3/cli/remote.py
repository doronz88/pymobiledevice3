import asyncio
import dataclasses
import logging
import sys
import tempfile
from contextlib import nullcontext
from functools import partial
from pathlib import Path
from typing import Annotated, Optional, TextIO

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remotepairing_manual_pairing
from pymobiledevice3.cli.cli_common import (
    RSDServiceProviderDep,
    print_json,
    prompt_device_list,
    sudo_required,
    user_requested_colored_output,
)
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.pair_records import PAIRING_RECORD_EXT, get_remote_pairing_record_filename
from pymobiledevice3.remote.common import ConnectionType, TunnelProtocol
from pymobiledevice3.remote.module_imports import MAX_IDLE_TIMEOUT, start_tunnel, verify_tunnel_imports
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService
from pymobiledevice3.remote.tunnel_service import (
    RemotePairingManualPairingService,
    get_core_device_tunnel_services,
    get_remote_pairing_tunnel_services,
)
from pymobiledevice3.remote.utils import get_rsds
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS
from pymobiledevice3.tunneld.server import TunneldRunner

logger = logging.getLogger(__name__)


async def browse_rsd(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[dict]:
    devices = []
    for rsd in await get_rsds(timeout):
        assert rsd.peer_info is not None
        devices.append({
            "address": rsd.service.address[0],
            "port": RSD_PORT,
            "UniqueDeviceID": rsd.peer_info["Properties"]["UniqueDeviceID"],
            "ProductType": rsd.peer_info["Properties"]["ProductType"],
            "OSVersion": rsd.peer_info["Properties"]["OSVersion"],
        })
    return devices


async def browse_remotepairing(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[dict]:
    devices = []
    for remotepairing in await get_remote_pairing_tunnel_services(timeout):
        devices.append({
            "address": remotepairing.hostname,
            "port": remotepairing.port,
            "identifier": remotepairing.remote_identifier,
        })
    return devices


async def cli_browse(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> None:
    print_json({
        "usb": await browse_rsd(timeout),
        "wifi": await browse_remotepairing(timeout),
    })


cli = InjectingTyper(
    name="remote",
    help="Create and browse RemoteXPC tunnels (RSD/tunneld) for developer services.",
    no_args_is_help=True,
)


@cli.command("tunneld")
@sudo_required
def cli_tunneld(
    host: Annotated[str, typer.Option(help="Address to bind the tunneld server to.")] = TUNNELD_DEFAULT_ADDRESS[0],
    port: Annotated[int, typer.Option(help="Port to bind the tunneld server to.")] = TUNNELD_DEFAULT_ADDRESS[1],
    daemonize: Annotated[bool, typer.Option("--daemonize", "-d", help="Run tunneld in the background.")] = False,
    protocol: Annotated[
        TunnelProtocol,
        typer.Option(
            "--protocol",
            "-p",
            case_sensitive=False,
            help="Transport protocol for tunneld (default: TCP on Python >=3.13, otherwise QUIC).",
        ),
    ] = TunnelProtocol.DEFAULT,
    usb: Annotated[bool, typer.Option(help="Enable USB monitoring")] = True,
    wifi: Annotated[bool, typer.Option(help="Enable WiFi monitoring")] = True,
    usbmux: Annotated[bool, typer.Option(help="Enable usbmux monitoring")] = True,
    mobdev2: Annotated[bool, typer.Option(help="Enable mobdev2 monitoring")] = True,
) -> None:
    """Start Tunneld service for remote tunneling"""
    if not verify_tunnel_imports():
        return
    tunneld_runner = partial(
        TunneldRunner.create,
        host,
        port,
        protocol=protocol,
        usb_monitor=usb,
        wifi_monitor=wifi,
        usbmux_monitor=usbmux,
        mobdev2_monitor=mobdev2,
    )
    if daemonize:
        try:
            from daemonize import Daemonize
        except ImportError as e:
            raise NotImplementedError("daemonizing is only supported on unix platforms") from e
        with tempfile.NamedTemporaryFile("wt") as pid_file:
            daemon = Daemonize(app=f"Tunneld {host}:{port}", pid=pid_file.name, action=tunneld_runner)
            logger.info(f"starting Tunneld {host}:{port}")
            daemon.start()
    else:
        tunneld_runner()


@cli.command("browse")
def browse(
    timeout: Annotated[float, typer.Option(help="Bonjour timeout (in seconds)")] = DEFAULT_BONJOUR_TIMEOUT,
) -> None:
    """browse RemoteXPC devices using bonjour"""
    asyncio.run(cli_browse(timeout), debug=True)


@cli.command("rsd-info")
def rsd_info(service_provider: RSDServiceProviderDep) -> None:
    """show info extracted from RSD peer"""
    print_json(service_provider.peer_info)


async def tunnel_task(
    service,
    secrets: Optional[TextIO] = None,
    script_mode: bool = False,
    max_idle_timeout: float = MAX_IDLE_TIMEOUT,
    protocol: TunnelProtocol = TunnelProtocol.DEFAULT,
) -> None:
    async with start_tunnel(
        service, secrets=secrets, max_idle_timeout=max_idle_timeout, protocol=protocol
    ) as tunnel_result:
        logger.info("tunnel created")
        if script_mode:
            print(f"{tunnel_result.address} {tunnel_result.port}")
        else:
            if user_requested_colored_output():
                if secrets is not None:
                    print(
                        typer.style("Secrets: ", bold=True, fg="magenta")
                        + typer.style(secrets.name, bold=True, fg="white")
                    )
                print(
                    typer.style("Identifier: ", bold=True, fg="yellow")
                    + typer.style(service.remote_identifier, bold=True, fg="white")
                )
                print(
                    typer.style("Interface: ", bold=True, fg="yellow")
                    + typer.style(tunnel_result.interface, bold=True, fg="white")
                )
                print(
                    typer.style("Protocol: ", bold=True, fg="yellow")
                    + typer.style(tunnel_result.protocol, bold=True, fg="white")
                )
                print(
                    typer.style("RSD Address: ", bold=True, fg="yellow")
                    + typer.style(tunnel_result.address, bold=True, fg="white")
                )
                print(
                    typer.style("RSD Port: ", bold=True, fg="yellow")
                    + typer.style(tunnel_result.port, bold=True, fg="white")
                )
                print(
                    typer.style("Use the follow connection option:\n", bold=True, fg="yellow")
                    + typer.style(f"--rsd {tunnel_result.address} {tunnel_result.port}", bold=True, fg="cyan")
                )
            else:
                if secrets is not None:
                    print(f"Secrets: {secrets.name}")
                print(f"Identifier: {service.remote_identifier}")
                print(f"Interface: {tunnel_result.interface}")
                print(f"Protocol: {tunnel_result.protocol}")
                print(f"RSD Address: {tunnel_result.address}")
                print(f"RSD Port: {tunnel_result.port}")
                print(f"Use the follow connection option:\n--rsd {tunnel_result.address} {tunnel_result.port}")
        sys.stdout.flush()
        await tunnel_result.client.wait_closed()
        logger.info("tunnel was closed")


async def start_tunnel_task(
    connection_type: ConnectionType,
    secrets: Optional[TextIO],
    udid: Optional[str] = None,
    script_mode: bool = False,
    max_idle_timeout: float = MAX_IDLE_TIMEOUT,
    protocol: TunnelProtocol = TunnelProtocol.DEFAULT,
) -> None:
    if start_tunnel is None:
        raise NotImplementedError("failed to start the tunnel on your platform")
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

    await tunnel_task(
        service, secrets=secrets, script_mode=script_mode, max_idle_timeout=max_idle_timeout, protocol=protocol
    )


@cli.command("start-tunnel")
@sudo_required
def cli_start_tunnel(
    connection_type: Annotated[
        ConnectionType,
        typer.Option(
            "--connection-type",
            "-t",
            case_sensitive=False,
            help="Connection interface to tunnel (USB, WiFi, etc.).",
        ),
    ] = ConnectionType.USB,
    udid: Annotated[
        Optional[str],
        typer.Option(help="UDID for a specific device to look for"),
    ] = None,
    secrets: Annotated[
        Optional[Path],
        typer.Option(help="File to write TLS secrets for Wireshark decryption."),
    ] = None,
    script_mode: Annotated[
        bool,
        typer.Option(help="Print only HOST and port for scripts instead of formatted output."),
    ] = False,
    max_idle_timeout: Annotated[
        float,
        typer.Option(help="Maximum idle time before QUIC keepalive pings are sent."),
    ] = MAX_IDLE_TIMEOUT,
    protocol: Annotated[
        TunnelProtocol,
        typer.Option(
            "--protocol",
            "-p",
            case_sensitive=False,
            help="Transport protocol for the tunnel (default: TCP on Python >=3.13, otherwise QUIC).",
        ),
    ] = TunnelProtocol.DEFAULT,
) -> None:
    """start tunnel"""
    if not verify_tunnel_imports():
        return
    with secrets.open("wt") if secrets is not None else nullcontext() as secrets_file:
        asyncio.run(
            start_tunnel_task(
                connection_type,
                secrets_file,
                udid,
                script_mode,
                max_idle_timeout=max_idle_timeout,
                protocol=protocol,
            ),
            debug=True,
        )


@dataclasses.dataclass
class RemotePairingManualPairingDevice:
    ip: str
    port: int
    device_name: str
    identifier: str


async def start_remote_pair_task(device_name: Optional[str]) -> None:
    if start_tunnel is None:
        raise NotImplementedError("failed to start the tunnel on your platform")

    devices: list[RemotePairingManualPairingDevice] = []
    for answer in await browse_remotepairing_manual_pairing():
        current_device_name = answer.properties[b"name"].decode()

        if device_name is not None and current_device_name != device_name:
            continue

        for address in answer.addresses:
            devices.append(
                RemotePairingManualPairingDevice(
                    ip=address.full_ip,
                    port=answer.port,
                    device_name=current_device_name,
                    identifier=answer.properties[b"identifier"].decode(),
                )
            )

    if len(devices) > 0:
        device = prompt_device_list(devices)
    else:
        logger.error("No devices were found during bonjour browse")
        return

    async with RemotePairingManualPairingService(device.identifier, device.ip, device.port) as service:
        await service.connect(autopair=True)


@cli.command("pair")
def cli_pair(
    name: Annotated[
        Optional[str],
        typer.Option(help="Device name for a specific device to look for"),
    ] = None,
) -> None:
    """start remote pairing for devices which allow"""
    asyncio.run(start_remote_pair_task(name), debug=True)


@cli.command("delete-pair")
@sudo_required
def cli_delete_pair(udid: str) -> None:
    """delete a pairing record"""
    pair_record_path = get_home_folder() / f"{get_remote_pairing_record_filename(udid)}.{PAIRING_RECORD_EXT}"
    pair_record_path.unlink()


async def cli_service_task(service_provider: RemoteServiceDiscoveryService, service_name: str) -> None:
    async with service_provider.start_remote_service(service_name) as service:
        service.shell()


@cli.command("service")
def cli_service(service_provider: RSDServiceProviderDep, service_name: str) -> None:
    """start an ipython shell for interacting with given service"""
    asyncio.run(cli_service_task(service_provider, service_name), debug=True)
