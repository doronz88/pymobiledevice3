import asyncio
import dataclasses
import logging
import platform
import sys
import tempfile
from collections.abc import Awaitable
from contextlib import nullcontext
from functools import partial
from pathlib import Path
from typing import Annotated, Any, Callable, Optional, TextIO, Union

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remotepairing_manual_pairing
from pymobiledevice3.cli.cli_common import (
    OSUTILS,
    USBMUX_ENV_VARS,
    USBMUX_OPTION_HELP,
    RSDServiceProviderDep,
    async_command,
    default_transport_preference,
    print_json,
    prompt_device_list,
    sudo_required,
    user_requested_colored_output,
)
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import AccessDeniedError, NoDeviceConnectedError
from pymobiledevice3.pair_records import PAIRING_RECORD_EXT, get_remote_pairing_record_filename
from pymobiledevice3.remote.common import ConnectionType, TunnelProtocol
from pymobiledevice3.remote.module_imports import MAX_IDLE_TIMEOUT, start_tunnel, verify_tunnel_imports
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT
from pymobiledevice3.remote.tunnel_service import (
    CoreDeviceTunnelProxy,
    PairableHostInfo,
    RemotePairingManualPairingService,
    RemotePairingProtocol,
    get_core_device_tunnel_services,
    get_remote_pairing_tunnel_services,
    serve_pairable_host,
)
from pymobiledevice3.remote.utils import get_rsds
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS
from pymobiledevice3.tunneld.server import TunneldRunner, normalize_upstream_url
from pymobiledevice3.utils import run_in_loop

logger = logging.getLogger(__name__)

TUNNEL_SERVICE_DISCOVERY_ATTEMPTS = 3


async def browse_rsd(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
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


async def browse_remotepairing(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
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
    upstream: Annotated[
        Optional[list[str]],
        typer.Option(
            "--upstream",
            help="URL of another tunneld to federate (repeatable). Its devices appear in this "
            "instance's listing, and connections to them are relayed through it, so clients need "
            "a route to this tunneld only.",
        ),
    ] = None,
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
    usbmux_address: Annotated[
        Optional[str],
        typer.Option("--usbmux-address", envvar=USBMUX_ENV_VARS, help=USBMUX_OPTION_HELP),
    ] = None,
    mobdev2: Annotated[bool, typer.Option(help="Enable mobdev2 monitoring")] = True,
) -> None:
    """Start Tunneld service for remote tunneling"""
    if not verify_tunnel_imports():
        return
    for url in upstream or []:
        try:
            normalize_upstream_url(url)
        except ValueError as e:
            raise typer.BadParameter(str(e), param_hint="--upstream") from e
    tunneld_runner = partial(
        TunneldRunner.create,
        host,
        port,
        protocol=protocol,
        upstreams=upstream,
        usb_monitor=usb,
        wifi_monitor=wifi,
        usbmux_monitor=usbmux,
        usbmux_address=usbmux_address,
        mobdev2_monitor=mobdev2,
    )
    if daemonize:
        try:
            from daemonize import Daemonize
        except ImportError as e:
            raise NotImplementedError("daemonizing is only supported on unix platforms") from e
        bind = f"{host}:{port}"
        with tempfile.NamedTemporaryFile("wt") as pid_file:
            daemon = Daemonize(app=f"Tunneld {bind}", pid=pid_file.name, action=tunneld_runner)
            logger.info(f"starting Tunneld {bind}")
            daemon.start()
    else:
        tunneld_runner()


@cli.command("browse")
@async_command
async def browse(
    timeout: Annotated[float, typer.Option(help="Browse timeout (in seconds)")] = DEFAULT_BONJOUR_TIMEOUT,
    native: Annotated[
        Optional[bool],
        typer.Option(
            "--native/--no-native",
            help="Browse via Apple's remotepairingd (the remoted tunnel daemon) instead of bonjour; no root, "
            "macOS only, and the default there. --no-native forces the bonjour browse.",
        ),
    ] = None,
) -> None:
    """browse RemoteXPC devices (remotepairingd on macOS by default, bonjour elsewhere)"""
    if native is None:
        native = default_transport_preference() == "native"
    if native:
        from pymobiledevice3.remote.native_tunnel import browse_native_devices

        print_json(await browse_native_devices(timeout=timeout))
        return
    await cli_browse(timeout)


@cli.command("rsd-info")
def rsd_info(service_provider: RSDServiceProviderDep) -> None:
    """show info extracted from RSD peer"""
    print_json(service_provider.peer_info)


@cli.command("auxiliary-metadata")
def auxiliary_metadata(service_provider: RSDServiceProviderDep) -> None:
    """show device auxiliary metadata (decoded deviceKVSData), keyed by preference domain

    e.g. ``com.apple.WebInspector.EnableRemoteInspection`` (Web Inspector on/off). Reliably populated
    on the macOS ``--native`` transport; empty or partial on others (see the network-stacks guide).
    """
    print_json(service_provider.auxiliary_metadata)


async def tunnel_task(
    service: Union[RemotePairingProtocol, CoreDeviceTunnelProxy],
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
            print(f"{tunnel_result.address} {tunnel_result.port}", flush=True)
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
    get_tunnel_services: dict[ConnectionType, Callable[..., Awaitable[list[Any]]]] = {
        connection_type.USB: get_core_device_tunnel_services,
        connection_type.WIFI: get_remote_pairing_tunnel_services,
    }
    tunnel_services: list[Any] = []
    for attempt in range(TUNNEL_SERVICE_DISCOVERY_ATTEMPTS):
        tunnel_services = await get_tunnel_services[connection_type](udid=udid)
        if tunnel_services:
            break
        if attempt < TUNNEL_SERVICE_DISCOVERY_ATTEMPTS - 1:
            logger.info("No tunnel services discovered, trying again")
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


async def native_tunnel_task(udid: Optional[str] = None, script_mode: bool = False) -> None:
    # establish_native_rsd holds the tunnel assertion for the process lifetime and releases it at
    # interpreter exit; the RSD address is kernel-routable (Apple's tunnel), so other processes can
    # use the printed --rsd directly.
    from pymobiledevice3.remote.native_tunnel import establish_native_rsd

    rsd = await establish_native_rsd(serial=udid)
    address, port = rsd.service.address
    logger.info("native tunnel is up")
    if script_mode:
        print(f"{address} {port}", flush=True)
    else:
        if user_requested_colored_output():
            print(typer.style("Identifier: ", bold=True, fg="yellow") + typer.style(rsd.udid, bold=True, fg="white"))
            print(typer.style("RSD Address: ", bold=True, fg="yellow") + typer.style(address, bold=True, fg="white"))
            print(typer.style("RSD Port: ", bold=True, fg="yellow") + typer.style(str(port), bold=True, fg="white"))
            print(
                typer.style("Use the follow connection option:\n", bold=True, fg="yellow")
                + typer.style(f"--rsd {address} {port}", bold=True, fg="cyan")
            )
        else:
            print(f"Identifier: {rsd.udid}")
            print(f"RSD Address: {address}")
            print(f"RSD Port: {port}")
            print(f"Use the follow connection option:\n--rsd {address} {port}")
    sys.stdout.flush()
    await asyncio.Event().wait()  # hold the assertion until Ctrl-C


@cli.command("start-tunnel")
@async_command
async def cli_start_tunnel(
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
        Optional[float],
        typer.Option(
            show_default=str(MAX_IDLE_TIMEOUT),
            help="Maximum idle time before QUIC keepalive pings are sent.",
        ),
    ] = None,
    protocol: Annotated[
        Optional[TunnelProtocol],
        typer.Option(
            "--protocol",
            "-p",
            case_sensitive=False,
            show_default="TCP on Python >=3.13, otherwise QUIC",
            help="Transport protocol for the tunnel.",
        ),
    ] = None,
    native: Annotated[
        Optional[bool],
        typer.Option(
            "--native/--no-native",
            help="Piggyback Apple's remoted tunnel via remotepairingd and publish its RSD address instead of "
            "creating a new tunnel; no root, macOS only, and the default there. --no-native forces the "
            "classic (root) tunnel, as does passing any of the classic-tunnel options.",
        ),
    ] = None,
) -> None:
    """start tunnel (Apple's native tunnel on macOS by default — no root; classic tunnel elsewhere)"""
    # Detect explicitly-passed classic-tunnel options via sentinel Nones rather than value-vs-default
    # (TunnelProtocol.DEFAULT is version-dependent -- QUIC on Python <3.13, TCP otherwise -- so a
    # value comparison cannot tell an explicit `--protocol quic` on 3.12 from the default).
    classic_options = [
        name
        for name, is_set in (
            ("--connection-type", connection_type is not ConnectionType.USB),
            ("--secrets", secrets is not None),
            ("--protocol", protocol is not None),
            ("--max-idle-timeout", max_idle_timeout is not None),
        )
        if is_set
    ]
    if native is None:
        # Auto: native on macOS (unless PYMOBILEDEVICE3_DEFAULT_FALLBACK opts out of it); an option
        # that shapes a new tunnel implies the classic path -- those options don't apply to Apple's
        # already-existing tunnel.
        prefers_native = default_transport_preference() == "native"
        native = prefers_native and not classic_options
        if prefers_native and classic_options:
            # Make the divert visible: the classic path needs root, and the user did not ask for it.
            logger.info(
                "%s only applies to the classic tunnel, so using it instead of the no-root native "
                "default (this requires root; drop the option, or pass --native, for the no-root tunnel).",
                ", ".join(classic_options),
            )
    if native:
        if classic_options:
            # Explicit --native: fail loud rather than silently ignore an inapplicable option.
            if connection_type is not ConnectionType.USB:
                raise typer.BadParameter("--connection-type cannot be combined with --native (select with --udid)")
            if secrets is not None:
                raise typer.BadParameter("--secrets cannot be combined with --native")
            if protocol is not None:
                raise typer.BadParameter("--protocol cannot be combined with --native")
            raise typer.BadParameter("--max-idle-timeout cannot be combined with --native")
        await native_tunnel_task(udid, script_mode=script_mode)
        return
    if not OSUTILS.is_admin:
        raise AccessDeniedError()
    if not verify_tunnel_imports():
        return
    with secrets.open("wt") if secrets is not None else nullcontext() as secrets_file:
        await start_tunnel_task(
            connection_type,
            secrets_file,
            udid,
            script_mode,
            max_idle_timeout=MAX_IDLE_TIMEOUT if max_idle_timeout is None else max_idle_timeout,
            protocol=protocol if protocol is not None else TunnelProtocol.DEFAULT,
        )


@dataclasses.dataclass
class RemotePairingManualPairingDevice:
    ip: str
    port: int
    device_name: str
    identifier: str


@cli.command("pair")
@async_command
async def cli_pair(
    name: Annotated[
        Optional[str],
        typer.Option(help="Device name for a specific device to look for"),
    ] = None,
) -> None:
    """start remote pairing for devices which allow"""
    if start_tunnel is None:
        raise NotImplementedError("failed to start the tunnel on your platform")

    devices: list[RemotePairingManualPairingDevice] = []
    for answer in await browse_remotepairing_manual_pairing():
        current_device_name = answer.properties["name"]

        if name is not None and current_device_name != name:
            continue

        for address in answer.addresses:
            devices.append(
                RemotePairingManualPairingDevice(
                    ip=address.full_ip,
                    port=answer.port,
                    device_name=current_device_name,
                    identifier=answer.properties["identifier"],
                )
            )

    if len(devices) > 0:
        device = prompt_device_list(devices)
    else:
        logger.error("No devices were found during bonjour browse")
        return

    async with RemotePairingManualPairingService(device.identifier, device.ip, device.port) as service:
        await service.connect(autopair=True)


@cli.command("pair-host")
@async_command
async def cli_pair_host(
    name: Annotated[
        Optional[str],
        typer.Option(help="Name shown on the device (defaults to this machine's hostname)"),
    ] = None,
    model: Annotated[
        str,
        typer.Option(help="Hardware model identifier shown on the device"),
    ] = "Mac17,7",
    port: Annotated[
        int,
        typer.Option(help="TCP port to listen on (0 = pick a free port)"),
    ] = 0,
    timeout: Annotated[
        Optional[float],
        typer.Option(help="Give up after this many seconds if no device starts pairing"),
    ] = None,
) -> None:
    """
    Advertise as a pairable host and accept a device-initiated pairing (iOS 27+).

    The device does not browse for pairable hosts automatically. On the device, enable
    Developer Mode and open Settings > Developer > Paired Macs; this host then appears
    under "Other Devices". Tap it and enter the 6-digit code printed here. The resulting
    pairing record is reused by `remote start-tunnel` afterwards.
    """
    host_info = PairableHostInfo(name=name or platform.node(), model=model)

    def pin_callback(pin: str) -> None:
        typer.echo(typer.style(f"\n  Enter this code on your device: {pin}\n", bold=True, fg="green"))

    def waiting_callback(elapsed: float) -> None:
        typer.echo(typer.style(f"  …still waiting ({int(elapsed)}s) — no device has started pairing yet", fg="cyan"))

    typer.echo(
        typer.style("Advertising as ", fg="yellow")
        + typer.style(f'"{host_info.name}" ({host_info.model})', bold=True, fg="white")
        + typer.style(f" identifier={host_info.identifier}", fg="yellow")
    )
    # The device does NOT browse for pairable hosts on its own — nothing happens until the
    # user opens the device-side screen that starts the browse. Spell out the steps.
    typer.echo(
        typer.style("On the device, to make this host appear and pair:\n", bold=True, fg="yellow")
        + "  1. Enable Developer Mode: Settings > Privacy & Security > Developer Mode (reboot if asked).\n"
        + "  2. Make sure the device is on the same Wi-Fi network as this computer.\n"
        + '  3. Open Settings > Developer > Paired Macs. This host appears under "Other Devices".\n'
        + "  4. Tap it, choose Pair, and enter the 6-digit code shown below when prompted.\n"
        + "  (Repeated failed attempts get throttled by the device — wait a bit if pairing stops responding.)"
    )
    typer.echo("Waiting for a device to connect and start pairing (Ctrl-C to stop)...")

    try:
        result = await serve_pairable_host(
            host_info, port=port, pin_callback=pin_callback, timeout=timeout, waiting_callback=waiting_callback
        )
    except asyncio.TimeoutError:
        typer.echo(
            typer.style(
                f"\nTimed out after {timeout:g}s with no device-initiated pairing. "
                "Make sure you opened Settings > Developer > Paired Macs on the device (Developer Mode "
                "must be on) — the device only browses for this host while that screen is open.",
                fg="red",
            )
        )
        raise typer.Exit(code=1) from None

    typer.echo(typer.style("\nPaired with device:", bold=True, fg="green"))
    typer.echo(f"  name:  {result.peer_device.name}")
    typer.echo(f"  model: {result.peer_device.model}")
    typer.echo(f"  udid:  {result.peer_device.udid}")
    typer.echo(f"\nPairing record written to {result.record_path}")


@cli.command("delete-pair")
def cli_delete_pair(udid: str) -> None:
    """Delete a pairing record"""
    pair_record_path = get_home_folder() / f"{get_remote_pairing_record_filename(udid)}.{PAIRING_RECORD_EXT}"
    pair_record_path.unlink()


@cli.command("service")
def cli_service(service_provider: RSDServiceProviderDep, service_name: str) -> None:
    """Start an ipython shell for interacting with given service"""
    service = service_provider.start_remote_service(service_name)
    run_in_loop(service.connect())
    service.shell()
