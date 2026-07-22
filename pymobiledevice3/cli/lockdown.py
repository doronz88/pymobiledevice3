import ast
import base64
import datetime
import logging
import plistlib
from pathlib import Path
from typing import Annotated, Literal, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    LockdownClientDep,
    NoAutoPairLockdownClientDep,
    ServiceProviderDep,
    async_command,
    print_json,
    sudo_required,
)
from pymobiledevice3.cli.remote import tunnel_task
from pymobiledevice3.exceptions import RemotePairingCompletedError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.tunnel_service import CoreDeviceTunnelProxy, RemotePairingLockdownService
from pymobiledevice3.services.heartbeat import HeartbeatService
from pymobiledevice3.utils import run_in_loop

logger = logging.getLogger(__name__)

cli = InjectingTyper(
    name="lockdown",
    help="Pair/Unpair device or access other lockdown services",
    no_args_is_help=True,
)


@cli.command("recovery")
@async_command
async def lockdown_recovery(service_provider: LockdownClientDep) -> None:
    """enter recovery"""
    print_json(await service_provider.enter_recovery())


@cli.command("service")
def lockdown_service(service_provider: ServiceProviderDep, service_name: str) -> None:
    """send-receive raw service messages with a given service name"""
    service = run_in_loop(service_provider.start_lockdown_service(service_name))
    try:
        service.shell()
    finally:
        run_in_loop(service.close())


@cli.command("developer-service")
def lockdown_developer_service(service_provider: ServiceProviderDep, service_name: str) -> None:
    """send-receive raw service messages with a given developer service name"""
    service = run_in_loop(service_provider.start_lockdown_developer_service(service_name))
    try:
        service.shell()
    finally:
        run_in_loop(service.close())


@cli.command("info")
def lockdown_info(service_provider: ServiceProviderDep) -> None:
    """query all lockdown values"""
    print_json(service_provider.all_values)


@cli.command("get")
@async_command
async def lockdown_get(
    service_provider: ServiceProviderDep, domain: Optional[str] = None, key: Optional[str] = None
) -> None:
    """query lockdown values by their domain and key names"""
    print_json(await service_provider.get_value(domain=domain, key=key))


@cli.command("set")
@async_command
async def lockdown_set(
    service_provider: ServiceProviderDep,
    value: str,
    domain: Optional[str] = None,
    key: Optional[str] = None,
) -> None:
    """set a lockdown value using python's ast.literal_eval()"""
    print_json(await service_provider.set_value(value=ast.literal_eval(value), domain=domain, key=key))


@cli.command("remove")
@async_command
async def lockdown_remove(service_provider: ServiceProviderDep, domain: str, key: str) -> None:
    """remove a domain/key pair"""
    print_json(await service_provider.remove_value(domain=domain, key=key))


@cli.command("unpair")
@async_command
async def lockdown_unpair(service_provider: NoAutoPairLockdownClientDep, host_id: Optional[str] = None) -> None:
    """unpair from connected device"""
    await service_provider.unpair(host_id=host_id)


@cli.command("pair")
@async_command
async def lockdown_pair(service_provider: NoAutoPairLockdownClientDep) -> None:
    """pair device"""
    await service_provider.pair()


@cli.command("pair-supervised")
@async_command
async def lockdown_pair_supervised(
    service_provider: NoAutoPairLockdownClientDep,
    keybag: Annotated[
        Path,
        typer.Argument(file_okay=True, dir_okay=False, exists=True),
    ],
) -> None:
    """pair supervised device"""
    await service_provider.pair_supervised(keybag)


@cli.command("save-pair-record")
def lockdown_save_pair_record(service_provider: NoAutoPairLockdownClientDep, output: Path) -> None:
    """save pair record to specified location"""
    if service_provider.pair_record is None:
        logger.error("no pairing record was found")
        return
    output.write_bytes(plistlib.dumps(service_provider.pair_record))


@cli.command("date")
@async_command
async def lockdown_date(service_provider: ServiceProviderDep) -> None:
    """get device date"""
    timestamp = await service_provider.get_value(key="TimeIntervalSince1970")
    print(datetime.datetime.fromtimestamp(timestamp))


@cli.command("heartbeat")
@async_command
async def lockdown_heartbeat(service_provider: ServiceProviderDep) -> None:
    """start heartbeat service"""
    await HeartbeatService(service_provider).start()


@cli.command("language")
@async_command
async def lockdown_language(
    service_provider: ServiceProviderDep, language: Annotated[Optional[str], typer.Argument()] = None
) -> None:
    """Get/Set current language settings"""
    if language is not None:
        await service_provider.set_language(language)
    print_json(await service_provider.get_language())


@cli.command("locale")
@async_command
async def lockdown_locale(
    service_provider: ServiceProviderDep, locale: Annotated[Optional[str], typer.Argument()] = None
) -> None:
    """Get/Set current language settings"""
    if locale is not None:
        await service_provider.set_locale(locale)
    print_json(await service_provider.get_locale())


@cli.command("device-name")
@async_command
async def lockdown_device_name(service_provider: ServiceProviderDep, new_name: Optional[str] = None) -> None:
    """get/set current device name"""
    if new_name:
        await service_provider.set_value(new_name, key="DeviceName")
    else:
        print(f"{await service_provider.get_value(key='DeviceName')}")


@cli.command("wifi-connections")
@async_command
async def lockdown_wifi_connections(
    service_provider: ServiceProviderDep, state: Optional[Literal["on", "off"]] = None
) -> None:
    """get/set wifi connections state"""
    if not state:
        # show current state
        print_json({"EnableWifiConnections": await service_provider.get_enable_wifi_connections()})
    else:
        # enable/disable
        await service_provider.set_enable_wifi_connections(state == "on")


async def async_cli_start_tunnel(service_provider: LockdownServiceProvider, script_mode: bool) -> None:
    await tunnel_task(
        await CoreDeviceTunnelProxy.create(service_provider),
        script_mode=script_mode,
        secrets=None,
        protocol=TunnelProtocol.TCP,
    )


@cli.command("start-tunnel")
@sudo_required
@async_command
async def cli_start_tunnel(
    service_provider: ServiceProviderDep,
    script_mode: Annotated[
        bool,
        typer.Option(help="Show only HOST and port number to allow easy parsing from external shell scripts"),
    ] = False,
) -> None:
    """start tunnel"""
    await async_cli_start_tunnel(service_provider, script_mode)


def _decode_device_kvs_data(handshake_info: dict) -> dict:
    """Decode the base64 binary-plist `deviceKVSData` blob in-place, if present."""
    peer_device_info = handshake_info.get("peerDeviceInfo", {})
    kvs = peer_device_info.get("deviceKVSData")
    if isinstance(kvs, str):
        try:
            peer_device_info["deviceKVSData"] = plistlib.loads(base64.b64decode(kvs))
        except Exception:
            logger.warning("failed to decode deviceKVSData; leaving it raw")
    return handshake_info


@cli.command("remotepairing")
@async_command
async def cli_remotepairing(
    service_provider: ServiceProviderDep,
    pair: Annotated[
        bool,
        typer.Option(
            "--pair", help="Perform RemotePairing pair-setup if not already paired (promptless over lockdownd)"
        ),
    ] = False,
    raw: Annotated[bool, typer.Option("--raw", help="Do not decode the base64 deviceKVSData blob")] = False,
) -> None:
    """
    Perform a RemotePairing handshake over the com.apple.dt.remotepairingdeviced.lockdown control
    channel and print the device's handshake info (peer device info, wire protocol versions,
    pairing capabilities). This control channel does not create tunnels - use `start-tunnel` for that.

    With --pair, performs RemotePairing pair-setup when the device is not already paired. Because this
    runs over the already-trusted lockdownd (USB) transport, pairing is promptless - no Trust dialog is
    shown - and it writes the RemotePairing pair record used by `pymobiledevice3 remote start-tunnel`,
    letting you bootstrap that record over USB without any on-device interaction.
    """
    service = await RemotePairingLockdownService.create(service_provider)
    try:
        try:
            await service.connect(autopair=pair)
        except RemotePairingCompletedError:
            # The device closes the connection once pairing completes; re-establish it to read the info.
            await service.close()
            service = await RemotePairingLockdownService.create(service_provider)
            await service.connect(autopair=False)
        handshake_info = service.handshake_info
        assert handshake_info is not None  # populated by connect()
        if not raw:
            handshake_info = _decode_device_kvs_data(handshake_info)
        print_json(handshake_info)
    finally:
        await service.close()


@cli.command("assistive-touch")
@async_command
async def lockdown_assistive_touch(
    service_provider: ServiceProviderDep, state: Optional[Literal["on", "off"]] = None
) -> None:
    """get/set assistive touch icon state (visibility)"""
    if not state:
        print_json({"AssistiveTouchEnabledByiTunes": await service_provider.get_assistive_touch()})
    else:
        # enable/disable
        await service_provider.set_assistive_touch(state == "on")
