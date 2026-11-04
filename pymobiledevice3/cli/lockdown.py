import ast
import base64
import datetime
import logging
import plistlib
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

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
    help="Pair/unpair, read and change device values, and talk to raw lockdown services.",
    no_args_is_help=True,
)


@cli.command("recovery")
@async_command
async def lockdown_recovery(service_provider: LockdownClientDep) -> None:
    """Reboot the device into recovery mode.

    The device leaves normal iOS and waits in recovery; use `restore exit`
    to boot it back normally.
    """
    print_json(await service_provider.enter_recovery())


@cli.command("service")
def lockdown_service(
    service_provider: ServiceProviderDep,
    service_name: Annotated[
        str, typer.Argument(help="Lockdown service name (e.g. com.apple.mobile.diagnostics_relay).")
    ],
) -> None:
    """Open an IPython shell on a raw lockdown service, to send and receive its messages."""
    service = run_in_loop(service_provider.start_lockdown_service(service_name))
    try:
        service.shell()
    finally:
        run_in_loop(service.close())


@cli.command("developer-service")
def lockdown_developer_service(
    service_provider: ServiceProviderDep,
    service_name: Annotated[
        str, typer.Argument(help="Developer service name (e.g. com.apple.instruments.remoteserver).")
    ],
) -> None:
    """Open an IPython shell on a raw developer service (needs the DeveloperDiskImage mounted)."""
    service = run_in_loop(service_provider.start_lockdown_developer_service(service_name))
    try:
        service.shell()
    finally:
        run_in_loop(service.close())


@cli.command("info")
def lockdown_info(service_provider: ServiceProviderDep) -> None:
    """Print all lockdown values (device name, iOS version, UDID, ...)."""
    print_json(service_provider.all_values)


@cli.command("get")
@async_command
async def lockdown_get(
    service_provider: ServiceProviderDep,
    domain: Annotated[
        Optional[str], typer.Argument(help="Value domain (e.g. com.apple.mobile.battery); omit for the global domain.")
    ] = None,
    key: Annotated[Optional[str], typer.Argument(help="Key to read; omit to read the whole domain.")] = None,
) -> None:
    """Print a lockdown value, or every value of a domain."""
    print_json(await service_provider.get_value(domain=domain, key=key))


@cli.command("set")
@async_command
async def lockdown_set(
    service_provider: ServiceProviderDep,
    value: Annotated[str, typer.Argument(help="New value as a Python literal (e.g. True, 42, 'text').")],
    domain: Annotated[Optional[str], typer.Argument(help="Value domain; omit for the global domain.")] = None,
    key: Annotated[Optional[str], typer.Argument(help="Key to set.")] = None,
) -> None:
    """Change a lockdown value on the device.

    VALUE is parsed as a Python literal (with ast.literal_eval), so quote
    strings, e.g. "'My iPhone'".
    """
    print_json(await service_provider.set_value(value=ast.literal_eval(value), domain=domain, key=key))


@cli.command("remove")
@async_command
async def lockdown_remove(
    service_provider: ServiceProviderDep,
    domain: Annotated[str, typer.Argument(help="Value domain.")],
    key: Annotated[str, typer.Argument(help="Key to remove.")],
) -> None:
    """Remove a lockdown value from the device."""
    print_json(await service_provider.remove_value(domain=domain, key=key))


@cli.command("unpair")
@async_command
async def lockdown_unpair(
    service_provider: NoAutoPairLockdownClientDep,
    host_id: Annotated[
        Optional[str], typer.Argument(help="HostID of the pairing to remove; omit to remove this host's pairing.")
    ] = None,
) -> None:
    """Unpair a host from the device and forget its local pair record.

    The device asks to "Trust This Computer" again on the next pairing.
    """
    await service_provider.unpair(host_id=host_id)


@cli.command("pair")
@async_command
async def lockdown_pair(service_provider: NoAutoPairLockdownClientDep) -> None:
    """Pair this computer with the device (accept "Trust This Computer" on the device)."""
    await service_provider.pair()


@cli.command("pair-supervised")
@async_command
async def lockdown_pair_supervised(
    service_provider: NoAutoPairLockdownClientDep,
    keybag: Annotated[
        Path,
        typer.Argument(
            file_okay=True,
            dir_okay=False,
            exists=True,
            help="PEM file with the supervisor's private key and certificate (see `profile create-keybag`).",
        ),
    ],
) -> None:
    """Pair with a supervised device using its supervision identity (no Trust dialog)."""
    await service_provider.pair_supervised(keybag)


@cli.command("save-pair-record")
def lockdown_save_pair_record(
    service_provider: NoAutoPairLockdownClientDep,
    output: Annotated[Path, typer.Argument(help="File to write the pair record (plist) to.")],
) -> None:
    """Save this host's pair record for the device to a file (it grants access to the device)."""
    if service_provider.pair_record is None:
        logger.error("no pairing record was found")
        raise typer.Exit(1)
    output.write_bytes(plistlib.dumps(service_provider.pair_record))


@cli.command("date")
@async_command
async def lockdown_date(service_provider: ServiceProviderDep) -> None:
    """Print the device's current date and time."""
    timestamp = await service_provider.get_value(key="TimeIntervalSince1970")
    print(datetime.datetime.fromtimestamp(timestamp))


@cli.command("heartbeat")
@async_command
async def lockdown_heartbeat(service_provider: ServiceProviderDep) -> None:
    """Keep a lockdown heartbeat going with the device; runs until Ctrl+C."""
    await HeartbeatService(service_provider).start()


@cli.command("language")
@async_command
async def lockdown_language(
    service_provider: ServiceProviderDep,
    language: Annotated[
        Optional[str], typer.Argument(help="Language code to set (e.g. en); omit to only print it.")
    ] = None,
) -> None:
    """Print the device language, or change it first if LANGUAGE is given."""
    if language is not None:
        await service_provider.set_language(language)
    print_json(await service_provider.get_language())


@cli.command("locale")
@async_command
async def lockdown_locale(
    service_provider: ServiceProviderDep,
    locale: Annotated[Optional[str], typer.Argument(help="Locale to set (e.g. en_US); omit to only print it.")] = None,
) -> None:
    """Print the device locale (region format), or change it first if LOCALE is given."""
    if locale is not None:
        await service_provider.set_locale(locale)
    print_json(await service_provider.get_locale())


@cli.command("device-name")
@async_command
async def lockdown_device_name(
    service_provider: ServiceProviderDep,
    new_name: Annotated[Optional[str], typer.Argument(help="New device name; omit to print the current one.")] = None,
) -> None:
    """Print the device name, or rename the device."""
    if new_name:
        await service_provider.set_value(new_name, key="DeviceName")
    else:
        print(f"{await service_provider.get_value(key='DeviceName')}")


@cli.command("wifi-connections")
@async_command
async def lockdown_wifi_connections(
    service_provider: ServiceProviderDep,
    state: Annotated[
        Optional[Literal["on", "off"]], typer.Argument(help="Turn it on or off; omit to print the current state.")
    ] = None,
) -> None:
    """Show or set whether this host may connect to the device over Wi-Fi (EnableWifiConnections)."""
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
        typer.Option(help="Print only HOST and port, for parsing from shell scripts."),
    ] = False,
) -> None:
    """Start an iOS 17.4+ tunnel over lockdown and print its `--rsd HOST PORT` (needs root).

    Rarely needed: commands build their own no-root tunnel. Use it when another
    process needs --rsd. Always uses TCP. Runs until Ctrl+C.
    """
    await async_cli_start_tunnel(service_provider, script_mode)


def _decode_device_kvs_data(handshake_info: dict[str, Any]) -> dict[str, Any]:
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
            "--pair", help="Perform RemotePairing pair-setup if not already paired (promptless over lockdownd)."
        ),
    ] = False,
    raw: Annotated[bool, typer.Option("--raw", help="Do not decode the base64 deviceKVSData blob.")] = False,
) -> None:
    """Print the device's RemotePairing handshake info; with --pair, also pair.

    Performs a RemotePairing handshake over the
    com.apple.dt.remotepairingdeviced.lockdown control channel and prints the
    device's handshake info (peer device info, wire protocol versions, pairing
    capabilities). This control channel does not create tunnels - use
    `start-tunnel` for that.

    With --pair, performs RemotePairing pair-setup when the device is not
    already paired. Because this runs over the already-trusted lockdownd (USB)
    transport, pairing is promptless - no Trust dialog is shown - and it writes
    the RemotePairing pair record used by `pymobiledevice3 remote start-tunnel`,
    letting you bootstrap that record over USB without any on-device
    interaction.
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
    service_provider: ServiceProviderDep,
    state: Annotated[
        Optional[Literal["on", "off"]], typer.Argument(help="Show or hide it; omit to print the current state.")
    ] = None,
) -> None:
    """Show or set whether the AssistiveTouch button is shown on screen."""
    if not state:
        print_json({"AssistiveTouchEnabledByiTunes": await service_provider.get_assistive_touch()})
    else:
        # enable/disable
        await service_provider.set_assistive_touch(state == "on")


@cli.command("auto-answer")
@async_command
async def lockdown_auto_answer(
    service_provider: ServiceProviderDep,
    state: Annotated[Literal["on", "off"], typer.Argument(help="Turn auto-answer on or off.")],
) -> None:
    """Set whether incoming calls are answered automatically (Accessibility > Call Audio Routing)."""
    await service_provider.set_auto_answer_calls(state == "on")
