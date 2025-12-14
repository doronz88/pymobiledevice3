import asyncio
import logging
import plistlib
from pathlib import Path
from typing import Annotated, Literal, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import NoAutoPairServiceProviderDep, ServiceProviderDep, print_json, sudo_required
from pymobiledevice3.cli.remote import tunnel_task
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.tunnel_service import CoreDeviceTunnelProxy
from pymobiledevice3.services.heartbeat import HeartbeatService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="lockdown",
    help="Pair/Unpair device or access other lockdown services",
    no_args_is_help=True,
)


@cli.command("recovery")
def lockdown_recovery(service_provider: ServiceProviderDep) -> None:
    """enter recovery"""
    print_json(service_provider.enter_recovery())


@cli.command("service")
def lockdown_service(service_provider: ServiceProviderDep, service_name: str) -> None:
    """send-receive raw service messages with a given service name"""
    service_provider.start_lockdown_service(service_name).shell()


@cli.command("developer-service")
def lockdown_developer_service(service_provider: ServiceProviderDep, service_name: str) -> None:
    """send-receive raw service messages with a given developer service name"""
    service_provider.start_lockdown_developer_service(service_name).shell()


@cli.command("info")
def lockdown_info(service_provider: ServiceProviderDep) -> None:
    """query all lockdown values"""
    print_json(service_provider.all_values)


@cli.command("get")
def lockdown_get(service_provider: ServiceProviderDep, domain: Optional[str] = None, key: Optional[str] = None) -> None:
    """query lockdown values by their domain and key names"""
    print_json(service_provider.get_value(domain=domain, key=key))


@cli.command("set")
def lockdown_set(
    service_provider: ServiceProviderDep,
    value: str,
    domain: Optional[str] = None,
    key: Optional[str] = None,
) -> None:
    """set a lockdown value using python's eval()"""
    print_json(service_provider.set_value(value=eval(value), domain=domain, key=key))


@cli.command("remove")
def lockdown_remove(service_provider: ServiceProviderDep, domain: str, key: str) -> None:
    """remove a domain/key pair"""
    print_json(service_provider.remove_value(domain=domain, key=key))


@cli.command("unpair")
def lockdown_unpair(service_provider: NoAutoPairServiceProviderDep, host_id: Optional[str] = None) -> None:
    """unpair from connected device"""
    service_provider.unpair(host_id=host_id)


@cli.command("pair")
def lockdown_pair(service_provider: NoAutoPairServiceProviderDep) -> None:
    """pair device"""
    service_provider.pair()


@cli.command("pair-supervised")
def lockdown_pair_supervised(
    service_provider: NoAutoPairServiceProviderDep,
    keybag: Annotated[
        Path,
        typer.Argument(file_okay=True, dir_okay=False, exists=True),
    ],
) -> None:
    """pair supervised device"""
    service_provider.pair_supervised(keybag)


@cli.command("save-pair-record")
def lockdown_save_pair_record(service_provider: NoAutoPairServiceProviderDep, output: Path) -> None:
    """save pair record to specified location"""
    if service_provider.pair_record is None:
        logger.error("no pairing record was found")
        return
    output.write_bytes(plistlib.dumps(service_provider.pair_record))


@cli.command("date")
def lockdown_date(service_provider: ServiceProviderDep) -> None:
    """get device date"""
    print(service_provider.date)


@cli.command("heartbeat")
def lockdown_heartbeat(service_provider: ServiceProviderDep) -> None:
    """start heartbeat service"""
    HeartbeatService(service_provider).start()


@cli.command("language")
def lockdown_language(service_provider: ServiceProviderDep, language: Optional[str] = None) -> None:
    """Get/Set current language settings"""
    if language is not None:
        service_provider.set_language(language)
    print_json(service_provider.language)


@cli.command("locale")
def lockdown_locale(service_provider: ServiceProviderDep, locale: Optional[str] = None) -> None:
    """Get/Set current language settings"""
    if locale is not None:
        service_provider.set_locale(locale)
    print_json(service_provider.locale)


@cli.command("device-name")
def lockdown_device_name(service_provider: ServiceProviderDep, new_name: Optional[str] = None) -> None:
    """get/set current device name"""
    if new_name:
        service_provider.set_value(new_name, key="DeviceName")
    else:
        print(f"{service_provider.get_value(key='DeviceName')}")


@cli.command("wifi-connections")
def lockdown_wifi_connections(
    service_provider: ServiceProviderDep, state: Optional[Literal["on", "off"]] = None
) -> None:
    """get/set wifi connections state"""
    if not state:
        # show current state
        print_json(service_provider.get_value(domain="com.apple.mobile.wireless_lockdown"))
    else:
        # enable/disable
        service_provider.enable_wifi_connections = state == "on"


async def async_cli_start_tunnel(service_provider: LockdownServiceProvider, script_mode: bool) -> None:
    await tunnel_task(
        await CoreDeviceTunnelProxy.create(service_provider),
        script_mode=script_mode,
        secrets=None,
        protocol=TunnelProtocol.TCP,
    )


@cli.command("start-tunnel")
@sudo_required
def cli_start_tunnel(
    service_provider: ServiceProviderDep,
    script_mode: Annotated[
        bool,
        typer.Option(help="Show only HOST and port number to allow easy parsing from external shell scripts"),
    ] = False,
) -> None:
    """start tunnel"""
    asyncio.run(async_cli_start_tunnel(service_provider, script_mode), debug=True)


@cli.command("assistive-touch")
def lockdown_assistive_touch(
    service_provider: ServiceProviderDep, state: Optional[Literal["on", "off"]] = None
) -> None:
    """get/set assistive touch icon state (visibility)"""
    if not state:
        key = "AssistiveTouchEnabledByiTunes"
        accessibility_values = service_provider.get_value("com.apple.Accessibility")
        print_json({key: bool(accessibility_values[key])})
    else:
        # enable/disable
        service_provider.assistive_touch = state == "on"
