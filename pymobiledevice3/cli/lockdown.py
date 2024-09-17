import asyncio
import logging
import plistlib
from pathlib import Path
from typing import Optional

import click

from pymobiledevice3.cli.cli_common import Command, CommandWithoutAutopair, print_json, sudo_required
from pymobiledevice3.cli.remote import tunnel_task
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.tunnel_service import CoreDeviceTunnelProxy
from pymobiledevice3.services.heartbeat import HeartbeatService

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group('lockdown')
def lockdown_group() -> None:
    """ Pair/Unpair device or access other lockdown services """
    pass


@lockdown_group.command('recovery', cls=Command)
def lockdown_recovery(service_provider: LockdownClient):
    """ enter recovery """
    print_json(service_provider.enter_recovery())


@lockdown_group.command('service', cls=Command)
@click.argument('service_name')
def lockdown_service(service_provider: LockdownServiceProvider, service_name):
    """ send-receive raw service messages with a given service name"""
    service_provider.start_lockdown_service(service_name).shell()


@lockdown_group.command('developer-service', cls=Command)
@click.argument('service_name')
def lockdown_developer_service(service_provider: LockdownServiceProvider, service_name):
    """ send-receive raw service messages with a given developer service name """
    service_provider.start_lockdown_developer_service(service_name).shell()


@lockdown_group.command('info', cls=Command)
def lockdown_info(service_provider: LockdownServiceProvider):
    """ query all lockdown values """
    print_json(service_provider.all_values)


@lockdown_group.command('get', cls=Command)
@click.argument('domain', required=False)
@click.argument('key', required=False)
def lockdown_get(service_provider: LockdownClient, domain, key):
    """ query lockdown values by their domain and key names """
    print_json(service_provider.get_value(domain=domain, key=key))


@lockdown_group.command('set', cls=Command)
@click.argument('value')
@click.argument('domain', required=False)
@click.argument('key', required=False)
def lockdown_set(service_provider: LockdownClient, value, domain, key):
    """ set a lockdown value using python's eval() """
    print_json(service_provider.set_value(value=eval(value), domain=domain, key=key))


@lockdown_group.command('remove', cls=Command)
@click.argument('domain')
@click.argument('key')
def lockdown_remove(service_provider: LockdownClient, domain, key):
    """ remove a domain/key pair """
    print_json(service_provider.remove_value(domain=domain, key=key))


@lockdown_group.command('unpair', cls=CommandWithoutAutopair)
@click.argument('host_id', required=False)
def lockdown_unpair(service_provider: LockdownClient, host_id: str = None):
    """ unpair from connected device """
    service_provider.unpair(host_id=host_id)


@lockdown_group.command('pair', cls=CommandWithoutAutopair)
def lockdown_pair(service_provider: LockdownClient):
    """ pair device """
    service_provider.pair()


@lockdown_group.command('pair-supervised', cls=CommandWithoutAutopair)
@click.argument('keybag', type=click.Path(file_okay=True, dir_okay=False, exists=True))
def lockdown_pair_supervised(service_provider: LockdownClient, keybag: str) -> None:
    """ pair supervised device """
    service_provider.pair_supervised(Path(keybag))


@lockdown_group.command('save-pair-record', cls=CommandWithoutAutopair)
@click.argument('output', type=click.File('wb'))
def lockdown_save_pair_record(service_provider: LockdownClient, output):
    """ save pair record to specified location """
    if service_provider.pair_record is None:
        logger.error('no pairing record was found')
        return
    plistlib.dump(service_provider.pair_record, output)


@lockdown_group.command('date', cls=Command)
def lockdown_date(service_provider: LockdownClient):
    """ get device date """
    print(service_provider.date)


@lockdown_group.command('heartbeat', cls=Command)
def lockdown_heartbeat(service_provider: LockdownClient):
    """ start heartbeat service """
    HeartbeatService(service_provider).start()


@lockdown_group.command('language', cls=Command)
@click.argument('language', required=False)
def lockdown_language(service_provider: LockdownClient, language: Optional[str]) -> None:
    """ Get/Set current language settings """
    if language is not None:
        service_provider.set_language(language)
    print_json(service_provider.language)


@lockdown_group.command('locale', cls=Command)
@click.argument('locale', required=False)
def lockdown_locale(service_provider: LockdownClient, locale: Optional[str]) -> None:
    """ Get/Set current language settings """
    if locale is not None:
        service_provider.set_locale(locale)
    print_json(service_provider.locale)


@lockdown_group.command('device-name', cls=Command)
@click.argument('new_name', required=False)
def lockdown_device_name(service_provider: LockdownClient, new_name):
    """ get/set current device name """
    if new_name:
        service_provider.set_value(new_name, key='DeviceName')
    else:
        print(f'{service_provider.get_value(key="DeviceName")}')


@lockdown_group.command('wifi-connections', cls=Command)
@click.argument('state', type=click.Choice(['on', 'off']), required=False)
def lockdown_wifi_connections(service_provider: LockdownClient, state):
    """ get/set wifi connections state """
    if not state:
        # show current state
        print_json(service_provider.get_value(domain='com.apple.mobile.wireless_lockdown'))
    else:
        # enable/disable
        service_provider.enable_wifi_connections = state == 'on'


@lockdown_group.command('start-tunnel', cls=Command)
@click.option('--script-mode', is_flag=True,
              help='Show only HOST and port number to allow easy parsing from external shell scripts')
@sudo_required
def cli_start_tunnel(
        service_provider: LockdownServiceProvider, script_mode: bool) -> None:
    """ start tunnel """
    service = CoreDeviceTunnelProxy(service_provider)
    asyncio.run(tunnel_task(service, script_mode=script_mode, secrets=None, protocol=TunnelProtocol.TCP), debug=True)


@lockdown_group.command('assistive-touch', cls=Command)
@click.argument('state', type=click.Choice(['on', 'off']), required=False)
def lockdown_assistive_touch(service_provider: LockdownClient, state: str) -> None:
    """ get/set assistive touch icon state (visibility) """
    if not state:
        key = 'AssistiveTouchEnabledByiTunes'
        accessibility_values = service_provider.get_value('com.apple.Accessibility')
        print_json({key: bool(accessibility_values[key])})
    else:
        # enable/disable
        service_provider.assistive_touch = state == 'on'
