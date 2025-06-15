import asyncio
import datetime
import json
import logging
import os
import sys
import uuid
from functools import wraps
from typing import Any, Callable, Optional

import click
import coloredlogs
import hexdump
import inquirer3
from click import Option, UsageError
from inquirer3.themes import GreenPassion
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import AccessDeniedError, DeviceNotFoundError, NoDeviceConnectedError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, async_get_tunneld_devices
from pymobiledevice3.usbmux import select_devices_by_connection_type

COLORED_OUTPUT = True
UDID_ENV_VAR = 'PYMOBILEDEVICE3_UDID'
TUNNEL_ENV_VAR = 'PYMOBILEDEVICE3_TUNNEL'
USBMUX_ENV_VAR = 'PYMOBILEDEVICE3_USBMUX'
OSUTILS = get_os_utils()

USBMUX_OPTION_HELP = (f'usbmuxd listener address (in the form of either /path/to/unix/socket OR HOST:PORT). '
                      f'Can be specified via {USBMUX_ENV_VAR} envvar')


class RSDOption(Option):
    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop('mutually_exclusive', []))
        help = kwargs.get('help', '')
        if self.mutually_exclusive:
            ex_str = ', '.join(self.mutually_exclusive)
            kwargs['help'] = help + (
                    '\nNOTE: This argument is mutually exclusive with '
                    ' arguments: [' + ex_str + '].'
            )
        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if (isinstance(ctx.command, RSDCommand) and not (isinstance(ctx.command, Command)) and
                ('rsd_service_provider_using_tunneld' not in opts) and ('rsd_service_provider_manually' not in opts)):
            # defaulting to `--tunnel ''` if no remote option was specified
            opts['rsd_service_provider_using_tunneld'] = ''
        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            raise UsageError(
                'Illegal usage: `{}` is mutually exclusive with '
                'arguments `{}`.'.format(
                    self.name,
                    ', '.join(self.mutually_exclusive)
                )
            )

        return super().handle_parse_result(
            ctx,
            opts,
            args
        )


def default_json_encoder(obj):
    if isinstance(obj, bytes):
        return f'<{obj.hex()}>'
    if isinstance(obj, datetime.datetime):
        return str(obj)
    if isinstance(obj, uuid.UUID):
        return str(obj)
    raise TypeError()


def print_json(buf, colored: Optional[bool] = None, default=default_json_encoder):
    if colored is None:
        colored = user_requested_colored_output()
    formatted_json = json.dumps(buf, sort_keys=True, indent=4, default=default)
    if colored and os.isatty(sys.stdout.fileno()):
        colorful_json = highlight(formatted_json, lexers.JsonLexer(),
                                  formatters.Terminal256Formatter(style='stata-dark'))
        print(colorful_json)
        return colorful_json
    else:
        print(formatted_json)
        return formatted_json


def print_hex(data, colored=True):
    hex_dump = hexdump.hexdump(data, result='return')
    if colored:
        print(highlight(hex_dump, lexers.HexdumpLexer(), formatters.Terminal256Formatter(style='native')))
    else:
        print(hex_dump, end='\n\n')


def set_verbosity(ctx, param, value):
    coloredlogs.set_level(logging.INFO - (value * 10))


def set_color_flag(ctx, param, value) -> None:
    global COLORED_OUTPUT
    COLORED_OUTPUT = value


def isatty() -> bool:
    return os.isatty(sys.stdout.fileno())


def user_requested_colored_output() -> bool:
    return COLORED_OUTPUT and isatty()


def get_last_used_terminal_formatting(buf: str) -> str:
    return '\x1b' + buf.rsplit('\x1b', 1)[1].split('m')[0] + 'm'


def sudo_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not OSUTILS.is_admin:
            raise AccessDeniedError()
        else:
            func(*args, **kwargs)

    return wrapper


def prompt_selection(choices: list[Any], message: str, idx: bool = False) -> Any:
    question = [inquirer3.List('selection', message=message, choices=choices, carousel=True)]
    try:
        result = inquirer3.prompt(question, theme=GreenPassion(), raise_keyboard_interrupt=True)
    except KeyboardInterrupt:
        raise click.ClickException('No selection was made')
    return result['selection'] if not idx else choices.index(result['selection'])


def prompt_device_list(device_list: list):
    return prompt_selection(device_list, 'Choose device')


def choose_service_provider(callback: Callable):
    def wrap_callback_calling(**kwargs: dict) -> None:
        service_provider = None
        lockdown_service_provider = kwargs.pop('lockdown_service_provider', None)
        rsd_service_provider_manually = kwargs.pop('rsd_service_provider_manually', None)
        rsd_service_provider_using_tunneld = kwargs.pop('rsd_service_provider_using_tunneld', None)
        del kwargs['rsd_use_userspace_tun']
        if lockdown_service_provider is not None:
            service_provider = lockdown_service_provider
        if rsd_service_provider_manually is not None:
            service_provider = rsd_service_provider_manually
        if rsd_service_provider_using_tunneld is not None:
            service_provider = rsd_service_provider_using_tunneld
        callback(service_provider=service_provider, **kwargs)

    return wrap_callback_calling


def is_invoked_for_completion() -> bool:
    """ Returns True if the command is ivoked for autocompletion. """
    for env in os.environ.keys():
        if env.startswith('_') and env.endswith('_COMPLETE'):
            return True
    return False


class BaseCommand(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('verbosity', '-v', '--verbose'), count=True, callback=set_verbosity, expose_value=False),
            click.Option(('color', '--color/--no-color'), default=True, callback=set_color_flag, is_flag=True,
                         expose_value=False, help='colorize output'),
        ]


class BaseServiceProviderCommand(BaseCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service_provider = None
        self.callback = choose_service_provider(self.callback)


class LockdownCommand(BaseServiceProviderCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.usbmux_address = None
        self.params[:0] = [
            click.Option(('usbmux', '--usbmux'), callback=self.usbmux, expose_value=False,
                         envvar=USBMUX_ENV_VAR, help=USBMUX_OPTION_HELP),
            click.Option(('lockdown_service_provider', '--udid'), envvar=UDID_ENV_VAR, callback=self.udid,
                         help=f'Device unique identifier. You may pass {UDID_ENV_VAR} environment variable to pass this'
                              f' option as well'),
        ]

    def usbmux(self, ctx, param: str, value: Optional[str] = None) -> None:
        if value is None:
            return
        self.usbmux_address = value

    def udid(self, ctx, param: str, value: str) -> Optional[LockdownClient]:
        if is_invoked_for_completion():
            # prevent lockdown connection establishment when in autocomplete mode
            return

        if self.service_provider is not None:
            return self.service_provider

        if value is not None:
            return create_using_usbmux(serial=value)

        devices = select_devices_by_connection_type(connection_type='USB', usbmux_address=self.usbmux_address)
        if len(devices) <= 1:
            return create_using_usbmux(usbmux_address=self.usbmux_address)

        return prompt_device_list(
            [create_using_usbmux(serial=device.serial, usbmux_address=self.usbmux_address) for device in devices])


class RSDCommand(BaseServiceProviderCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.userspace_tun_address = None
        self.params[:0] = [
            RSDOption(('rsd_use_userspace_tun', '--userspace-tun'), type=(str, int),
                      callback=self.userspace_tun,
                      mutually_exclusive=['rsd_service_provider_using_tunneld'],
                      help='\b\nhostname and port number of userspace tunnel server '
                           '(as provided by a `start-tunnel` subcommand).'),
            RSDOption(('rsd_service_provider_manually', '--rsd'), type=(str, int), callback=self.rsd,
                      mutually_exclusive=['rsd_service_provider_using_tunneld'],
                      help='\b\n'
                           'RSD hostname and port number (as provided by a `start-tunnel` subcommand).'),
            RSDOption(('rsd_service_provider_using_tunneld', '--tunnel'), callback=self.tunneld,
                      mutually_exclusive=[
                          'rsd_service_provider_manually',
                          'rsd_use_userspace_tun'
                      ],
                      envvar=TUNNEL_ENV_VAR,
                      help='\b\n'
                           'Either an empty string to force tunneld device selection, or a UDID of a tunneld '
                           'discovered device.\n'
                           'The string may be suffixed with :PORT in case tunneld is not serving at the default port.\n'
                           f'This option may also be transferred as an environment variable: {TUNNEL_ENV_VAR}')
        ]

    def userspace_tun(self, ctx, param: str, value: Optional[tuple[str, int]]) -> None:
        self.userspace_tun_address = value

    def rsd(self, ctx, param: str, value: Optional[tuple[str, int]]) -> Optional[RemoteServiceDiscoveryService]:
        if value is not None:
            rsd = RemoteServiceDiscoveryService(value, userspace_tun_address=self.userspace_tun_address)
            asyncio.run(rsd.connect(), debug=True)
            self.service_provider = rsd
            return self.service_provider

    async def _tunneld(self, udid: Optional[str] = None) -> Optional[RemoteServiceDiscoveryService]:
        if udid is None:
            return

        udid = udid.strip()
        port = TUNNELD_DEFAULT_ADDRESS[1]
        if ':' in udid:
            udid, port = udid.split(':')

        rsds = await async_get_tunneld_devices((TUNNELD_DEFAULT_ADDRESS[0], port))
        if len(rsds) == 0:
            raise NoDeviceConnectedError()

        if udid != '':
            try:
                # Connect to the specified device
                self.service_provider = [rsd for rsd in rsds if rsd.udid == udid][0]
            except IndexError:
                raise DeviceNotFoundError(udid)
        else:
            if len(rsds) == 1:
                self.service_provider = rsds[0]
            else:
                self.service_provider = prompt_device_list(rsds)

        for rsd in rsds:
            if rsd == self.service_provider:
                continue
            await rsd.close()

        return self.service_provider

    def tunneld(self, ctx, param: str, udid: Optional[str] = None) -> Optional[RemoteServiceDiscoveryService]:
        return asyncio.run(self._tunneld(udid), debug=True)


class Command(RSDCommand, LockdownCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class CommandWithoutAutopair(Command):
    @staticmethod
    def udid(ctx, param, value):
        if is_invoked_for_completion():
            # prevent lockdown connection establishment when in autocomplete mode
            return
        return create_using_usbmux(serial=value, autopair=False)


class BasedIntParamType(click.ParamType):
    name = 'based int'

    def convert(self, value, param, ctx):
        try:
            return int(value, 0)
        except ValueError:
            self.fail(f'{value!r} is not a valid int.', param, ctx)


BASED_INT = BasedIntParamType()
