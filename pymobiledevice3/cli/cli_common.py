import datetime
import json
import logging
import os
import sys
import uuid
from typing import Callable, List, Mapping, Optional, Tuple

import click
import coloredlogs
import hexdump
import inquirer3
from click import Option, UsageError
from inquirer3.themes import GreenPassion
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import AccessDeniedError, DeviceNotFoundError, NoDeviceConnectedError, \
    NoDeviceSelectedError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.utils import get_tunneld_devices
from pymobiledevice3.usbmux import select_devices_by_connection_type

USBMUX_OPTION_HELP = 'usbmuxd listener address (in the form of either /path/to/unix/socket OR HOST:PORT'


class RSDOption(Option):
    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop('mutually_exclusive', []))
        help = kwargs.get('help', '')
        if self.mutually_exclusive:
            ex_str = ', '.join(self.mutually_exclusive)
            kwargs['help'] = help + (
                    ' NOTE: This argument is mutually exclusive with '
                    ' arguments: [' + ex_str + '].'
            )
        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if len(opts) == 0 and isinstance(ctx.command, RSDCommand) and not (isinstance(ctx.command, Command)):
            raise UsageError('Illegal usage: At least one is required [--rsd | --tunnel]')
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


def print_json(buf, colored=True, default=default_json_encoder):
    formatted_json = json.dumps(buf, sort_keys=True, indent=4, default=default)
    if colored:
        colorful_json = highlight(formatted_json, lexers.JsonLexer(),
                                  formatters.TerminalTrueColorFormatter(style='stata-dark'))
        print(colorful_json)
        return colorful_json
    else:
        print(formatted_json)
        return formatted_json


def print_hex(data, colored=True):
    hex_dump = hexdump.hexdump(data, result='return')
    if colored:
        print(highlight(hex_dump, lexers.HexdumpLexer(), formatters.TerminalTrueColorFormatter(style='native')))
    else:
        print(hex_dump, end='\n\n')


def set_verbosity(ctx, param, value):
    coloredlogs.set_level(logging.INFO - (value * 10))


def get_last_used_terminal_formatting(buf: str) -> str:
    return '\x1b' + buf.rsplit('\x1b', 1)[1].split('m')[0] + 'm'


def wait_return() -> None:
    if sys.platform != 'win32':
        import signal
        print("Press Ctrl+C to send a SIGINT or use 'kill' command to send a SIGTERM")
        signal.sigwait([signal.SIGINT, signal.SIGTERM])
    else:
        input('Press ENTER to exit>')


UDID_ENV_VAR = 'PYMOBILEDEVICE3_UDID'


def is_admin_user() -> bool:
    """ Check if the current OS user is an Administrator or root.

    See: https://github.com/Preston-Landers/pyuac/blob/master/pyuac/admin.py

    :return: True if the current user is an 'Administrator', otherwise False.
    """
    if os.name == 'nt':
        import win32security

        try:
            admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            return win32security.CheckTokenMembership(None, admin_sid)
        except Exception:
            return False
    else:
        # Check for root on Posix
        return os.getuid() == 0


def sudo_required(func):
    def wrapper(*args, **kwargs):
        if not is_admin_user():
            raise AccessDeniedError()
        else:
            func(*args, **kwargs)

    return wrapper


def prompt_device_list(device_list: List):
    device_question = [inquirer3.List('device', message='choose device', choices=device_list, carousel=True)]
    try:
        result = inquirer3.prompt(device_question, theme=GreenPassion(), raise_keyboard_interrupt=True)
        return result['device']
    except KeyboardInterrupt:
        raise NoDeviceSelectedError()


def choose_service_provider(callback: Callable):
    def wrap_callback_calling(**kwargs: Mapping):
        service_provider = None
        lockdown_service_provider = kwargs.pop('lockdown_service_provider', None)
        rsd_service_provider_manually = kwargs.pop('rsd_service_provider_manually', None)
        rsd_service_provider_using_tunneld = kwargs.pop('rsd_service_provider_using_tunneld', None)
        if lockdown_service_provider is not None:
            service_provider = lockdown_service_provider
        if rsd_service_provider_manually is not None:
            service_provider = rsd_service_provider_manually
        if rsd_service_provider_using_tunneld is not None:
            service_provider = rsd_service_provider_using_tunneld
        callback(service_provider=service_provider, **kwargs)

    return wrap_callback_calling


class BaseCommand(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('verbosity', '-v', '--verbose'), count=True, callback=set_verbosity, expose_value=False),
        ]


class BaseServiceProviderCommand(BaseCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('verbosity', '-v', '--verbose'), count=True, callback=set_verbosity, expose_value=False),
        ]
        self.service_provider = None
        self.callback = choose_service_provider(self.callback)


class LockdownCommand(BaseServiceProviderCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.usbmux_address = None
        self.params[:0] = [
            click.Option(('usbmux', '--usbmux'), callback=self.usbmux, expose_value=False,
                         help=USBMUX_OPTION_HELP),
            click.Option(('lockdown_service_provider', '--udid'), envvar=UDID_ENV_VAR, callback=self.udid,
                         help=f'Device unique identifier. You may pass {UDID_ENV_VAR} environment variable to pass this'
                              f' option as well'),
        ]

    def usbmux(self, ctx, param: str, value: Optional[str] = None) -> None:
        if value is None:
            return
        self.usbmux_address = value

    def udid(self, ctx, param: str, value: str) -> Optional[LockdownClient]:
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
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
        self.params[:0] = [
            RSDOption(('rsd_service_provider_manually', '--rsd'), type=(str, int), callback=self.rsd,
                      mutually_exclusive=['rsd_service_provider_using_tunneld'],
                      help='RSD hostname and port number'),
            RSDOption(('rsd_service_provider_using_tunneld', '--tunnel'), callback=self.tunneld,
                      mutually_exclusive=['rsd_service_provider_manually'],
                      help='Either an empty string to force tunneld device selection, or a UDID of a tunneld '
                           'discovered device')
        ]

    def rsd(self, ctx, param: str, value: Optional[Tuple[str, int]]) -> Optional[RemoteServiceDiscoveryService]:
        if value is not None:
            rsd = RemoteServiceDiscoveryService(value)
            rsd.connect()
            self.service_provider = rsd
            return self.service_provider

    def tunneld(self, ctx, param: str, udid: Optional[str] = None) -> Optional[RemoteServiceDiscoveryService]:
        if udid is None:
            return

        rsds = get_tunneld_devices()
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
            rsd.close()

        return self.service_provider


class Command(RSDCommand, LockdownCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class CommandWithoutAutopair(Command):
    @staticmethod
    def udid(ctx, param, value):
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
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
