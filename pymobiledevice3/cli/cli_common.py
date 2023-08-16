import datetime
import json
import logging
import os
import uuid
from typing import Callable, List, Mapping, Optional, Tuple

import click
import coloredlogs
import hexdump
import inquirer3
from inquirer3.themes import GreenPassion
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import NoDeviceSelectedError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.usbmux import select_devices_by_connection_type


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
    else:
        print(formatted_json)


def print_hex(data, colored=True):
    hex_dump = hexdump.hexdump(data, result='return')
    if colored:
        print(highlight(hex_dump, lexers.HexdumpLexer(), formatters.TerminalTrueColorFormatter(style='native')))
    else:
        print(hex_dump, end='\n\n')


def set_verbosity(ctx, param, value):
    coloredlogs.set_level(logging.INFO - (value * 10))


def wait_return():
    input('> Hit RETURN to exit')


UDID_ENV_VAR = 'PYMOBILEDEVICE3_UDID'


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
        rsd_service_provider = kwargs.pop('rsd_service_provider', None)
        if lockdown_service_provider is not None:
            service_provider = lockdown_service_provider
        if rsd_service_provider is not None:
            service_provider = rsd_service_provider
        callback(service_provider=service_provider, **kwargs)

    return wrap_callback_calling


class BaseCommand(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('verbosity', '-v', '--verbose'), count=True, callback=set_verbosity, expose_value=False),
        ]
        self.service_provider = None
        self.callback = choose_service_provider(self.callback)


class LockdownCommand(BaseCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('lockdown_service_provider', '--udid'), envvar=UDID_ENV_VAR, callback=self.udid,
                         help=f'Device unique identifier. You may pass {UDID_ENV_VAR} environment variable to pass this'
                              f' option as well'),
        ]

    def udid(self, ctx, param: str, value: str) -> Optional[LockdownClient]:
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return

        if self.service_provider is not None:
            return self.service_provider

        if value is not None:
            return create_using_usbmux(serial=value)

        devices = select_devices_by_connection_type(connection_type='USB')
        if len(devices) <= 1:
            return create_using_usbmux()

        return prompt_device_list([create_using_usbmux(serial=device.serial) for device in devices])


class RSDCommand(BaseCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('rsd_service_provider', '--rsd'), type=(str, int), callback=self.rsd, required=True,
                         help='RSD hostname and port number'),
        ]

    def rsd(self, ctx, param: str, value: Optional[Tuple[str, int]]) -> Optional[RemoteServiceDiscoveryService]:
        if value is not None:
            with RemoteServiceDiscoveryService(value) as rsd:
                self.service_provider = rsd
                return self.service_provider


class Command(RSDCommand, LockdownCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # make the RSD optional
        self.params[0].required = False


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
