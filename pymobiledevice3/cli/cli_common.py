import datetime
import json
import logging
import os
import uuid

import click
import coloredlogs
import inquirer
from inquirer.themes import GreenPassion
from pygments import highlight, lexers, formatters

from pymobiledevice3.exceptions import NoDeviceSelectedError
from pymobiledevice3.lockdown import LockdownClient
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


def set_verbosity(ctx, param, value):
    coloredlogs.set_level(logging.INFO - (value * 10))


def wait_return():
    input('> Hit RETURN to exit')


UDID_ENV_VAR = 'PYMOBILEDEVICE3_UDID'


class DeviceInfo:
    def __init__(self, lockdown_client: LockdownClient):
        self.lockdown_client = lockdown_client
        self.product_version = self.lockdown_client.product_version
        self.serial = self.lockdown_client.identifier
        self.display_name = self.lockdown_client.display_name

    def __str__(self):
        if self.display_name is None:
            return f'Unknown device, ios version: {self.product_version}, serial: {self.serial}'
        else:
            return f'{self.display_name}, ios version: {self.product_version}, serial: {self.serial}'


class Command(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('lockdown', '--udid'), envvar=UDID_ENV_VAR, callback=self.udid,
                         help=f'Device unique identifier. You may pass {UDID_ENV_VAR} environment variable to pass this'
                              f' option as well'),
            click.Option(('verbosity', '-v', '--verbose'), count=True, callback=set_verbosity, expose_value=False),
        ]

    @staticmethod
    def udid(ctx, param, value):
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return

        if value is not None:
            return LockdownClient(serial=value)

        devices = select_devices_by_connection_type(connection_type='USB')
        if len(devices) <= 1:
            return LockdownClient()

        devices_options = []
        for device in devices:
            lockdown_client = LockdownClient(serial=device.serial)
            device_info = DeviceInfo(lockdown_client)
            devices_options.append(device_info)

        device_question = [inquirer.List('device', message='choose device', choices=devices_options, carousel=True)]
        try:
            result = inquirer.prompt(device_question, theme=GreenPassion(), raise_keyboard_interrupt=True)
            return result['device'].lockdown_client
        except KeyboardInterrupt as e:
            raise NoDeviceSelectedError from e


class CommandWithoutAutopair(Command):
    @staticmethod
    def udid(ctx, param, value):
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return
        return LockdownClient(serial=value, autopair=False)


class BasedIntParamType(click.ParamType):
    name = 'based int'

    def convert(self, value, param, ctx):
        try:
            return int(value, 0)
        except ValueError:
            self.fail(f'{value!r} is not a valid int.', param, ctx)


BASED_INT = BasedIntParamType()
