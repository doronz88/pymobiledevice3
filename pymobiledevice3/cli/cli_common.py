import datetime
import json
import logging
import os
import uuid

import click
import coloredlogs
from pygments import highlight, lexers, formatters

from pymobiledevice3.lockdown import LockdownClient


def default_json_encoder(obj):
    if isinstance(obj, bytes):
        return obj.hex()
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
        return LockdownClient(udid=value)
