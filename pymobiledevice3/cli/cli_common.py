import json
import os
from pprint import pprint

import click
from pygments import highlight, lexers, formatters

from pymobiledevice3.lockdown import LockdownClient


def print_object(buf, colored=True, default=None):
    if colored:
        formatted_json = json.dumps(buf, sort_keys=True, indent=4, default=default)
        colorful_json = highlight(formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter())
        print(colorful_json)
    else:
        pprint(buf)


class Command(click.Command):
    @staticmethod
    def udid(ctx, param, value):
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return
        return LockdownClient(udid=value)

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('lockdown', '--udid'), callback=self.udid),
        ]
