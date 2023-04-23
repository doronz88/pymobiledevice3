import plistlib
from pathlib import Path

import click

from pymobiledevice3.bonjour import browse
from pymobiledevice3.cli.cli_common import print_json

DEFAULT_BROWSE_TIMEOUT = 5


@click.group()
def cli():
    """ bonjour cli """
    pass


@cli.group('bonjour')
def bonjour_cli():
    """ bonjour options """
    pass


@bonjour_cli.command('browse')
@click.option('--timeout', default=DEFAULT_BROWSE_TIMEOUT, type=click.INT)
@click.option('--pair-records', type=click.Path(dir_okay=True, file_okay=False, exists=True),
              help='pair records to attempt validation with')
@click.option('--color/--no-color', default=True)
def cli_browse(timeout: int, pair_records: str, color: bool):
    """ browse devices over bonjour """
    records = []
    if pair_records is not None:
        for record in Path(pair_records).glob('*.plist'):
            records.append(plistlib.loads(record.read_bytes()))

    output = []
    for device in browse(timeout, pair_records=records).values():
        device = device.asdict()
        output.append(device)

    print_json(output, colored=color)
