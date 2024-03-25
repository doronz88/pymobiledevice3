import asyncio
import plistlib
from pathlib import Path

import click

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_mobdev2, browse_remotepairing
from pymobiledevice3.cli.cli_common import BaseCommand, print_json
from pymobiledevice3.cli.remote import browse_rsd
from pymobiledevice3.lockdown import create_using_tcp


@click.group()
def cli():
    """ bonjour cli """
    pass


@cli.group('bonjour')
def bonjour_cli():
    """ bonjour options """
    pass


async def cli_mobdev2_task(timeout: float, pair_records: str) -> None:
    records = []
    if pair_records is not None:
        for record in Path(pair_records).glob('*.plist'):
            records.append(plistlib.loads(record.read_bytes()))
    output = []
    for answer in await browse_mobdev2():
        for ip in answer.ips:
            try:
                lockdown = create_using_tcp(hostname=ip, autopair=False)
                for pair_record in records:
                    lockdown = create_using_tcp(hostname=ip, autopair=False, pair_record=pair_record)
                    if lockdown.paired:
                        break
                output.append(lockdown.short_info)
            except ConnectionRefusedError:
                continue
    print_json(output)


@bonjour_cli.command('mobdev2', cls=BaseCommand)
@click.option('--timeout', default=DEFAULT_BONJOUR_TIMEOUT, type=click.INT)
@click.option('--pair-records', type=click.Path(dir_okay=True, file_okay=False, exists=True),
              help='pair records to attempt validation with')
def cli_mobdev2(timeout: float, pair_records: str) -> None:
    """ browse for mobdev2 devices over bonjour """
    asyncio.run(cli_mobdev2_task(timeout, pair_records))


async def cli_remotepairing_task(timeout: float) -> None:
    output = []
    for answer in await browse_remotepairing(timeout=timeout):
        for ip in answer.ips:
            output.append({'hostname': ip, 'port': answer.port})
    print_json(output)


@bonjour_cli.command('remotepairing', cls=BaseCommand)
@click.option('--timeout', default=DEFAULT_BONJOUR_TIMEOUT, type=click.FLOAT)
def cli_remotepairing(timeout: float) -> None:
    """ browse for remotepairing devices over bonjour (without attempting pair verification) """
    asyncio.run(cli_remotepairing_task(timeout=timeout))


async def cli_browse_rsd() -> None:
    print_json(await browse_rsd())


@bonjour_cli.command('rsd', cls=BaseCommand)
def cli_rsd() -> None:
    """ browse RemoteXPC devices using bonjour """
    asyncio.run(cli_browse_rsd(), debug=True)
