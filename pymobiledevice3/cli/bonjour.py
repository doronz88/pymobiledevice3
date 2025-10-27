import asyncio
from typing import Optional

import click

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remotepairing, browse_remotepairing_manual_pairing
from pymobiledevice3.cli.cli_common import BaseCommand, print_json
from pymobiledevice3.cli.remote import browse_rsd
from pymobiledevice3.lockdown import get_mobdev2_lockdowns


@click.group()
def cli() -> None:
    pass


@cli.group("bonjour")
def bonjour_cli() -> None:
    """Browse devices over bonjour"""
    pass


async def cli_mobdev2_task(timeout: float, pair_records: Optional[str]) -> None:
    output = []
    async for ip, lockdown in get_mobdev2_lockdowns(timeout=timeout, pair_records=pair_records):
        short_info = lockdown.short_info
        short_info["ip"] = ip
        output.append(short_info)
    print_json(output)


@bonjour_cli.command("mobdev2", cls=BaseCommand)
@click.option("--timeout", default=DEFAULT_BONJOUR_TIMEOUT, type=click.INT)
@click.option(
    "--pair-records",
    type=click.Path(dir_okay=True, file_okay=False, exists=True),
    help="pair records to attempt validation with",
)
def cli_mobdev2(timeout: float, pair_records: Optional[str]) -> None:
    """browse for mobdev2 devices over bonjour"""
    asyncio.run(cli_mobdev2_task(timeout, pair_records))


async def cli_remotepairing_task(timeout: float) -> None:
    output = []
    for answer in await browse_remotepairing(timeout=timeout):
        for address in answer.addresses:
            output.append({"hostname": address.full_ip, "port": answer.port})
    print_json(output)


@bonjour_cli.command("remotepairing", cls=BaseCommand)
@click.option("--timeout", default=DEFAULT_BONJOUR_TIMEOUT, type=click.FLOAT)
def cli_remotepairing(timeout: float) -> None:
    """browse for remotepairing devices over bonjour (without attempting pair verification)"""
    asyncio.run(cli_remotepairing_task(timeout=timeout))


async def cli_remotepairing_manual_pairing_task(timeout: float) -> None:
    output = []
    for answer in await browse_remotepairing_manual_pairing(timeout=timeout):
        for address in answer.addresses:
            output.append({
                "hostname": address.full_ip,
                "port": answer.port,
                "name": answer.properties[b"name"].decode(),
            })
    print_json(output)


@bonjour_cli.command("remotepairing-manual-pairing", cls=BaseCommand)
@click.option("--timeout", default=DEFAULT_BONJOUR_TIMEOUT, type=click.FLOAT)
def cli_remotepairing_manual_pairing(timeout: float) -> None:
    """browse for remotepairing-manual-pairing devices over bonjour"""
    asyncio.run(cli_remotepairing_manual_pairing_task(timeout=timeout))


async def cli_browse_rsd() -> None:
    print_json(await browse_rsd())


@bonjour_cli.command("rsd", cls=BaseCommand)
def cli_rsd() -> None:
    """browse RemoteXPC devices using bonjour"""
    asyncio.run(cli_browse_rsd(), debug=True)
