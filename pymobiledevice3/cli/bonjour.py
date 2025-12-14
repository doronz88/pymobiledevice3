import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remotepairing, browse_remotepairing_manual_pairing
from pymobiledevice3.cli.cli_common import print_json
from pymobiledevice3.cli.remote import browse_rsd
from pymobiledevice3.lockdown import get_mobdev2_lockdowns

cli = InjectingTyper(
    name="bonjour",
    help="Browse devices over bonjour",
    no_args_is_help=True,
)


async def cli_mobdev2_task(timeout: float, pair_records: Optional[Path]) -> None:
    output = []
    async for ip, lockdown in get_mobdev2_lockdowns(timeout=timeout, pair_records=pair_records):
        short_info = lockdown.short_info
        short_info["ip"] = ip
        output.append(short_info)
    print_json(output)


@cli.command("mobdev2")
def cli_mobdev2(
    timeout: Annotated[float, typer.Option()] = DEFAULT_BONJOUR_TIMEOUT,
    pair_records: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            dir_okay=True,
            file_okay=True,
            help="pair records to attempt validation with",
        ),
    ] = None,
) -> None:
    """browse for mobdev2 devices over bonjour"""
    asyncio.run(cli_mobdev2_task(timeout, pair_records))


async def cli_remotepairing_task(timeout: float) -> None:
    output = []
    for answer in await browse_remotepairing(timeout=timeout):
        for address in answer.addresses:
            output.append({"hostname": address.full_ip, "port": answer.port})
    print_json(output)


@cli.command("remotepairing")
def cli_remotepairing(timeout: Annotated[float, typer.Option()] = DEFAULT_BONJOUR_TIMEOUT) -> None:
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


@cli.command("remotepairing-manual-pairing")
def cli_remotepairing_manual_pairing(
    timeout: Annotated[float, typer.Option()] = DEFAULT_BONJOUR_TIMEOUT,
) -> None:
    """browse for remotepairing-manual-pairing devices over bonjour"""
    asyncio.run(cli_remotepairing_manual_pairing_task(timeout=timeout))


async def cli_browse_rsd() -> None:
    print_json(await browse_rsd())


@cli.command("rsd")
def cli_rsd() -> None:
    """browse RemoteXPC devices using bonjour"""
    asyncio.run(cli_browse_rsd(), debug=True)
