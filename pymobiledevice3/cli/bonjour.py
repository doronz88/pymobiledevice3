from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remotepairing, browse_remotepairing_manual_pairing
from pymobiledevice3.cli.cli_common import async_command, print_json
from pymobiledevice3.cli.remote import browse_rsd
from pymobiledevice3.lockdown import get_mobdev2_lockdowns

cli = InjectingTyper(
    name="bonjour",
    help="Discover devices on the local network over bonjour (mDNS).",
    no_args_is_help=True,
)


@cli.command("mobdev2")
@async_command
async def cli_mobdev2(
    timeout: Annotated[float, typer.Option(help="How long to browse, in seconds.")] = DEFAULT_BONJOUR_TIMEOUT,
    pair_records: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            dir_okay=True,
            file_okay=True,
            help="Pair record file, or directory of them, to try against discovered devices "
            "(default: this host's pair records).",
        ),
    ] = None,
) -> None:
    """Find Wi-Fi-reachable devices advertising lockdown (mobdev2) and print their info."""
    output: list[dict[str, Any]] = []
    async for ip, lockdown in get_mobdev2_lockdowns(timeout=timeout, pair_records=pair_records):
        short_info = lockdown.short_info
        short_info["ip"] = ip
        output.append(short_info)
    print_json(output)


@cli.command("remotepairing")
@async_command
async def cli_remotepairing(
    timeout: Annotated[float, typer.Option(help="How long to browse, in seconds.")] = DEFAULT_BONJOUR_TIMEOUT,
) -> None:
    """List addresses advertising RemotePairing (iOS 17+ Wi-Fi tunnels), without verifying pairing."""
    output: list[dict[str, Any]] = []
    for answer in await browse_remotepairing(timeout=timeout):
        for address in answer.addresses:
            output.append({"hostname": address.full_ip, "port": answer.port})
    print_json(output)


@cli.command("remotepairing-manual-pairing")
@async_command
async def cli_remotepairing_manual_pairing(
    timeout: Annotated[float, typer.Option(help="How long to browse, in seconds.")] = DEFAULT_BONJOUR_TIMEOUT,
) -> None:
    """List devices offering manual pairing (e.g. Apple TV); pair with `remote pair`."""
    output: list[dict[str, Any]] = []
    for answer in await browse_remotepairing_manual_pairing(timeout=timeout):
        for address in answer.addresses:
            output.append({
                "hostname": address.full_ip,
                "port": answer.port,
                "name": answer.properties["name"],
            })
    print_json(output)


async def cli_browse_rsd() -> None:
    print_json(await browse_rsd())


@cli.command("rsd")
@async_command
async def cli_rsd() -> None:
    """List iOS 17+ devices whose RemoteServiceDiscovery (RSD) is reachable, via bonjour."""
    await cli_browse_rsd()
