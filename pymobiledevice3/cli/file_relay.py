from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.services.file_relay import (
    DEFAULT_SOURCE,
    KNOWN_SOURCES,
    FileRelayService,
    file_relay_unsupported_message,
    is_file_relay_likely_supported,
)

cli = InjectingTyper(
    name="file-relay",
    help="Request compressed CPIO archives from the legacy file_relay service.",
    no_args_is_help=True,
)

OutputPathArg = Annotated[
    Path,
    typer.Argument(
        dir_okay=False,
        help="Local output archive path.",
    ),
]
SourceOption = Annotated[
    Optional[list[str]],
    typer.Option(
        "--source",
        "-s",
        help=f"File relay source to request. Repeat to request multiple sources. Defaults to {DEFAULT_SOURCE}.",
    ),
]


@cli.command("list-sources")
def file_relay_list_sources() -> None:
    """List source names commonly accepted by the legacy file_relay service."""
    for source in KNOWN_SOURCES:
        print(source)


@cli.command("request")
@async_command
async def file_relay_request(
    service_provider: ServiceProviderDep,
    out: OutputPathArg,
    sources: SourceOption = None,
    timeout: Annotated[
        Optional[float],
        typer.Option(
            "--timeout",
            help="Seconds to wait for the device to acknowledge the source request.",
        ),
    ] = 60.0,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite the output archive if it already exists.",
        ),
    ] = False,
    allow_unsupported: Annotated[
        bool,
        typer.Option(
            "--allow-unsupported",
            help="Try the request even when the device iOS version is unlikely to support file_relay.",
        ),
    ] = False,
) -> None:
    """Request selected file_relay sources and save the returned compressed CPIO archive."""
    if out.exists() and not force:
        raise typer.BadParameter(f"output already exists: {out}", param_hint="OUT")

    if not allow_unsupported and not is_file_relay_likely_supported(service_provider.product_version):
        typer.echo(file_relay_unsupported_message(service_provider.product_version), err=True)
        raise typer.Exit(2)

    out.parent.mkdir(parents=True, exist_ok=True)
    async with FileRelayService(service_provider) as service:
        archive_stream = service.iter_sources(sources, timeout=timeout)
        try:
            first_chunk = await archive_stream.__anext__()
        except StopAsyncIteration:
            first_chunk = b""

        with out.open("wb") as archive:
            if first_chunk:
                archive.write(first_chunk)
            async for chunk in archive_stream:
                archive.write(chunk)
