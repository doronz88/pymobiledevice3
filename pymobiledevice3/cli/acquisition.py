import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.acquisition import build_acquisition_manifest, build_device_context
from pymobiledevice3.cli.cli_common import UDID_ENV_VAR, async_command, print_json
from pymobiledevice3.lockdown import create_using_usbmux

cli = InjectingTyper(
    name="acquisition",
    help="Create acquisition metadata for collected artifacts.",
    no_args_is_help=True,
)


@cli.callback()
def acquisition() -> None:
    """Create acquisition metadata for collected artifacts."""


@cli.command("manifest")
@async_command
async def acquisition_manifest(
    artifacts: Annotated[
        list[Path],
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=True,
            readable=True,
            resolve_path=True,
            help="Files or directories to include in the manifest.",
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            dir_okay=False,
            writable=True,
            help="Write manifest JSON to a file instead of stdout.",
        ),
    ] = None,
    include_device: Annotated[
        bool,
        typer.Option(help="Include non-identifying Lockdown device context from the connected USB device."),
    ] = False,
    include_identifiers: Annotated[
        bool,
        typer.Option(help="Include device identifiers such as UDID, serial number, ECID, and device name."),
    ] = False,
    udid: Annotated[
        Optional[str],
        typer.Option(
            "--udid",
            envvar=UDID_ENV_VAR,
            help="Target USB device UDID when including device context.",
        ),
    ] = None,
    hash_files: Annotated[
        bool,
        typer.Option(
            "--hash/--no-hash",
            help="Compute SHA-256 hashes for files and deterministic directory digests.",
        ),
    ] = True,
) -> None:
    """Create a JSON manifest for local acquisition artifacts."""
    device = None
    if include_device or include_identifiers:
        async with await create_using_usbmux(serial=udid) as lockdown:
            device = build_device_context(lockdown.all_values, include_identifiers=include_identifiers)

    manifest = build_acquisition_manifest(artifacts, device=device, hash_files=hash_files)
    if output is None:
        print_json(manifest)
    else:
        output.write_text(json.dumps(manifest, sort_keys=True, indent=4) + "\n")
