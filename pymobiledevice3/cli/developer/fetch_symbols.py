import asyncio
import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
from ipsw_parser.dsc import create_device_support_layout, get_device_support_path
from packaging.version import Version
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.exceptions import RSDRequiredError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dtfetchsymbols import DtFetchSymbols
from pymobiledevice3.services.remote_fetch_symbols import RemoteFetchSymbolsService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="fetch-symbols",
    help="Download the DSC (and dyld) from the device",
    no_args_is_help=True,
)


async def fetch_symbols_list_task(service_provider: LockdownServiceProvider) -> None:
    if Version(service_provider.product_version) < Version("17.0"):
        print_json(DtFetchSymbols(service_provider).list_files())
    else:
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            raise RSDRequiredError(service_provider.identifier)

        async with RemoteFetchSymbolsService(service_provider) as fetch_symbols:
            print_json([f.file_path for f in await fetch_symbols.get_dsc_file_list()])


@cli.command("list")
def fetch_symbols_list(service_provider: ServiceProviderDep) -> None:
    """list of files to be downloaded"""
    asyncio.run(fetch_symbols_list_task(service_provider), debug=True)


async def fetch_symbols_download_task(service_provider: LockdownServiceProvider, out: Optional[Path] = None) -> None:
    should_create_device_support_layout = False
    if out is None:
        assert service_provider.product_type is not None  # for type checker
        out = get_device_support_path(
            service_provider.product_type, service_provider.product_version, service_provider.product_build_version
        )
        should_create_device_support_layout = True

    logger.info(f"Downloading DSC into: {out}")

    out.mkdir(parents=True, exist_ok=True)

    if Version(service_provider.product_version) < Version("17.0"):
        fetch_symbols = DtFetchSymbols(service_provider)
        files = fetch_symbols.list_files()

        downloaded_files = set()

        for i, file in enumerate(files):
            if file.startswith("/"):
                # trim root to allow relative download
                file = file[1:]
            file = out / file

            if file not in downloaded_files:
                # first time the file was seen in list, means we can safely remove any old copy if any
                file.unlink(missing_ok=True)

            downloaded_files.add(file)
            file.parent.mkdir(parents=True, exist_ok=True)
            with open(file, "ab") as f:
                # same file may appear twice, so we'll need to append data into it
                logger.info(f"writing to: {file}")
                fetch_symbols.get_file(i, f)
    else:
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            raise RSDRequiredError(service_provider.identifier)
        async with RemoteFetchSymbolsService(service_provider) as fetch_symbols:
            await fetch_symbols.download(out)

    if should_create_device_support_layout:
        assert service_provider.product_type is not None  # for type checker
        create_device_support_layout(
            service_provider.product_type, service_provider.product_version, service_provider.product_build_version, out
        )


@cli.command("download")
def fetch_symbols_download(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Optional[Path],
        typer.Argument(dir_okay=True, file_okay=False),
    ] = None,
) -> None:
    """
    Fetches symbols from the given device and saves them into Xcode DeviceSupport directory.

    This command downloads symbol data. Optionally, the user can specify an output directory where the data will
    be stored. If no output directory is provided, the symbols will be downloaded into the Xcode directory directly
    (DeviceSupport).
    """
    asyncio.run(fetch_symbols_download_task(service_provider, out), debug=True)
