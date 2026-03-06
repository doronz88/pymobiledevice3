from pathlib import Path

import pytest
from packaging.version import Version

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dtfetchsymbols import DtFetchSymbols
from pymobiledevice3.services.remote_fetch_symbols import RemoteFetchSymbolsService


@pytest.mark.asyncio
async def test_fetch_symbols_list(service_provider: LockdownServiceProvider) -> None:
    """
    Test listing of device symbol files
    """
    if Version(service_provider.product_version) < Version("17.0"):
        assert len(await DtFetchSymbols(service_provider).list_files()) > 0
    else:
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            pytest.skip("requires RemoteServiceDiscoveryService")

        async with RemoteFetchSymbolsService(service_provider) as fetch_symbols:
            assert len(await fetch_symbols.get_dsc_file_list()) > 0


@pytest.mark.asyncio
async def test_fetch_symbols_download(service_provider: LockdownServiceProvider, tmp_path: Path) -> None:
    """
    Test that the download mechanism can transfer data from the device.
    Only probes a small amount to verify the transfer protocol works without
    downloading entire symbol files (which can be several GB).
    """
    _PROBE_BYTES = 64 * 1024  # 64 KB is enough to confirm data flows

    if Version(service_provider.product_version) < Version("17.0"):
        tmp_file = Path(tmp_path) / "tmp"
        with tmp_file.open("wb") as file:
            await DtFetchSymbols(service_provider).get_file(0, file, max_bytes=_PROBE_BYTES)
        assert tmp_file.stat().st_size > 0
    else:
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            pytest.skip("requires RemoteServiceDiscoveryService")

        async with RemoteFetchSymbolsService(service_provider) as fetch_symbols:
            files = await fetch_symbols.get_dsc_file_list()
            assert len(files) > 0
            # Receive just the first chunk of the first file to confirm data transfer works.
            received = 0
            async for chunk in fetch_symbols.service.iter_file_chunks(files[0].file_size, file_idx=0):
                received += len(chunk)
                break
            assert received > 0
