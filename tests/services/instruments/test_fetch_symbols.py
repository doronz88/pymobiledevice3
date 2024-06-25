from pathlib import Path

import pytest
from packaging.version import Version

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dtfetchsymbols import DtFetchSymbols
from pymobiledevice3.services.remote_fetch_symbols import RemoteFetchSymbolsService


@pytest.mark.asyncio
async def test_fetch_symbols_list(service_provider):
    """
    Test listing of device symbol files
    """
    if Version(service_provider.product_version) < Version('17.0'):
        DtFetchSymbols(service_provider).list_files()
    else:
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            pytest.skip('requires RemoteServiceDiscoveryService')

        async with RemoteFetchSymbolsService(service_provider) as fetch_symbols:
            assert len(await fetch_symbols.get_dsc_file_list()) > 0


@pytest.mark.asyncio
async def test_fetch_symbols_download(service_provider, tmp_path):
    """
    Test download of device symbol files
    """
    if Version(service_provider.product_version) < Version('17.0'):
        tmp_file = Path(tmp_path) / 'tmp'
        with tmp_file.open('wb') as file:
            DtFetchSymbols(service_provider).get_file(0, file)
    else:
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            pytest.skip('requires RemoteServiceDiscoveryService')

        async with RemoteFetchSymbolsService(service_provider) as fetch_symbols:
            await fetch_symbols.download(tmp_path)
