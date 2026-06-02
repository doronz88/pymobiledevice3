import asyncio
from types import MethodType

import pytest

from pymobiledevice3.services.remote_fetch_symbols import DSCFile, RemoteFetchSymbolsService


@pytest.mark.asyncio
async def test_download_uses_multiple_streams(tmp_path):
    files = [DSCFile(file_path=f"/file{i}", file_size=1) for i in range(4)]
    active_downloads = 0
    max_active_downloads = 0

    class FakeConnection:
        async def iter_file_chunks(self, file_size, file_idx):
            nonlocal active_downloads, max_active_downloads
            active_downloads += 1
            max_active_downloads = max(max_active_downloads, active_downloads)
            await asyncio.sleep(0)
            yield str(file_idx).encode()
            active_downloads -= 1

    async def get_dsc_file_list(self):
        return files

    fetch_symbols = object.__new__(RemoteFetchSymbolsService)
    fetch_symbols.rsd = object()
    fetch_symbols.service = FakeConnection()
    fetch_symbols.get_dsc_file_list = MethodType(get_dsc_file_list, fetch_symbols)

    await RemoteFetchSymbolsService.download(fetch_symbols, tmp_path)

    assert max_active_downloads > 1
    for i in range(4):
        assert (tmp_path / f"file{i}").read_bytes() == str(i).encode()
