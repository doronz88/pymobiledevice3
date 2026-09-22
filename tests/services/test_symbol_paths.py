import asyncio
from unittest.mock import Mock

import pytest

from pymobiledevice3.cli.developer import fetch_symbols
from pymobiledevice3.exceptions import DevicePathError
from pymobiledevice3.services.remote_fetch_symbols import DSCFile, RemoteFetchSymbolsService


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["/../../victim", "//host/share", r"/C:\victim", "/link/victim"])
@pytest.mark.parametrize("remote", [False, True])
async def test_symbol_download_rejects_escape(tmp_path, monkeypatch, name, remote):
    out = tmp_path / "out"
    out.mkdir()
    (out / "link").symlink_to(tmp_path)
    if remote:
        service = object.__new__(RemoteFetchSymbolsService)
        queue = asyncio.Queue()
        queue.put_nowait(0)
        with pytest.raises(DevicePathError):
            await service._download_files([DSCFile(name, 4)], queue, out, Mock())
    else:

        class FakeSymbols:
            def __init__(self, provider):
                pass

            async def list_files(self):
                return [name]

        monkeypatch.setattr(fetch_symbols, "DtFetchSymbols", FakeSymbols)
        with pytest.raises(DevicePathError):
            await fetch_symbols.fetch_symbols_download_task(Mock(product_version="16.0"), out)
    assert not (tmp_path / "victim").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["/System/Library/cache", "System/Library/cache"])
async def test_remote_symbol_download_preserves_layout(tmp_path, name):
    async def chunks(*args, **kwargs):
        yield b"data"

    service = object.__new__(RemoteFetchSymbolsService)
    service._service = Mock(iter_file_chunks=chunks)
    queue = asyncio.Queue()
    queue.put_nowait(0)
    await service._download_files([DSCFile(name, 4)], queue, tmp_path, Mock())
    assert (tmp_path / "System/Library/cache").read_bytes() == b"data"
