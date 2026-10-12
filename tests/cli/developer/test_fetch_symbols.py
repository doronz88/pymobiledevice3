from types import SimpleNamespace
from typing import Any, cast

import pytest

from pymobiledevice3.cli.developer import fetch_symbols
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.remote_fetch_symbols import DSCFile, RemoteFetchSymbolsService


@pytest.mark.asyncio
async def test_download_into_xcode_device_support_symbols_directory(monkeypatch, tmp_path):
    device_support_path = tmp_path / "DeviceSupport" / "iPhone15,2 16.0 (20A362)"
    layout_root = None

    class FakeDtFetchSymbols:
        def __init__(self, service_provider):
            pass

        async def list_files(self):
            return ["/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e"]

        async def get_file(self, fileno, stream):
            stream.write(b"symbols")

    def create_device_support_layout(product_type, product_version, product_build_version, root_path):
        nonlocal layout_root
        layout_root = root_path
        (device_support_path / "Info.plist").write_bytes(b"plist")

    monkeypatch.setattr(fetch_symbols, "DtFetchSymbols", FakeDtFetchSymbols)
    monkeypatch.setattr(fetch_symbols, "get_device_support_path", lambda *args: device_support_path)
    monkeypatch.setattr(fetch_symbols, "create_device_support_layout", create_device_support_layout)

    service_provider = cast(
        LockdownServiceProvider,
        SimpleNamespace(
            product_type="iPhone15,2",
            product_version="16.0",
            product_build_version="20A362",
        ),
    )

    await fetch_symbols.fetch_symbols_download_task(service_provider)

    symbols_path = device_support_path / "Symbols"
    assert layout_root == symbols_path
    assert (symbols_path / "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e").read_bytes() == b"symbols"
    assert (device_support_path / "Info.plist").read_bytes() == b"plist"


@pytest.mark.asyncio
@pytest.mark.parametrize("force", [False, True])
async def test_download_keeps_finalized_device_support_unless_forced(monkeypatch, tmp_path, force):
    device_support_path = tmp_path / "DeviceSupport" / "iPhone15,2 16.0 (20A362)"
    frameworks = device_support_path / "Symbols/System/Library/Frameworks"
    frameworks.mkdir(parents=True)
    (frameworks / "stale").write_bytes(b"stale")
    (device_support_path / ".finalized").touch()
    downloads = 0

    class FakeDtFetchSymbols:
        def __init__(self, service_provider):
            pass

        async def list_files(self):
            return ["/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e"]

        async def get_file(self, fileno, stream):
            nonlocal downloads
            downloads += 1

    monkeypatch.setattr(fetch_symbols, "DtFetchSymbols", FakeDtFetchSymbols)
    monkeypatch.setattr(fetch_symbols, "get_device_support_path", lambda *args: device_support_path)
    monkeypatch.setattr(fetch_symbols, "create_device_support_layout", lambda *args: None)

    service_provider = cast(
        LockdownServiceProvider,
        SimpleNamespace(product_type="iPhone15,2", product_version="16.0", product_build_version="20A362"),
    )

    await fetch_symbols.fetch_symbols_download_task(service_provider, force=force)

    assert downloads == (1 if force else 0)
    assert (frameworks / "stale").exists() != force


@pytest.mark.asyncio
async def test_download_redoes_device_support_which_was_never_split(monkeypatch, tmp_path):
    device_support_path = tmp_path / "DeviceSupport" / "iPhone15,2 16.0 (20A362)"
    (device_support_path / "Symbols/System/Cryptexes").mkdir(parents=True)
    (device_support_path / ".finalized").touch()
    downloads = 0

    class FakeDtFetchSymbols:
        def __init__(self, service_provider):
            pass

        async def list_files(self):
            return ["/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e"]

        async def get_file(self, fileno, stream):
            nonlocal downloads
            downloads += 1

    monkeypatch.setattr(fetch_symbols, "DtFetchSymbols", FakeDtFetchSymbols)
    monkeypatch.setattr(fetch_symbols, "get_device_support_path", lambda *args: device_support_path)
    monkeypatch.setattr(fetch_symbols, "create_device_support_layout", lambda *args: None)

    service_provider = cast(
        LockdownServiceProvider,
        SimpleNamespace(product_type="iPhone15,2", product_version="16.0", product_build_version="20A362"),
    )

    await fetch_symbols.fetch_symbols_download_task(service_provider)

    assert downloads == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("force", [False, True])
async def test_remote_download_keeps_files_of_the_reported_size_unless_forced(tmp_path, force):
    files = [DSCFile("/dsc/complete", 4), DSCFile("/dsc/partial", 4), DSCFile("/dsc/missing", 4)]
    (tmp_path / "dsc").mkdir()
    (tmp_path / "dsc/complete").write_bytes(b"old!")
    (tmp_path / "dsc/partial").write_bytes(b"ol")
    requested = []

    async def chunks(size, file_idx):
        requested.append(file_idx)
        yield b"new!"

    async def get_dsc_file_list():
        return files

    service = object.__new__(RemoteFetchSymbolsService)
    service._service = cast(Any, SimpleNamespace(iter_file_chunks=chunks))
    service.get_dsc_file_list = get_dsc_file_list  # pyright: ignore[reportAttributeAccessIssue]

    await service.download(tmp_path, force=force)

    assert sorted(requested) == ([0, 1, 2] if force else [1, 2])
    assert (tmp_path / "dsc/complete").read_bytes() == (b"new!" if force else b"old!")
    assert (tmp_path / "dsc/partial").read_bytes() == b"new!"
    assert (tmp_path / "dsc/missing").read_bytes() == b"new!"
