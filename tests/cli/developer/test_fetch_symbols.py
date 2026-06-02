from types import SimpleNamespace

import pytest

from pymobiledevice3.cli.developer import fetch_symbols


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

    service_provider = SimpleNamespace(
        product_type="iPhone15,2",
        product_version="16.0",
        product_build_version="20A362",
    )

    await fetch_symbols.fetch_symbols_download_task(service_provider)

    symbols_path = device_support_path / "Symbols"
    assert layout_root == symbols_path
    assert (symbols_path / "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e").read_bytes() == b"symbols"
    assert (device_support_path / "Info.plist").read_bytes() == b"plist"
