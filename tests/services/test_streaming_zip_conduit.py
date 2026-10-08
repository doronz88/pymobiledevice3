import os
import plistlib
import stat
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services import streaming_zip_conduit
from pymobiledevice3.services.streaming_zip_conduit import StreamingZipConduitError, StreamingZipConduitService

HEADER = struct.Struct("<IHHHHHIIIHH")


class FakeConnection:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.setup: dict[str, Any] = {}
        self.stream = b""
        self._responses = list(responses)

    async def send_plist(self, message: dict[str, Any]) -> None:
        self.setup = message

    async def sendall(self, data: bytes) -> None:
        self.stream += data

    async def recv_plist(self) -> dict[str, Any]:
        return self._responses.pop(0)


def _service(responses: list[dict[str, Any]]) -> tuple[StreamingZipConduitService, FakeConnection]:
    connection = FakeConnection(responses)
    service = StreamingZipConduitService(cast(LockdownServiceProvider, object()))
    service._service = cast(ServiceConnection, connection)
    return service, connection


def _parse(stream: bytes) -> list[tuple[str, int, bytes, bytes]]:
    """Split a stream into ``(name, compression, extra, content)`` records; it must end at the terminator."""
    records, offset = [], 0
    while stream[offset : offset + 4] != b"PK\x01\x02":
        signature, _, flags, method, _, _, crc, compressed, size, name_len, extra_len = HEADER.unpack_from(
            stream, offset
        )
        assert signature == 0x04034B50 and flags == 0 and compressed == size
        offset += HEADER.size
        name = stream[offset : offset + name_len].decode()
        extra = stream[offset + name_len : offset + name_len + extra_len]
        offset += name_len + extra_len
        content = stream[offset : offset + size]
        assert zlib.crc32(content) == crc
        offset += size
        records.append((name, method, extra, content))
    assert offset + 4 == len(stream)
    return records


def _make_app(root: Path) -> Path:
    app = root / "Demo.app"
    (app / "Frameworks").mkdir(parents=True)
    (app / "Info.plist").write_bytes(b"info")
    executable = app / "Demo"
    executable.write_bytes(b"binary")
    if os.name != "nt":
        (app / "Info.plist").chmod(0o644)
        (app / "Frameworks").chmod(0o755)
        app.chmod(0o755)
        executable.chmod(0o755)
        os.symlink("Demo", app / "Frameworks" / "link")
    return app


@pytest.mark.skipif(os.name == "nt", reason="needs unix permission bits and symlinks")
@pytest.mark.asyncio
async def test_install_streams_an_app_directory(tmp_path: Path) -> None:
    service, connection = _service([{"Status": "DataComplete"}])

    await service.install(_make_app(tmp_path), developer=True)

    assert connection.setup["InstallTransferredDirectory"] is True
    assert connection.setup["InstallOptionsDictionary"] == {"PackageType": "Developer"}
    assert connection.setup["MediaSubdir"].startswith("PublicStaging/")
    records = {name: (method, extra, content) for name, method, extra, content in _parse(connection.stream)}
    assert list(records)[:2] == ["META-INF/", "META-INF/com.apple.ZipMetadata.plist"]
    assert all(method == zipfile.ZIP_STORED for method, _, _ in records.values())
    # A file with the standard mode carries no extra; the executable and the link carry their mode.
    assert records["Payload/Demo.app/Info.plist"] == (0, b"", b"info")
    assert records["Payload/Demo.app/Demo"][1] == b"SZ" + struct.pack("<HH", 2, stat.S_IFREG | 0o755)
    link = records["Payload/Demo.app/Frameworks/link"]
    assert stat.S_ISLNK(struct.unpack("<H", link[1][4:])[0]) and link[2] == b"Demo"
    metadata = plistlib.loads(records["META-INF/com.apple.ZipMetadata.plist"][2])
    assert metadata["Version"] == 2 and metadata["RecordCount"] == len(records)
    assert metadata["TotalUncompressedBytes"] == len(b"info") + len(b"binary") + len(b"Demo")


@pytest.mark.asyncio
async def test_files_are_sent_executable_where_modes_do_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(streaming_zip_conduit, "_HAS_PERMISSION_BITS", False)
    service, connection = _service([{"Status": "DataComplete"}])
    app = tmp_path / "Demo.app"
    app.mkdir()
    (app / "Demo").write_bytes(b"binary")

    await service.install(app)

    records = {name: extra for name, _, extra, _ in _parse(connection.stream)}
    assert records["Payload/Demo.app/Demo"] == b"SZ" + struct.pack("<HH", 2, stat.S_IFREG | 0o755)
    assert records["Payload/Demo.app/"] == b""


@pytest.mark.asyncio
async def test_install_streams_an_ipa_uncompressed(tmp_path: Path) -> None:
    ipa = tmp_path / "demo.ipa"
    with zipfile.ZipFile(ipa, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Payload/Demo.app/data", b"a" * 5000)
        executable = zipfile.ZipInfo("Payload/Demo.app/Demo")
        executable.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(executable, b"binary")
    service, connection = _service([{"Status": "DataComplete"}])

    await service.install(ipa)

    records = {name: (extra, content) for name, _, extra, content in _parse(connection.stream)}
    assert connection.setup["InstallOptionsDictionary"] == {"PackageType": "Customer"}
    assert records["Payload/Demo.app/data"] == (b"", b"a" * 5000)
    assert records["Payload/Demo.app/Demo"] == (b"SZ" + struct.pack("<HH", 2, stat.S_IFREG | 0o755), b"binary")


@pytest.mark.asyncio
async def test_install_reports_progress_until_complete(tmp_path: Path) -> None:
    service, _ = _service([
        {"InstallProgressDict": {"Status": "Installing", "PercentComplete": 40}},
        {"InstallProgressDict": {"Status": "Installing", "PercentComplete": 90}},
        {"Status": "DataComplete"},
    ])
    progress: list[int] = []

    await service.install(_make_app(tmp_path), handler=progress.append)

    assert progress == [40, 90]


@pytest.mark.asyncio
async def test_install_raises_on_an_installation_error(tmp_path: Path) -> None:
    service, _ = _service([
        {"InstallProgressDict": {"Error": "ApplicationVerificationFailed", "ErrorDescription": "bad signature"}}
    ])

    with pytest.raises(AppInstallError, match="ApplicationVerificationFailed: bad signature"):
        await service.install(_make_app(tmp_path))


@pytest.mark.asyncio
async def test_install_raises_on_a_transfer_error(tmp_path: Path) -> None:
    service, _ = _service([{"Error": "NoSpace"}])

    with pytest.raises(StreamingZipConduitError) as error:
        await service.install(_make_app(tmp_path))

    assert error.value.error == "NoSpace"
