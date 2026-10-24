import logging
from io import BytesIO
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock
from zipfile import ZIP_STORED, ZipFile

import pytest

from pymobiledevice3.services import installation_proxy
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.installation_proxy import InstallationProxyService


def _service(replies: list[dict[str, Any]]) -> InstallationProxyService:
    service = InstallationProxyService.__new__(InstallationProxyService)
    service.logger = logging.getLogger(__name__)
    connection = AsyncMock()
    connection.recv_plist.side_effect = replies
    service._service = connection
    return service


_PROGRESS = [{"PercentComplete": 50}, {"Status": "Complete"}]


@pytest.mark.parametrize(
    "operation",
    [
        lambda service, handler: service.restore("com.example", None, handler, "a", "b"),
        lambda service, handler: service.uninstall("com.example", None, handler, "a", "b"),
        lambda service, handler: service.send_package("Install", {}, handler, "/x.ipa", "a", "b"),
    ],
)
async def test_progress_handler_gets_the_extra_args_unpacked(operation: Any) -> None:
    calls: list[tuple[Any, ...]] = []
    await operation(_service(list(_PROGRESS)), lambda *args: calls.append(args))
    assert calls == [(50, "a", "b")]


_MIB = 1024 * 1024


class _FakeAfc(AfcService):
    def __init__(self, fail_on_write: int = 0) -> None:
        self.files: dict[str, bytearray] = {}
        self.open_handles: dict[int, str] = {}
        self.removed: list[str] = []
        self.fail_on_write = fail_on_write
        self.writes = 0

    async def __aenter__(self) -> "_FakeAfc":
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        pass

    async def makedirs(self, filename: str, mode: int = 0) -> bytes:
        return b""

    async def fopen(self, filename: str, mode: str = "r") -> int:
        handle = len(self.open_handles) + len(self.files) + 1
        self.open_handles[handle] = filename
        self.files[filename] = bytearray()
        return handle

    async def fwrite(self, handle: int, data: bytes, chunk_size: int = 0) -> None:
        self.writes += 1
        if self.writes == self.fail_on_write:
            raise ConnectionError("transfer interrupted")
        self.files[self.open_handles[handle]] += data

    async def fclose(self, handle: int) -> bytes:
        del self.open_handles[handle]
        return b""

    async def rm_single(self, filename: str, force: bool = False) -> bool:
        self.removed.append(filename)
        return True


def _install_service(monkeypatch: pytest.MonkeyPatch, afc: _FakeAfc, replies: list[dict[str, Any]]) -> Any:
    monkeypatch.setattr(installation_proxy, "AfcService", lambda lockdown: afc)
    service = _service(replies)
    service.lockdown = cast(Any, object())
    return service


def _ipa(payload: bytes) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_STORED) as archive:
        archive.writestr("Payload/Example.app/data", payload)
    return buffer.getvalue()


@pytest.mark.parametrize("from_bytes", [True, False])
async def test_ipa_upload_is_byte_identical_and_temp_file_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, from_bytes: bool
) -> None:
    package = _ipa(b"p" * (9 * _MIB + 123))
    afc = _FakeAfc()
    service = _install_service(monkeypatch, afc, list(_PROGRESS))

    if from_bytes:
        await service.install_from_bytes(package)
    else:
        path = tmp_path / "Example.ipa"
        path.write_bytes(package)
        await service.install_from_local(path)

    ((remote_path, uploaded),) = afc.files.items()
    assert bytes(uploaded) == package
    assert not afc.open_handles
    assert afc.removed == [remote_path]


async def test_failed_upload_closes_the_file_and_removes_the_temp_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "Example.ipa"
    path.write_bytes(_ipa(b"p" * (9 * _MIB)))
    afc = _FakeAfc(fail_on_write=2)
    service = _install_service(monkeypatch, afc, list(_PROGRESS))

    with pytest.raises(ConnectionError, match="transfer interrupted"):
        await service.install_from_local(path)

    ((remote_path, _),) = afc.files.items()
    assert not afc.open_handles
    assert afc.removed == [remote_path]
    service.service.send_plist.assert_not_called()
