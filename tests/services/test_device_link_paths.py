import ctypes
import errno
import os
import plistlib
import struct
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from pymobiledevice3.exceptions import DevicePathError
from pymobiledevice3.services.device_link import DeviceLink
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,message",
    [
        ("download_files", ["", ["../victim"]]),
        ("contents_of_directory", ["", ".."]),
        ("create_directory", ["", "../new"]),
        ("remove_items", ["", ["../victim"]]),
        ("move_items", ["", {"../victim": "moved"}]),
        ("move_items", ["", {"local": "../victim"}]),
        ("copy_item", ["", "../victim", "copy"]),
        ("copy_item", ["", "local", "../victim"]),
    ],
)
async def test_operations_reject_escape(tmp_path, method, message):
    root = tmp_path / "backup"
    root.mkdir()
    (root / "local").write_bytes(b"local")
    victim = tmp_path / "victim"
    victim.write_bytes(b"secret")
    service = AsyncMock()
    link = DeviceLink(service, root)
    with pytest.raises(DevicePathError):
        await getattr(link, method)(message)
    assert victim.read_bytes() == b"secret"
    assert all(b"secret" not in call.args[0] for call in service.sendall.call_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize("preserve", [True, False])
async def test_upload_rejects_escape_before_writing(tmp_path, preserve):
    service = AsyncMock()
    link = DeviceLink(service, tmp_path, preserve_file=lambda *args: preserve)
    link._prefixed_recv = AsyncMock(side_effect=["device", "../victim"])
    service.recvall.side_effect = [struct.pack(">I", 5), b"\x0c"]
    with pytest.raises(DevicePathError):
        await link.upload_files([])
    assert not (tmp_path.parent / "victim").exists()


@pytest.mark.asyncio
async def test_valid_operations(tmp_path):
    link = DeviceLink(AsyncMock(), tmp_path)
    await link.create_directory(["", "device/sub"])
    (tmp_path / "device/sub/file").write_bytes(b"data")
    await link.copy_item(["", "device/sub/file", "device/copy"])
    await link.move_items(["", {"device/copy": "device/moved"}])
    assert (tmp_path / "device/moved").read_bytes() == b"data"
    await link.remove_items(["", ["device/moved"]])
    assert not (tmp_path / "device/moved").exists()


def test_backup_rejects_device_identifier():
    service = object.__new__(Mobilebackup2Service)
    service.lockdown = Mock(udid="../outside")
    with pytest.raises(DevicePathError):
        _ = service._udid


@pytest.mark.asyncio
async def test_directory_modification_date_is_utc(tmp_path):
    file = tmp_path / "file"
    file.touch()
    os.utime(file, (1760000000, 1760000000))
    service = AsyncMock()
    await DeviceLink(service, tmp_path).contents_of_directory(["", "."])
    response = service.send_plist.call_args.args[0]
    expected = datetime(2025, 10, 9, 8, 53, 20)
    assert response[3]["file"]["DLFileModificationDate"] == expected
    assert (
        plistlib.loads(plistlib.dumps(response, fmt=plistlib.FMT_BINARY))[3]["file"]["DLFileModificationDate"]
        == expected
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("error,expected", [(errno.ELOOP, -10), (errno.EACCES, -1)])
async def test_download_maps_host_errno(tmp_path, monkeypatch, error, expected):
    monkeypatch.setattr(Path, "open", Mock(side_effect=OSError(error, os.strerror(error))))
    service = AsyncMock()
    await DeviceLink(service, tmp_path).download_files(["", ["file"]])
    response = service.send_plist.call_args.args[0]
    assert response[:3] == ["DLMessageStatusResponse", ctypes.c_uint64(-13).value, "Multi status"]
    assert response[3]["file"]["DLFileErrorCode"] == ctypes.c_uint64(expected).value
    assert service.sendall.call_args_list[1].args[0][4] == 0x06  # CODE_ERROR_LOCAL
