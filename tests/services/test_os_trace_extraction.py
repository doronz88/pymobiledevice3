import io
import tarfile

import pytest

from pymobiledevice3.exceptions import DevicePathError
from pymobiledevice3.services.os_trace import OsTraceService


async def collect_archive(tmp_path, name, kind=tarfile.REGTYPE, linkname=""):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = linkname
        member.size = 4 if kind == tarfile.REGTYPE else 0
        archive.addfile(member, io.BytesIO(b"data") if member.size else None)
    service = object.__new__(OsTraceService)

    async def create_archive(out, size_limit=None, age_limit=None, start_time=None):
        out.write(buf.getvalue())

    service.create_archive = create_archive
    await service.collect(str(tmp_path / "out"))


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["../victim", "/absolute", r"C:\victim", r"..\victim"])
async def test_rejects_archive_traversal(tmp_path, name):
    with pytest.raises(DevicePathError):
        await collect_archive(tmp_path, name)
    assert not (tmp_path / "victim").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE])
async def test_rejects_links_and_special_entries(tmp_path, kind):
    with pytest.raises(DevicePathError):
        await collect_archive(tmp_path, "link", kind, "../victim")
    assert not (tmp_path / "out/link").exists()


@pytest.mark.asyncio
async def test_extracts_regular_nested_file(tmp_path):
    await collect_archive(tmp_path, "./logs/file")
    assert (tmp_path / "out/logs/file").read_bytes() == b"data"


@pytest.mark.asyncio
async def test_rejects_existing_symlink(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out/link").symlink_to(tmp_path)
    with pytest.raises(DevicePathError):
        await collect_archive(tmp_path, "link/victim")
    assert not (tmp_path / "victim").exists()
