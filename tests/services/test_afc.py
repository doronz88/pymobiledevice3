import asyncio
import hashlib
import os
import pathlib
import posixpath
import re
import struct
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any, ClassVar, cast

import pytest
import pytest_asyncio

from pymobiledevice3.exceptions import AfcException, AfcFileNotFoundError, ConnectionTerminatedError, DevicePathError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.afc import MAXIMUM_READ_SIZE, AfcError, AfcOpcode, AfcService

TEST_FILENAME = "test"
TEST_FOLDER_NAME = "test_folder"

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(scope="function")
async def afc(lockdown: LockdownClient):
    async with AfcService(lockdown) as afc:
        yield afc


async def test_exists(afc: AfcService) -> None:
    assert await afc.exists("DCIM")
    assert not await afc.exists("a_directory_that_doesnt_exist")


async def test_exists_folder_in_a_file(afc: AfcService) -> None:
    await afc.set_file_contents(TEST_FILENAME, b"data")
    try:
        assert not await afc.exists(f"{TEST_FILENAME}/sub_folder")
    finally:
        await afc.rm(TEST_FILENAME)


async def test_rm(afc: AfcService) -> None:
    await afc.set_file_contents(TEST_FILENAME, b"")
    filenames = await afc.listdir("/")
    assert TEST_FILENAME in filenames

    await afc.rm(TEST_FILENAME)

    filenames = await afc.listdir("/")
    assert TEST_FILENAME not in filenames


async def test_rm_force_missing_file(afc: AfcService) -> None:
    with pytest.raises(AfcFileNotFoundError):
        await afc.rm(TEST_FILENAME)
    await afc.rm(TEST_FILENAME, force=True)


@pytest.mark.parametrize(
    "path",
    [
        "file_that_doesnt_exist.txt",
        "missingfolder/file_that_doesnt_exist.txt",
        "/missingfolder/file_that_doesnt_exist.txt",
        "/missingfolder/file_that_doesnt_exist.txt/",
        "/missingfolder/./././file_that_doesnt_exist.txt/",
    ],
)
async def test_rm_file_doesnt_exist(afc: AfcService, path: str) -> None:
    with pytest.raises(AfcFileNotFoundError) as e:
        await afc.rm(path)
    assert e.value.status == AfcError.OBJECT_NOT_FOUND


async def test_rm_tree_in_one_request(afc: AfcService, monkeypatch: pytest.MonkeyPatch) -> None:
    await afc.rm(TEST_FOLDER_NAME, force=True)
    for d in range(3):
        await afc.makedirs(f"{TEST_FOLDER_NAME}/d{d}/sub")
        await afc.set_file_contents(f"{TEST_FOLDER_NAME}/d{d}/sub/file", b"data")
    opcodes = []
    do_operation = afc._do_operation

    async def recording_do_operation(opcode, *args, **kwargs):
        opcodes.append(opcode)
        return await do_operation(opcode, *args, **kwargs)

    monkeypatch.setattr(afc, "_do_operation", recording_do_operation)
    try:
        assert await afc.rm(TEST_FOLDER_NAME) == []
        assert opcodes == [AfcOpcode.REMOVE_PATH_AND_CONTENTS]
        assert not await afc.exists(TEST_FOLDER_NAME)
    finally:
        await afc.rm(TEST_FOLDER_NAME, force=True)


_RM_MATCH_LAYOUT = (
    "drop_top.txt",
    "keep_top.txt",
    "drop_dir/drop_nested.txt",
    "drop_dir/keep_nested.txt",
    "drop_dir/drop_sub/drop_deep.txt",
    "drop_dir/keep_sub/drop_skipped.txt",
    "keep_dir/drop_skipped.txt",
)


@pytest_asyncio.fixture(scope="function")
async def rm_match_tree(afc: AfcService) -> AsyncGenerator[str, None]:
    root = f"/pmd3_rm_match_{uuid.uuid4().hex}"
    for name in _RM_MATCH_LAYOUT:
        path = posixpath.join(root, name)
        await afc.makedirs(posixpath.dirname(path))
        await afc.set_file_contents(path, b"data")
    try:
        yield root
    finally:
        await afc.rm(root, force=True)


async def _files_under(afc: AfcService, root: str) -> set[str]:
    return {
        posixpath.relpath(posixpath.join(dirpath, name), root)
        async for dirpath, _dirs, files in afc.walk(root)
        for name in files
    }


async def test_rm_match_removes_exactly_what_pull_copies(
    afc: AfcService, rm_match_tree: str, tmp_path: pathlib.Path
) -> None:
    match = re.compile(r"drop_")
    await afc.pull(rm_match_tree, str(tmp_path), match=match, progress_bar=False)
    pulled_root = tmp_path / posixpath.basename(rm_match_tree)
    pulled = {path.relative_to(pulled_root).as_posix() for path in pulled_root.rglob("*") if path.is_file()}

    assert await afc.rm(rm_match_tree, match=match) == []

    remaining = await _files_under(afc, rm_match_tree)
    assert pulled == {"drop_top.txt", "drop_dir/drop_nested.txt", "drop_dir/drop_sub/drop_deep.txt"}
    assert remaining == set(_RM_MATCH_LAYOUT) - pulled
    # directories are never removed when a match is given
    for directory in ("drop_dir", "drop_dir/drop_sub", "drop_dir/keep_sub", "keep_dir"):
        assert await afc.isdir(posixpath.join(rm_match_tree, directory))


async def test_rm_match_single_file(afc: AfcService, rm_match_tree: str) -> None:
    keep = posixpath.join(rm_match_tree, "keep_top.txt")
    drop = posixpath.join(rm_match_tree, "drop_top.txt")
    assert await afc.rm(keep, match=re.compile(r"drop_")) == []
    assert await afc.exists(keep)
    assert await afc.rm(drop, match=re.compile(r"drop_")) == []
    assert not await afc.exists(drop)


async def test_rm_match_missing_path(afc: AfcService) -> None:
    with pytest.raises(AfcFileNotFoundError):
        await afc.rm(f"/pmd3_rm_match_missing_{uuid.uuid4().hex}", match=re.compile("x"))


async def test_get_device_info(afc: AfcService) -> None:
    device_info = await afc.get_device_info()
    assert device_info["Model"].startswith("iPhone")
    assert int(device_info["FSTotalBytes"]) > int(device_info["FSFreeBytes"])


async def test_listdir(afc: AfcService) -> None:
    filenames = await afc.listdir("/")
    assert "DCIM" in filenames
    assert "Downloads" in filenames
    assert "Books" in filenames


@pytest.mark.parametrize(
    "path",
    [
        "missing_folder",
        "missingfolder/missing_folder",
        "missingfolder/missing_folder/",
        "/missingfolder/missing_folder",
        "/missingfolder/missing_folder/",
    ],
)
async def test_listdir_folder_doesnt_exist(afc: AfcService, path: str) -> None:
    with pytest.raises(AfcFileNotFoundError) as e:
        await afc.listdir(path)
    assert e.value.status == AfcError.OBJECT_NOT_FOUND


async def test_listdir_file(afc: AfcService):
    await afc.set_file_contents(TEST_FILENAME, b"data")
    try:
        with pytest.raises(AfcException) as e:
            await afc.listdir(TEST_FILENAME)
    finally:
        await afc.rm(TEST_FILENAME)
    assert e.value.status == AfcError.READ_ERROR


@pytest.mark.parametrize(
    "path",
    [
        "test_dir_a/test_dir_b/test_dir_c/test_dir_d",
        "test_dir_a/test_dir_b/test_dir_c/test_dir_d/",
        "/test_dir_a/test_dir_b/test_dir_c/test_dir_d",
        "/test_dir_a/test_dir_b/test_dir_c/test_dir_d/",
        "/test_dir_a/./../test_dir_a/test_dir_b/../test_dir_b/test_dir_c/",
    ],
)
async def test_makedirs_and_rm_dir(afc: AfcService, path: str) -> None:
    root_dir = pathlib.PosixPath(path.lstrip("/")).parts[0]
    await afc.rm(root_dir, force=True)
    try:
        assert not await afc.exists(path)
        await afc.makedirs(path)
        assert await afc.exists(path)
        await afc.rm(root_dir)
        assert not await afc.exists(path)
    finally:
        await afc.rm(root_dir, force=True)


async def test_makedirs_file(afc: AfcService):
    await afc.set_file_contents(TEST_FILENAME, b"data")
    impossible_path = f"{TEST_FILENAME}/sub_folder"
    try:
        with pytest.raises(AfcException) as e:
            await afc.makedirs(impossible_path)
        assert not await afc.exists(impossible_path)
    finally:
        await afc.rm(TEST_FILENAME)
    assert e.value.status == AfcError.OBJECT_EXISTS


async def test_isdir_file(afc: AfcService):
    await afc.set_file_contents(TEST_FILENAME, b"data")
    assert not await afc.isdir(TEST_FILENAME)
    await afc.rm(TEST_FILENAME)


@pytest.mark.parametrize(
    "path",
    [
        TEST_FOLDER_NAME,
        f"{TEST_FOLDER_NAME}/",
        f"/{TEST_FOLDER_NAME}",
        f"/{TEST_FOLDER_NAME}/",
        f"/{TEST_FOLDER_NAME}/./../{TEST_FOLDER_NAME}/",
    ],
)
async def test_isdir_folder(afc: AfcService, path: str) -> None:
    await afc.makedirs(TEST_FILENAME)
    assert await afc.isdir(TEST_FILENAME)
    await afc.rm(TEST_FILENAME)


async def test_isdir_missing_path(afc: AfcService) -> None:
    with pytest.raises(AfcFileNotFoundError):
        await afc.isdir("folder_that_doesnt_exist")


async def test_isdir_missing_path_inside_a_file(afc: AfcService) -> None:
    await afc.set_file_contents(TEST_FILENAME, b"data")
    impossible_path = f"{TEST_FILENAME}/sub_folder"
    try:
        with pytest.raises(AfcFileNotFoundError):
            await afc.isdir(impossible_path)
    finally:
        await afc.rm(TEST_FILENAME)


async def test_stat_file(afc: AfcService) -> None:
    data = b"data"
    timestamp = datetime.fromtimestamp(await afc.lockdown.get_value(key="TimeIntervalSince1970"))
    timestamp = timestamp.replace(microsecond=0)  # stat resolution might not include microseconds
    await afc.set_file_contents(TEST_FILENAME, data)
    stat = await afc.stat(TEST_FILENAME)
    await afc.rm(TEST_FILENAME)
    assert stat["st_size"] == len(data)
    assert stat["st_ifmt"] == "S_IFREG"
    assert stat["st_mtime"] >= timestamp


async def test_fseek_reads_from_offset(afc: AfcService) -> None:
    import os

    data = bytes(range(256)) * 8  # 2 KiB with distinct byte values
    await afc.set_file_contents(TEST_FILENAME, data)
    try:
        handle = await afc.fopen(TEST_FILENAME)
        try:
            await afc.fseek(handle, 300, os.SEEK_SET)
            assert await afc.fread(handle, 100) == data[300:400]
            await afc.fseek(handle, -10, os.SEEK_END)
            assert await afc.fread(handle, 10) == data[-10:]
        finally:
            await afc.fclose(handle)
    finally:
        await afc.rm(TEST_FILENAME)


async def test_stat_folder(afc: AfcService) -> None:
    timestamp = datetime.fromtimestamp(await afc.lockdown.get_value(key="TimeIntervalSince1970"))
    timestamp = timestamp.replace(microsecond=0)  # stat resolution might not include microseconds
    await afc.makedirs(TEST_FOLDER_NAME)
    stat = await afc.stat(TEST_FOLDER_NAME)
    await afc.rm(TEST_FOLDER_NAME)
    assert stat["st_size"] in (64, 68)
    assert stat["st_ifmt"] == "S_IFDIR"
    assert stat["st_mtime"] >= timestamp


@pytest.mark.parametrize(
    "path",
    [
        "missing_file",
        "/missing_file",
        "missing_folder/",
        "/missing_folder/",
        "missingfolder/missing_file",
        "missingfolder/missing_folder/",
        "/missingfolder/missing_file",
        "/missingfolder/missing_folder/",
    ],
)
async def test_stat_doesnt_exist(afc: AfcService, path: str) -> None:
    with pytest.raises(AfcFileNotFoundError):
        await afc.stat(path)


async def test_stat_missing_path_inside_a_file(afc: AfcService) -> None:
    await afc.set_file_contents(TEST_FILENAME, b"data")
    impossible_path = f"{TEST_FILENAME}/sub_folder"
    try:
        with pytest.raises(AfcFileNotFoundError):
            await afc.stat(impossible_path)
    finally:
        await afc.rm(TEST_FILENAME)


async def test_fopen_missing_file(afc: AfcService) -> None:
    with pytest.raises(AfcFileNotFoundError):
        await afc.fopen("file_that_doesnt_exist")


async def test_fclose_not_opened(afc: AfcService) -> None:
    with pytest.raises(AfcException) as e:
        await afc.fclose(77)
    assert e.value.status == AfcError.INVALID_ARG


async def test_rename(afc: AfcService):
    await afc.set_file_contents("source.txt", b"data")
    await afc.rename("source.txt", "dest.txt")
    try:
        assert await afc.get_file_contents("dest.txt") == b"data"
    finally:
        await afc.rm("dest.txt")
    with pytest.raises(AfcFileNotFoundError):
        await afc.get_file_contents("source.txt")


async def test_rename_between_folders(afc: AfcService) -> None:
    await afc.makedirs("dir_a/dir_b")
    source = "dir_a/dir_b/source.txt"
    dest = "dir_a/source.txt"
    await afc.set_file_contents(source, b"data")
    await afc.rename(source, dest)
    try:
        assert await afc.get_file_contents(dest) == b"data"
        with pytest.raises(AfcFileNotFoundError):
            await afc.get_file_contents(source)
    finally:
        await afc.rm("dir_a")


async def test_rename_missing_source(afc: AfcService) -> None:
    with pytest.raises(AfcFileNotFoundError):
        await afc.rename("source.txt", "dest.txt")


async def test_rename_source_path_inside_a_file(afc: AfcService) -> None:
    await afc.set_file_contents(TEST_FILENAME, b"data")
    impossible_path = f"{TEST_FILENAME}/source.txt"
    try:
        with pytest.raises(AfcFileNotFoundError):
            await afc.rename(impossible_path, "dest.txt")
    finally:
        await afc.rm(TEST_FILENAME)


async def test_rename_dest_path_inside_a_file(afc: AfcService) -> None:
    await afc.set_file_contents(TEST_FILENAME, b"data")
    source = "source.txt"
    await afc.set_file_contents(source, b"data")
    impossible_path = f"{TEST_FILENAME}/dest.txt"
    try:
        with pytest.raises(AfcException):
            await afc.rename(source, impossible_path)
    finally:
        await afc.rm(TEST_FILENAME)
        await afc.rm(source)


async def test_rename_to_self(afc: AfcService) -> None:
    data = b"data"
    await afc.set_file_contents(TEST_FILENAME, data)
    await afc.rename(TEST_FILENAME, TEST_FILENAME)
    assert await afc.get_file_contents(TEST_FILENAME) == data
    await afc.rm(TEST_FILENAME)


async def test_fread_more_than_file_size(afc: AfcService) -> None:
    data = b"data"
    await afc.set_file_contents(TEST_FILENAME, data)
    h = await afc.fopen(TEST_FILENAME)
    read_data = await afc.fread(h, len(data) + 2)
    await afc.fclose(h)
    await afc.rm(TEST_FILENAME)
    assert read_data == data


async def test_fread_not_opened(afc: AfcService) -> None:
    with pytest.raises(AfcException) as e:
        await afc.fread(77, 4)
    assert e.value.status == AfcError.INVALID_ARG


async def test_fwrite_not_opened(afc: AfcService) -> None:
    with pytest.raises(AfcException) as e:
        await afc.fwrite(77, b"asdasd")
    assert e.value.status == AfcError.INVALID_ARG


async def test_file_read_write(afc: AfcService) -> None:
    body = b"data"

    await afc.set_file_contents(TEST_FILENAME, body)
    try:
        assert await afc.get_file_contents(TEST_FILENAME) == body
    finally:
        await afc.rm(TEST_FILENAME)


async def test_get_file_contents_missing_file(afc: AfcService) -> None:
    with pytest.raises(AfcFileNotFoundError):
        await afc.get_file_contents("missing_file")


async def test_dirlist(afc: AfcService):
    await afc.makedirs("test_a/test_b/test_c/test_d")
    try:
        assert [x async for x in afc.dirlist("/", 0)] == ["/"]
        dirlist = [x async for x in afc.dirlist("/", 2)]
        assert "/" in dirlist
        assert "/test_a" in dirlist
        assert "/test_a/test_b" in dirlist
        assert "/test_a/test_b/test_c" not in dirlist
        assert [x async for x in afc.dirlist("test_a", 0)] == ["test_a"]
        dirlist = [x async for x in afc.dirlist("test_a", 2)]
        assert "test_a" in dirlist
        assert "test_a/test_b" in dirlist
        assert "test_a/test_b/test_c" in dirlist
        assert "test_a/test_b/test_c/test_d" not in dirlist
    finally:
        await afc.rm("test_a")


class _FakeTreeAfc(AfcService):
    """An `AfcService` over an in-memory tree, where only the ``readable`` directories may be listed."""

    TREE: ClassVar[dict[str, list[str]]] = {
        "/": ["a", "f"],
        "/a": ["b", "g"],
        "/a/b": ["c"],
        "/a/b/c": ["d"],
        "/a/b/c/d": [],
        "a": ["b", "g"],
        "a/b": ["c"],
        "a/b/c": ["d"],
        "a/b/c/d": [],
    }

    def __init__(self, readable: list[str]) -> None:
        super().__init__(cast(LockdownServiceProvider, object()), service_name="com.apple.afc")
        self.readable = readable
        self.listed: list[str] = []

    async def listdir(self, filename: str) -> list[str]:
        if filename not in self.readable:
            # what iOS 27.2 answers for e.g. /PhotoData/UBF
            raise AfcException(f"READ_DIR failed for file: {filename}", AfcError.PERM_DENIED, filename)
        self.listed.append(filename)
        return self.TREE[filename]

    async def stat(self, filename: str) -> dict[str, Any]:
        return {"st_ifmt": "S_IFDIR" if filename in self.TREE else "S_IFREG"}


@pytest.mark.parametrize(
    ("root", "depth", "expected", "listed"),
    [
        ("/", 0, ["/"], ["/"]),
        ("/", 1, ["/", "/a", "/f"], ["/"]),
        ("/", 2, ["/", "/a", "/f", "/a/b", "/a/g"], ["/", "/a"]),
        ("a", 0, ["a"], ["a"]),
        ("a", 1, ["a", "a/b", "a/g"], ["a"]),
        ("a", 2, ["a", "a/b", "a/g", "a/b/c"], ["a", "a/b"]),
        ("a", -1, ["a", "a/b", "a/g", "a/b/c", "a/b/c/d"], ["a", "a/b", "a/b/c", "a/b/c/d"]),
    ],
)
async def test_dirlist_does_not_read_beyond_depth(
    root: str, depth: int, expected: list[str], listed: list[str]
) -> None:
    """``dirlist`` must not list directories beyond ``depth``: they may be unreadable, failing the whole listing."""
    afc = _FakeTreeAfc(readable=listed)
    assert [x async for x in afc.dirlist(root, depth)] == expected
    assert afc.listed == listed


class _MaliciousPullAfc(AfcService):
    """A device whose directory listing surfaces ``..`` entries to climb the local destination."""

    TREE: ClassVar[dict[str, list[str]]] = {
        "exfil": [".."],
        "exfil/..": [".."],
        "exfil/../..": ["escaped"],
    }

    def __init__(self) -> None:
        super().__init__(cast(LockdownServiceProvider, object()), service_name="com.apple.afc")

    async def resolve_path(self, filename: str) -> str:
        return filename

    async def isdir(self, filename: str) -> bool:
        return filename in self.TREE

    async def listdir(self, filename: str) -> list[str]:
        return self.TREE[filename]

    async def stat(self, filename: str) -> dict[str, Any]:
        is_dir = filename in self.TREE
        return {"st_ifmt": "S_IFDIR" if is_dir else "S_IFREG", "st_size": 4, "st_mtime": datetime(2020, 1, 1)}

    async def get_file_contents(self, filename: str) -> bytes:
        return b"pwnd"


async def test_pull_rejects_parent_traversal_entry(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(DevicePathError):
        await _MaliciousPullAfc().pull("exfil", str(out), progress_bar=False)
    assert not (tmp_path / "escaped").exists()


async def test_pull_skips_parent_traversal_entry_when_ignoring_errors(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    await _MaliciousPullAfc().pull("exfil", str(out), ignore_errors=True, progress_bar=False)
    assert not (tmp_path / "escaped").exists()


class _LinkPullAfc(AfcService):
    """A device whose listing is clean, but one entry is a symlink whose target ends in ``..``."""

    TREE: ClassVar[dict[str, list[str]]] = {
        "exfil": ["link"],
        "exfil/../payload/x/..": ["escaped"],
    }

    def __init__(self) -> None:
        super().__init__(cast(LockdownServiceProvider, object()), service_name="com.apple.afc")

    async def isdir(self, filename: str) -> bool:
        return filename in self.TREE

    async def listdir(self, filename: str) -> list[str]:
        return self.TREE[filename]

    async def stat(self, filename: str) -> dict[str, Any]:
        info: dict[str, Any] = {"st_ifmt": "S_IFREG", "st_size": 4, "st_mtime": datetime(2020, 1, 1)}
        if filename == "exfil/link":
            info.update(st_ifmt="S_IFLNK", LinkTarget="../payload/x/..")
        elif filename in self.TREE:
            info["st_ifmt"] = "S_IFDIR"
        return info

    async def get_file_contents(self, filename: str) -> bytes:
        return b"pwnd"


async def test_pull_rejects_link_target_ending_in_parent(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(DevicePathError):
        await _LinkPullAfc().pull("exfil", str(out), progress_bar=False)
    assert not (out / "escaped").exists()


async def test_push_pull_bigger_than_max_chunk(afc: AfcService) -> None:
    contents = b"x" * MAXIMUM_READ_SIZE * 2
    await afc.set_file_contents("test", contents)
    assert contents == await afc.get_file_contents("test")
    await afc.rm("test")


OPS_FOLDER = "__pymobiledevice3_afc_ops_tests"
OPS_FILE = f"{OPS_FOLDER}/file"
OPS_DATA = bytes(range(256))[::-1] * 37 + b"tail"


@pytest_asyncio.fixture(scope="function")
async def ops_afc(afc: AfcService):
    await afc.rm(OPS_FOLDER, force=True)
    await afc.makedirs(OPS_FOLDER)
    await afc.set_file_contents(OPS_FILE, OPS_DATA)
    try:
        yield afc
    finally:
        await afc.rm(OPS_FOLDER, force=True)


async def test_get_file_hash(ops_afc: AfcService) -> None:
    assert await ops_afc.get_file_hash(OPS_FILE) == hashlib.sha1(OPS_DATA).digest()


async def test_get_file_hash_empty_file(ops_afc: AfcService) -> None:
    await ops_afc.set_file_contents(f"{OPS_FOLDER}/empty", b"")
    assert await ops_afc.get_file_hash(f"{OPS_FOLDER}/empty") == hashlib.sha1(b"").digest()


async def test_get_file_hash_errors(ops_afc: AfcService) -> None:
    with pytest.raises(AfcFileNotFoundError):
        await ops_afc.get_file_hash(f"{OPS_FOLDER}/missing")
    with pytest.raises(AfcException) as e:
        await ops_afc.get_file_hash(OPS_FOLDER)
    assert e.value.status == AfcError.OBJECT_IS_DIR


async def test_get_file_hash_range(ops_afc: AfcService) -> None:
    assert await ops_afc.get_file_hash_range(OPS_FILE, 100, 300) == hashlib.sha1(OPS_DATA[100:400]).digest()
    assert await ops_afc.get_file_hash_range(OPS_FILE, len(OPS_DATA) - 1, 1) == hashlib.sha1(OPS_DATA[-1:]).digest()
    with pytest.raises(AfcException) as e:
        await ops_afc.get_file_hash_range(OPS_FILE, 1, len(OPS_DATA))
    assert e.value.status == AfcError.INVALID_ARG


async def test_set_file_time(ops_afc: AfcService) -> None:
    mtime = datetime(2020, 9, 13, 12, 26, 40, 123456)
    await ops_afc.set_file_time(OPS_FILE, mtime)
    assert (await ops_afc.stat(OPS_FILE))["st_mtime"] == mtime
    with pytest.raises(AfcFileNotFoundError):
        await ops_afc.set_file_time(f"{OPS_FOLDER}/missing", mtime)


async def test_truncate(ops_afc: AfcService) -> None:
    await ops_afc.truncate(OPS_FILE, 100)
    assert await ops_afc.get_file_contents(OPS_FILE) == OPS_DATA[:100]
    await ops_afc.truncate(OPS_FILE, 200)
    assert await ops_afc.get_file_contents(OPS_FILE) == OPS_DATA[:100] + b"\0" * 100


async def test_get_size_of_path_contents(ops_afc: AfcService) -> None:
    await ops_afc.makedirs(f"{OPS_FOLDER}/a/b")
    await ops_afc.set_file_contents(f"{OPS_FOLDER}/a/b/nested", b"x" * 5000)
    size = await ops_afc.get_size_of_path_contents(OPS_FOLDER)
    assert size["st_size"] == len(OPS_DATA) + 5000
    assert size["st_blocks"] > 0
    with pytest.raises(AfcFileNotFoundError):
        await ops_afc.get_size_of_path_contents(f"{OPS_FOLDER}/missing")


async def test_get_connection_info(afc: AfcService) -> None:
    info = await afc.get_connection_info()
    assert "afc" in info["Version"]


async def test_ftell_and_ftruncate(ops_afc: AfcService) -> None:
    handle = await ops_afc.fopen(OPS_FILE, "r+")
    try:
        assert await ops_afc.ftell(handle) == 0
        await ops_afc.fseek(handle, 300)
        assert await ops_afc.ftell(handle) == 300
        await ops_afc.ftruncate(handle, 1000)
        assert await ops_afc.ftell(handle) == 300
    finally:
        await ops_afc.fclose(handle)
    assert (await ops_afc.stat(OPS_FILE))["st_size"] == 1000
    assert await ops_afc.get_file_contents(OPS_FILE) == OPS_DATA[:1000]


async def test_pread_pwrite(ops_afc: AfcService) -> None:
    handle = await ops_afc.fopen(OPS_FILE, "r+")
    try:
        await ops_afc.fseek(handle, 10)
        assert await ops_afc.pread(handle, 7, 1234) == OPS_DATA[1234:1241]
        assert await ops_afc.pread(handle, 100, len(OPS_DATA) - 2) == OPS_DATA[-2:]
        assert await ops_afc.pread(handle, 100, len(OPS_DATA) + 100) == b""
        await ops_afc.pwrite(handle, b"ABCDEFG", 3000)
        await ops_afc.pwrite(handle, b"END", len(OPS_DATA) + 10)
        # positional I/O leaves the handle's position alone
        assert await ops_afc.ftell(handle) == 10
    finally:
        await ops_afc.fclose(handle)
    expected = OPS_DATA[:3000] + b"ABCDEFG" + OPS_DATA[3007:] + b"\0" * 10 + b"END"
    assert await ops_afc.get_file_contents(OPS_FILE) == expected


async def test_pread_pwrite_bigger_than_max_chunk(ops_afc: AfcService) -> None:
    contents = os.urandom(MAXIMUM_READ_SIZE + 1000)
    handle = await ops_afc.fopen(OPS_FILE, "w+")
    try:
        await ops_afc.pwrite(handle, contents, 0, chunk_size=MAXIMUM_READ_SIZE)
        assert await ops_afc.pread(handle, len(contents) + 10, 0) == contents
    finally:
        await ops_afc.fclose(handle)


class _RecordingAfc(AfcService):
    """Records the packets an operation sends and answers each with a canned reply."""

    def __init__(self, reply: bytes = b"") -> None:
        super().__init__(cast(LockdownServiceProvider, object()), service_name="com.apple.afc")
        self.sent: list[tuple[AfcOpcode, bytes, int]] = []
        self.reply = reply

    async def _send_and_wait(self, operation: AfcOpcode, data: bytes, this_length: int = 0):
        self.sent.append((operation, data, this_length))
        return AfcError.SUCCESS, self.reply


async def test_request_layouts() -> None:
    afc = _RecordingAfc(reply=struct.pack("<Q", 42))
    assert await afc.ftell(3) == 42
    await afc.ftruncate(3, 1000)
    await afc.pread(3, 8, 100)
    await afc.truncate("f", 5)
    await afc.set_file_time("f", datetime.fromtimestamp(1600000000.123456))
    await afc.get_file_hash_range("f", 1, 2)
    assert afc.sent == [
        (AfcOpcode.FILE_TELL, struct.pack("<Q", 3), 0),
        (AfcOpcode.FILE_SET_SIZE, struct.pack("<QQ", 3, 1000), 0),
        (AfcOpcode.FILE_READ_OFFSET, struct.pack("<QQQ", 3, 8, 100), 0),
        (AfcOpcode.TRUNCATE, struct.pack("<Q", 5) + b"f\0", 0),
        (AfcOpcode.SET_FILE_TIME, struct.pack("<Q", 1600000000123456000) + b"f\0", 0),
        (AfcOpcode.GET_FILE_HASH_RANGE, struct.pack("<QQ", 1, 2) + b"f\0", 0),
    ]


async def test_pwrite_sends_offset_header_and_chunks() -> None:
    afc = _RecordingAfc()
    await afc.pwrite(7, b"abcde", 10, chunk_size=2)
    assert afc.sent == [
        (AfcOpcode.FILE_WRITE_OFFSET, struct.pack("<QQ", 7, 10) + b"ab", 56),
        (AfcOpcode.FILE_WRITE_OFFSET, struct.pack("<QQ", 7, 12) + b"cd", 56),
        (AfcOpcode.FILE_WRITE_OFFSET, struct.pack("<QQ", 7, 14) + b"e", 56),
    ]


async def test_concurrent_operations(lockdown: LockdownClient) -> None:
    """
    Verify that a single AfcService instance handles multiple concurrent operations
    correctly via the packet_num demultiplexer.

    Before the background reader + packet_num demux was implemented this test failed with:
        RuntimeError: readexactly() called while another coroutine is already waiting
    """
    async with AfcService(lockdown) as afc:
        # 10 concurrent get_device_info calls — all must return non-empty dicts
        results = await asyncio.gather(*[afc.get_device_info() for _ in range(10)])
        assert all(isinstance(r, dict) and len(r) > 0 for r in results), (
            f"Expected all concurrent get_device_info calls to return non-empty dicts, got {results}"
        )

        # 5 concurrent listdir("/") — all must return the same non-empty listing
        listings = await asyncio.gather(*[afc.listdir("/") for _ in range(5)])
        assert all(isinstance(r, list) and len(r) > 0 for r in listings), (
            f"Expected all concurrent listdir calls to return non-empty lists, got {listings}"
        )
        assert all(sorted(r) == sorted(listings[0]) for r in listings), (
            f"Expected all concurrent listdir results to be identical, got {listings}"
        )


class _DisconnectingConnection:
    """A fake service connection: ``recvall`` blocks until ``dropped``, then dies."""

    def __init__(self) -> None:
        self.dropped = asyncio.Event()

    async def recvall(self, size: int) -> bytes:
        await self.dropped.wait()
        raise ConnectionTerminatedError()

    async def close(self) -> None:
        pass


async def test_wait_terminated_unblocks_on_connection_drop() -> None:
    """``wait_terminated`` must return once the underlying connection dies (device disconnect)."""
    afc = AfcService(cast(LockdownServiceProvider, object()), service_name="com.apple.afc")
    connection = _DisconnectingConnection()
    afc._service = cast(ServiceConnection, connection)  # pre-injected connection: no real device needed
    waiter = asyncio.create_task(afc.wait_terminated())
    await asyncio.sleep(0.05)
    assert not waiter.done()

    connection.dropped.set()
    await asyncio.wait_for(waiter, timeout=5)
