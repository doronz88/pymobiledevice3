import pathlib
from datetime import datetime

import pytest
import pytest_asyncio

from pymobiledevice3.exceptions import AfcException, AfcFileNotFoundError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import MAXIMUM_READ_SIZE, AfcError, AfcService

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
    assert not await afc.exists(path)
    await afc.makedirs(path)
    assert await afc.exists(path)
    await afc.rm(pathlib.PosixPath(path.lstrip("/")).parts[0])
    assert not await afc.exists(path)


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


async def test_push_pull_bigger_than_max_chunk(afc: AfcService) -> None:
    contents = b"x" * MAXIMUM_READ_SIZE * 2
    await afc.set_file_contents("test", contents)
    assert contents == await afc.get_file_contents("test")
    await afc.rm("test")
