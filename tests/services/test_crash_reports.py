import glob
import shutil
import time
from contextlib import suppress

import pytest
import pytest_asyncio

from pymobiledevice3.exceptions import AfcFileNotFoundError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.crash_reports import CrashReportsManager

BASENAME = "__pymobiledevice3_tests"
PATH_COMPONENT = f"/{BASENAME}"


@pytest_asyncio.fixture(scope="function")
async def crash_manager(lockdown: LockdownClient):
    async with CrashReportsManager(lockdown) as crash_manager:
        yield crash_manager


@pytest_asyncio.fixture(scope="function")
async def temp_directory(lockdown: LockdownClient):
    yield
    async with CrashReportsManager(lockdown) as crash_manager:
        with suppress(AfcFileNotFoundError):
            await crash_manager.afc.rm(BASENAME)


async def test_ls_default(crash_manager: CrashReportsManager, temp_directory) -> None:
    await crash_manager.afc.makedirs(PATH_COMPONENT)
    assert PATH_COMPONENT in await crash_manager.ls()


async def test_ls_path(crash_manager: CrashReportsManager, temp_directory) -> None:
    await crash_manager.afc.makedirs(PATH_COMPONENT * 2)
    assert (PATH_COMPONENT * 2) in await crash_manager.ls(path=PATH_COMPONENT)


@pytest.mark.parametrize("depth", [2, 3, 4])
async def test_ls_depth(crash_manager: CrashReportsManager, temp_directory, depth: int) -> None:
    path = PATH_COMPONENT * depth
    path_list = [PATH_COMPONENT * i for i in range(1, depth + 1)]
    await crash_manager.afc.makedirs(path)
    crash_list = await crash_manager.ls(depth=depth)
    for item in path_list:
        assert item in crash_list


async def test_ls_depth_minus_one(crash_manager: CrashReportsManager, temp_directory) -> None:
    path_list = [PATH_COMPONENT, PATH_COMPONENT * 2, PATH_COMPONENT * 3]
    await crash_manager.afc.makedirs(path_list[-1])
    crash_list = await crash_manager.ls(depth=-1)
    for path in path_list:
        assert path in crash_list


async def test_clear(crash_manager, temp_directory) -> None:
    await crash_manager.afc.makedirs(PATH_COMPONENT)
    # true indication device time we can assure that every other file should create after it
    test_dir_birth_time = (await crash_manager.afc.stat(PATH_COMPONENT))["st_birthtime"]
    await crash_manager.clear()
    crash_dirlist = await crash_manager.ls(depth=-1)
    assert PATH_COMPONENT not in crash_dirlist
    for path in crash_dirlist:
        if path != crash_manager.APPSTORED_PATH:
            assert (await crash_manager.afc.stat(path))["st_birthtime"] > test_dir_birth_time


async def test_pull(crash_manager, temp_directory) -> None:
    await crash_manager.afc.makedirs(PATH_COMPONENT)
    dir_list = await crash_manager.ls(depth=-1)
    await crash_manager.pull(BASENAME)
    pulled_list = [file[len(BASENAME) :] for file in glob.glob(f"{BASENAME}/**", recursive=True)][
        1:
    ]  # ignore root path
    assert sorted(dir_list) == sorted(pulled_list)
    shutil.rmtree(BASENAME)


@pytest.mark.parametrize(
    ("end_time", "return_value"),
    ((-1, True), (0, True), (time.monotonic() + 1000, False), (None, False)),
)
def test_check_timeout(crash_manager: CrashReportsManager, end_time: int, return_value: bool) -> None:
    assert crash_manager._check_timeout(end_time) is return_value
