import glob
import shutil
import time

import pytest

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.crash_reports import CrashReportsManager

BASENAME = '__pymobiledevice3_tests'
PATH_COMPONENT = f'/{BASENAME}'


@pytest.fixture(scope='function')
def crash_manager(lockdown):
    with CrashReportsManager(lockdown) as crash_manager:
        yield crash_manager


@pytest.fixture(scope='module')
def delete_test_dir():
    yield
    with create_using_usbmux() as lockdown_client:
        with CrashReportsManager(lockdown_client) as crash_manager:
            crash_manager.afc.rm(BASENAME)


def test_ls_default(crash_manager, delete_test_dir):
    crash_manager.afc.makedirs(PATH_COMPONENT)
    assert PATH_COMPONENT in crash_manager.ls()


def test_ls_path(crash_manager, delete_test_dir):
    crash_manager.afc.makedirs(PATH_COMPONENT * 2)
    assert (PATH_COMPONENT * 2) in crash_manager.ls(path=PATH_COMPONENT)


@pytest.mark.parametrize('depth', [2, 3, 4])
def test_ls_depth(crash_manager, delete_test_dir, depth):
    path = PATH_COMPONENT * depth
    path_list = [PATH_COMPONENT * i for i in range(1, depth + 1)]
    crash_manager.afc.makedirs(path)
    crash_list = crash_manager.ls(depth=depth)
    for item in path_list:
        assert item in crash_list


def test_ls_depth_minus_one(crash_manager, delete_test_dir):
    path_list = [PATH_COMPONENT, PATH_COMPONENT * 2, PATH_COMPONENT * 3]
    crash_manager.afc.makedirs(path_list[-1])
    crash_list = crash_manager.ls(depth=-1)
    for path in path_list:
        assert path in crash_list


def test_clear(crash_manager, delete_test_dir):
    crash_manager.afc.makedirs(PATH_COMPONENT)
    # true indication device time we can assure that every other file should create after it
    test_dir_birth_time = crash_manager.afc.stat(PATH_COMPONENT)['st_birthtime']
    crash_manager.clear()
    crash_dirlist = crash_manager.ls(depth=-1)
    assert PATH_COMPONENT not in crash_dirlist
    for path in crash_dirlist:
        if crash_manager.APPSTORED_PATH != path:
            assert crash_manager.afc.stat(path)['st_birthtime'] > test_dir_birth_time


def test_pull(crash_manager, delete_test_dir):
    crash_manager.afc.makedirs(PATH_COMPONENT)
    dir_list = crash_manager.ls(depth=-1)
    crash_manager.pull(BASENAME)
    pulled_list = [file[len(BASENAME):] for file in glob.glob(f'{BASENAME}/**', recursive=True)][1:]  # ignore root path
    assert sorted(dir_list) == sorted(pulled_list)
    shutil.rmtree(BASENAME)


@pytest.mark.parametrize(
    ('end_time', 'return_value'),
    ((-1, True), (0, True), (time.monotonic() + 1000, False), (None, False))
)
def test_check_timeout(crash_manager, end_time, return_value):
    assert crash_manager._check_timeout(end_time) is return_value
