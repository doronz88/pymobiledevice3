import pathlib
from datetime import datetime

import pytest

from pymobiledevice3.exceptions import AfcException, AfcFileNotFoundError
from pymobiledevice3.services.afc import AfcService, afc_error_t, MAXIMUM_READ_SIZE

TEST_FILENAME = 'test'
TEST_FOLDER_NAME = 'test_folder'


@pytest.fixture(scope='function')
def afc(lockdown):
    with AfcService(lockdown) as afc:
        yield afc


def test_exists(afc: AfcService):
    assert afc.exists('DCIM')
    assert not afc.exists('a_directory_that_doesnt_exist')


def test_exists_folder_in_a_file(afc: AfcService):
    afc.set_file_contents(TEST_FILENAME, b'data')
    try:
        assert not afc.exists(f'{TEST_FILENAME}/sub_folder')
    finally:
        afc.rm(TEST_FILENAME)


def test_rm(afc):
    afc.set_file_contents(TEST_FILENAME, b'')
    filenames = afc.listdir('/')
    assert TEST_FILENAME in filenames

    afc.rm(TEST_FILENAME)

    filenames = afc.listdir('/')
    assert TEST_FILENAME not in filenames


def test_rm_force_missing_file(afc):
    with pytest.raises(AfcFileNotFoundError):
        afc.rm(TEST_FILENAME)
    afc.rm(TEST_FILENAME, force=True)


@pytest.mark.parametrize('path', [
    'file_that_doesnt_exist.txt',
    'missingfolder/file_that_doesnt_exist.txt',
    '/missingfolder/file_that_doesnt_exist.txt',
    '/missingfolder/file_that_doesnt_exist.txt/',
    '/missingfolder/./././file_that_doesnt_exist.txt/',
])
def test_rm_file_doesnt_exist(afc: AfcService, path):
    with pytest.raises(AfcFileNotFoundError) as e:
        afc.rm(path)
    assert e.value.status == afc_error_t.OBJECT_NOT_FOUND


def test_get_device_info(afc: AfcService):
    device_info = afc.get_device_info()
    assert device_info['Model'].startswith('iPhone')
    assert device_info['FSTotalBytes'] > device_info['FSFreeBytes']


def test_listdir(afc):
    filenames = afc.listdir('/')
    assert 'DCIM' in filenames
    assert 'Downloads' in filenames
    assert 'Books' in filenames


@pytest.mark.parametrize('path', [
    'missing_folder',
    'missingfolder/missing_folder',
    'missingfolder/missing_folder/',
    '/missingfolder/missing_folder',
    '/missingfolder/missing_folder/',
])
def test_listdir_folder_doesnt_exist(afc: AfcService, path):
    with pytest.raises(AfcFileNotFoundError) as e:
        afc.listdir(path)
    assert e.value.status == afc_error_t.OBJECT_NOT_FOUND


def test_listdir_file(afc: AfcService):
    afc.set_file_contents(TEST_FILENAME, b'data')
    try:
        with pytest.raises(AfcException) as e:
            afc.listdir(TEST_FILENAME)
    finally:
        afc.rm(TEST_FILENAME)
    assert e.value.status == afc_error_t.READ_ERROR


@pytest.mark.parametrize('path', [
    'test_dir_a/test_dir_b/test_dir_c/test_dir_d',
    'test_dir_a/test_dir_b/test_dir_c/test_dir_d/',
    '/test_dir_a/test_dir_b/test_dir_c/test_dir_d',
    '/test_dir_a/test_dir_b/test_dir_c/test_dir_d/',
    '/test_dir_a/./../test_dir_a/test_dir_b/../test_dir_b/test_dir_c/',
])
def test_makedirs_and_rm_dir(afc: AfcService, path):
    assert not afc.exists(path)
    afc.makedirs(path)
    assert afc.exists(path)
    afc.rm(pathlib.PosixPath(path.lstrip('/')).parts[0])
    assert not afc.exists(path)


def test_makedirs_file(afc: AfcService):
    afc.set_file_contents(TEST_FILENAME, b'data')
    impossible_path = f'{TEST_FILENAME}/sub_folder'
    try:
        with pytest.raises(AfcException) as e:
            afc.makedirs(impossible_path)
        assert not afc.exists(impossible_path)
    finally:
        afc.rm(TEST_FILENAME)
    assert e.value.status == afc_error_t.OBJECT_EXISTS


def test_isdir_file(afc: AfcService):
    afc.set_file_contents(TEST_FILENAME, b'data')
    assert not afc.isdir(TEST_FILENAME)
    afc.rm(TEST_FILENAME)


@pytest.mark.parametrize('path', [
    TEST_FOLDER_NAME,
    f'{TEST_FOLDER_NAME}/',
    f'/{TEST_FOLDER_NAME}',
    f'/{TEST_FOLDER_NAME}/',
    f'/{TEST_FOLDER_NAME}/./../{TEST_FOLDER_NAME}/',
])
def test_isdir_folder(afc: AfcService, path):
    afc.makedirs(TEST_FILENAME)
    assert afc.isdir(TEST_FILENAME)
    afc.rm(TEST_FILENAME)


def test_isdir_missing_path(afc: AfcService):
    with pytest.raises(AfcFileNotFoundError):
        afc.isdir('folder_that_doesnt_exist')


def test_isdir_missing_path_inside_a_file(afc: AfcService):
    afc.set_file_contents(TEST_FILENAME, b'data')
    impossible_path = f'{TEST_FILENAME}/sub_folder'
    try:
        with pytest.raises(AfcFileNotFoundError):
            afc.isdir(impossible_path)
    finally:
        afc.rm(TEST_FILENAME)


def test_stat_file(afc: AfcService):
    data = b'data'
    timestamp = datetime.fromtimestamp(afc.lockdown.get_value(key='TimeIntervalSince1970'))
    timestamp = timestamp.replace(microsecond=0)  # stat resolution might not include microseconds
    afc.set_file_contents(TEST_FILENAME, data)
    stat = afc.stat(TEST_FILENAME)
    afc.rm(TEST_FILENAME)
    assert stat['st_size'] == len(data)
    assert stat['st_ifmt'] == 'S_IFREG'
    assert stat['st_mtime'] >= timestamp


def test_stat_folder(afc: AfcService):
    timestamp = datetime.fromtimestamp(afc.lockdown.get_value(key='TimeIntervalSince1970'))
    timestamp = timestamp.replace(microsecond=0)  # stat resolution might not include microseconds
    afc.makedirs(TEST_FOLDER_NAME)
    stat = afc.stat(TEST_FOLDER_NAME)
    afc.rm(TEST_FOLDER_NAME)
    assert stat['st_size'] in (64, 68)
    assert stat['st_ifmt'] == 'S_IFDIR'
    assert stat['st_mtime'] >= timestamp


@pytest.mark.parametrize('path', [
    'missing_file',
    '/missing_file',
    'missing_folder/',
    '/missing_folder/',
    'missingfolder/missing_file',
    'missingfolder/missing_folder/',
    '/missingfolder/missing_file',
    '/missingfolder/missing_folder/',
])
def test_stat_doesnt_exist(afc: AfcService, path):
    with pytest.raises(AfcFileNotFoundError):
        afc.stat(path)


def test_stat_missing_path_inside_a_file(afc: AfcService):
    afc.set_file_contents(TEST_FILENAME, b'data')
    impossible_path = f'{TEST_FILENAME}/sub_folder'
    try:
        with pytest.raises(AfcFileNotFoundError):
            afc.stat(impossible_path)
    finally:
        afc.rm(TEST_FILENAME)


def test_fopen_missing_file(afc: AfcService):
    with pytest.raises(AfcFileNotFoundError):
        afc.fopen('file_that_doesnt_exist')


def test_fclose_not_opened(afc: AfcService):
    with pytest.raises(AfcException) as e:
        afc.fclose(77)
    assert e.value.status == afc_error_t.INVALID_ARG


def test_rename(afc: AfcService):
    afc.set_file_contents('source.txt', b'data')
    afc.rename('source.txt', 'dest.txt')
    try:
        assert afc.get_file_contents('dest.txt') == b'data'
    finally:
        afc.rm('dest.txt')
    with pytest.raises(AfcFileNotFoundError):
        afc.get_file_contents('source.txt')


def test_rename_between_folders(afc: AfcService):
    afc.makedirs('dir_a/dir_b')
    source = 'dir_a/dir_b/source.txt'
    dest = 'dir_a/source.txt'
    afc.set_file_contents(source, b'data')
    afc.rename(source, dest)
    try:
        assert afc.get_file_contents(dest) == b'data'
        with pytest.raises(AfcFileNotFoundError):
            afc.get_file_contents(source)
    finally:
        afc.rm('dir_a')


def test_rename_missing_source(afc: AfcService):
    with pytest.raises(AfcFileNotFoundError):
        afc.rename('source.txt', 'dest.txt')


def test_rename_source_path_inside_a_file(afc: AfcService):
    afc.set_file_contents(TEST_FILENAME, b'data')
    impossible_path = f'{TEST_FILENAME}/source.txt'
    try:
        with pytest.raises(AfcFileNotFoundError):
            afc.rename(impossible_path, 'dest.txt')
    finally:
        afc.rm(TEST_FILENAME)


def test_rename_dest_path_inside_a_file(afc: AfcService):
    afc.set_file_contents(TEST_FILENAME, b'data')
    source = 'source.txt'
    afc.set_file_contents(source, b'data')
    impossible_path = f'{TEST_FILENAME}/dest.txt'
    try:
        with pytest.raises(AfcException):
            afc.rename(source, impossible_path)
    finally:
        afc.rm(TEST_FILENAME)
        afc.rm(source)


def test_rename_to_self(afc: AfcService):
    data = b'data'
    afc.set_file_contents(TEST_FILENAME, data)
    afc.rename(TEST_FILENAME, TEST_FILENAME)
    assert afc.get_file_contents(TEST_FILENAME) == data
    afc.rm(TEST_FILENAME)


def test_fread_more_than_file_size(afc: AfcService):
    data = b'data'
    afc.set_file_contents(TEST_FILENAME, data)
    h = afc.fopen(TEST_FILENAME)
    read_data = afc.fread(h, len(data) + 2)
    afc.fclose(h)
    afc.rm(TEST_FILENAME)
    assert read_data == data


def test_fread_not_opened(afc: AfcService):
    with pytest.raises(AfcException) as e:
        afc.fread(77, 4)
    assert e.value.status == afc_error_t.INVALID_ARG


def test_fwrite_not_opened(afc: AfcService):
    with pytest.raises(AfcException) as e:
        afc.fwrite(77, b'asdasd')
    assert e.value.status == afc_error_t.INVALID_ARG


def test_file_read_write(afc: AfcService):
    body = b'data'

    afc.set_file_contents(TEST_FILENAME, body)
    try:
        assert afc.get_file_contents(TEST_FILENAME) == body
    finally:
        afc.rm(TEST_FILENAME)


def test_get_file_contents_missing_file(afc: AfcService):
    with pytest.raises(AfcFileNotFoundError):
        afc.get_file_contents('missing_file')


def test_dirlist(afc: AfcService):
    afc.makedirs('test_a/test_b/test_c/test_d')
    try:
        assert list(afc.dirlist('/', 0)) == ['/']
        dirlist = list(afc.dirlist('/', 2))
        assert '/' in dirlist
        assert '/test_a' in dirlist
        assert '/test_a/test_b' in dirlist
        assert '/test_a/test_b/test_c' not in dirlist
        assert list(afc.dirlist('test_a', 0)) == ['test_a']
        dirlist = list(afc.dirlist('test_a', 2))
        assert 'test_a' in dirlist
        assert 'test_a/test_b' in dirlist
        assert 'test_a/test_b/test_c' in dirlist
        assert 'test_a/test_b/test_c/test_d' not in dirlist
    finally:
        afc.rm('test_a')


def test_push_pull_bigger_than_max_chunk(afc: AfcService):
    contents = b'x' * MAXIMUM_READ_SIZE * 2
    afc.set_file_contents('test', contents)
    assert contents == afc.get_file_contents('test')
    afc.rm('test')
