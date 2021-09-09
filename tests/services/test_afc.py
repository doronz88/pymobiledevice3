import pytest

from pymobiledevice3.services.afc import AfcService

TEST_FILENAME = 'test'
TEST_FOLDER_NAME = 'test_folder'


@pytest.fixture(scope='function')
def afc(lockdown):
    return AfcService(lockdown)


def test_exists(afc: AfcService):
    assert afc.exists('DCIM')
    assert not afc.exists('a_directory_that_doesnt_exist')


def test_file_read_write(afc):
    body = b'data'

    afc.set_file_contents(TEST_FILENAME, body)
    assert afc.get_file_contents(TEST_FILENAME) == body


def test_ls(afc):
    filenames = afc.listdir('/')
    assert 'DCIM' in filenames
    assert 'Downloads' in filenames
    assert 'Books' in filenames


def test_rm(afc):
    afc.set_file_contents(TEST_FILENAME, b'')
    filenames = afc.listdir('/')
    assert TEST_FILENAME in filenames

    afc.rm(TEST_FILENAME)

    filenames = afc.listdir('/')
    assert TEST_FILENAME not in filenames


def test_mkdir_and_rm_dir(afc: AfcService):
    assert TEST_FOLDER_NAME not in afc.listdir('/')
    afc.mkdir(TEST_FOLDER_NAME)
    assert TEST_FOLDER_NAME in afc.listdir('/')
    afc.rm(TEST_FOLDER_NAME)
    assert TEST_FOLDER_NAME not in afc.listdir('/')
