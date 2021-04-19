from pymobiledevice3.services.afc import AfcService

TEST_FILENAME = 'test'


def test_file_read_write(lockdown):
    afc = AfcService(lockdown)
    body = b'data'

    afc.set_file_contents(TEST_FILENAME, body)
    assert afc.get_file_contents(TEST_FILENAME) == body


def test_ls(lockdown):
    afc = AfcService(lockdown)
    filenames = afc.listdir('/')
    assert 'DCIM' in filenames


def test_rm(lockdown):
    afc = AfcService(lockdown)
    afc.set_file_contents(TEST_FILENAME, b'')
    filenames = afc.listdir('/')
    assert TEST_FILENAME in filenames

    afc.rm(TEST_FILENAME)

    filenames = afc.listdir('/')
    assert TEST_FILENAME not in filenames
