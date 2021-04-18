# -*- coding:utf-8 -*-
"""
AFC test case
"""

from pymobiledevice3.afc import AFCClient, AFC_FOPEN_RW, AFC_FOPEN_RDONLY


def test_file_read_write(lockdown):
    afc = AFCClient(lockdown)
    body = b'data'

    handle = afc.file_open('test', AFC_FOPEN_RW)
    afc.file_write(handle, body)
    afc.file_close(handle)

    handle = afc.file_open('test', AFC_FOPEN_RDONLY)
    read_data = afc.file_read(handle, len(body))
    afc.file_close(handle)

    assert body == read_data
