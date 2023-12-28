import pytest
from pymobiledevice3.services.remote_server import NSUUID
from bpylist2 import archiver

from pprint import pprint


def test_bpylist2_self_register_class():
    for value in ("1", {"hello": [1, 2, 3, set([1, 2, 3])]}, NSUUID.uuid4()):
        plist_bytes = archiver.archive(value)
        new_value = archiver.unarchive(plist_bytes)
        assert value == new_value
