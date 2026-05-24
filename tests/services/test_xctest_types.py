import dataclasses
import plistlib

from bpylist2 import archiver

from pymobiledevice3.dtx.ns_types import NSMutableArray


def test_nsmutablearray_behaves_like_list() -> None:
    array = NSMutableArray(["modelCode", "cpuType"])

    assert isinstance(array, list)
    assert list(array) == ["modelCode", "cpuType"]
    assert array[0] == "modelCode"

    attributes_cls = dataclasses.make_dataclass("Attributes", ["model", "cpu"])
    assert attributes_cls(*array) == attributes_cls("modelCode", "cpuType")


def test_nsmutablearray_archive_round_trip_preserves_class_and_items() -> None:
    payload = archiver.archive(NSMutableArray(["test/Class/testMethod"]))
    plist = plistlib.loads(payload)

    class_entries = [entry for entry in plist["$objects"] if isinstance(entry, dict) and entry.get("$classname")]
    assert {
        "$classname": "NSMutableArray",
        "$classes": ["NSMutableArray", "NSArray", "NSObject"],
    } in class_entries

    decoded = archiver.unarchive(payload)
    assert isinstance(decoded, NSMutableArray)
    assert isinstance(decoded, list)
    assert decoded == ["test/Class/testMethod"]
