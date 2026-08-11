from typing import Any

import pytest

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.restore.tss import TSSRequest

# Modeled on the iPhone17,1 iOS 27.0 beta (24A5408d) BuildManifest: SysTopPatch entries
# come in EPRO=False/True pairs per FabRevision, and Yonkers,SepObject (new in iOS 27)
# carries neither EPRO nor FabRevision. Keys are listed in plist (alphabetical) order,
# so SepObject is seen before any SysTopPatch entry.
MANIFEST: dict[str, Any] = {
    "SEP": {"Digest": b"\xff", "Info": {}},
    "Yonkers,SepObject": {"Digest": b"\x00", "Info": {}},
    "Yonkers,SysTopPatch8": {"Digest": b"\x08", "EPRO": False, "FabRevision": 54529, "Info": {}},
    "Yonkers,SysTopPatch9": {"Digest": b"\x09", "EPRO": True, "FabRevision": 54529, "Info": {}},
    "Yonkers,SysTopPatchA": {"Digest": b"\x0a", "EPRO": False, "FabRevision": 56577, "Info": {}},
    "Yonkers,SysTopPatchB": {"Digest": b"\x0b", "EPRO": True, "FabRevision": 56577, "Info": {}},
}


def _parameters(isprod: bool, fabrevision: int) -> dict[str, Any]:
    return {
        "Manifest": MANIFEST,
        "Yonkers,ProductionMode": isprod,
        "Yonkers,FabRevision": fabrevision,
    }


def _select(isprod: bool, fabrevision: int) -> str:
    request = TSSRequest()
    return request.add_yonkers_tags(_parameters(isprod, fabrevision))


def test_sep_object_is_not_selected() -> None:
    # Yonkers,SepObject has neither EPRO nor FabRevision, so before the SysTopPatch
    # prefix restriction it passed both filters and shadowed the real component.
    assert _select(True, 54529) == "Yonkers,SysTopPatch9"


def test_production_device_selects_the_epro_true_entry() -> None:
    # EPRO=False must be treated as a present-and-failing filter, not skipped:
    # SysTopPatch8 (EPRO=False) precedes SysTopPatch9 (EPRO=True) for the same fab.
    assert _select(True, 54529) == "Yonkers,SysTopPatch9"
    assert _select(True, 56577) == "Yonkers,SysTopPatchB"


def test_development_device_selects_the_epro_false_entry() -> None:
    assert _select(False, 54529) == "Yonkers,SysTopPatch8"
    assert _select(False, 56577) == "Yonkers,SysTopPatchA"


def test_selected_component_is_added_to_the_request() -> None:
    request = TSSRequest()
    comp_name = request.add_yonkers_tags(_parameters(True, 54529))
    assert request._request[comp_name] == {"Digest": b"\x09", "EPRO": True, "FabRevision": 54529}


def test_unknown_fab_revision_raises() -> None:
    with pytest.raises(PyMobileDevice3Exception):
        _select(True, 12345)
