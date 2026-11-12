import pytest

from pymobiledevice3.remote import ddi_services
from pymobiledevice3.remote.ddi_services import DDI_BUILDS, DDI_SERVICES, ddi_includes
from pymobiledevice3.services.mobile_image_mounter import LATEST_DDI_BUILD_ID

SCREEN_CAPTURE = "com.apple.coredevice.screencaptureservice"  # 27A5194q on
APP_SERVICE = "com.apple.coredevice.appservice"  # in every known build
DROPPED = "com.apple.coredevice.dropped"


@pytest.fixture
def dropped_service(monkeypatch: pytest.MonkeyPatch) -> str:
    # No DDI has dropped a service so far, but nothing stops a future one
    monkeypatch.setitem(ddi_services.DDI_SERVICES, DROPPED, ("16B40", "17B5045g"))
    return DROPPED


def test_the_table_knows_the_ddi_this_release_mounts() -> None:
    # Bumping LATEST_DDI_BUILD_ID without rerunning misc/ddi_services.py leaves the table stale
    assert DDI_BUILDS[-1] == LATEST_DDI_BUILD_ID


def test_every_span_is_made_of_known_builds_in_order() -> None:
    for first, last in DDI_SERVICES.values():
        # `None` stands for "still provided": the newest build is never spelled out as a last one
        assert last is None or DDI_BUILDS.index(first) <= DDI_BUILDS.index(last) < len(DDI_BUILDS) - 1


@pytest.mark.parametrize(
    ("build", "included"),
    [
        ("27A5194q", True),  # the first known build with it
        (LATEST_DDI_BUILD_ID, True),
        ("17E5179g", False),  # the last known build without it
        ("16B40", False),
    ],
)
def test_a_known_build_is_answered_from_the_table(build: str, included: bool) -> None:
    assert ddi_includes(SCREEN_CAPTURE, build) is included


@pytest.mark.parametrize(
    ("build", "included"),
    [
        ("27C10", True),  # newer than every known build
        ("28A100", True),
        ("17C50", False),  # older than the last known build without it
        ("14A100", False),
        ("17F100", None),  # between the last known build without it and the first with it
    ],
)
def test_an_unknown_build_is_placed_by_its_train(build: str, included: object) -> None:
    assert ddi_includes(SCREEN_CAPTURE, build) is included


def test_a_build_older_than_every_known_one_is_not_assumed_to_lack_a_service_they_all_have() -> None:
    assert ddi_includes(APP_SERVICE, "14A100") is None


@pytest.mark.parametrize("build", ["27A300", "17E100", "not-a-build", ""])
def test_a_build_that_cannot_be_ordered_is_not_answered(build: str) -> None:
    # 27A300 shares its train with 27A5194q: a seed and a release do not order by their numbers
    assert ddi_includes(SCREEN_CAPTURE, build) is None


def test_a_dropped_service_is_not_included_after_its_last_build(dropped_service: str) -> None:
    assert ddi_includes(dropped_service, "17A324") is True
    assert ddi_includes(dropped_service, "17E5179g") is False
    assert ddi_includes(dropped_service, "28A100") is False
    assert ddi_includes(dropped_service, "17C50") is None  # between its last build and the next known one


def test_a_service_the_newest_build_has_carries_no_last_build() -> None:
    assert DDI_SERVICES[SCREEN_CAPTURE] == ("27A5194q", None)
