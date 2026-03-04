import glob
import posixpath
import shutil
import time
from datetime import datetime, timezone
from json import JSONDecodeError
from typing import Optional

import pytest

from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.services.crash_reports import CrashReportsManager

BASENAME = "__pymobiledevice3_tests"
PATH_COMPONENT = f"/{BASENAME}"


@pytest.fixture(scope="function")
def crash_manager(lockdown: LockdownClient):
    with CrashReportsManager(lockdown) as crash_manager:
        yield crash_manager


@pytest.fixture(scope="function")
def delete_test_dir():
    with create_using_usbmux() as lockdown_client, CrashReportsManager(lockdown_client) as crash_manager:
        if crash_manager.afc.exists(BASENAME):
            crash_manager.afc.rm(BASENAME)
        yield
        if crash_manager.afc.exists(BASENAME):
            crash_manager.afc.rm(BASENAME)


def _create_crash_report(crash_manager: CrashReportsManager, filename: str, *, name: Optional[str] = None) -> None:
    creation_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f +0000")
    name_str = posixpath.splitext(posixpath.basename(filename))[0] if name is None else name

    crash_manager.afc.set_file_contents(
        filename,
        (
            '{"bug_type":"999","incident_id":"'
            + name_str
            + '","timestamp":"'
            + creation_time
            + '","name":"'
            + name_str
            + '"}\n{"payload":"ok"}'
        ).encode(),
    )


@pytest.mark.usefixtures("delete_test_dir")
def test_ls_default(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    assert PATH_COMPONENT in crash_manager.ls()


@pytest.mark.usefixtures("delete_test_dir")
def test_ls_path(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT * 2)
    assert (PATH_COMPONENT * 2) in crash_manager.ls(path=PATH_COMPONENT)


@pytest.mark.usefixtures("delete_test_dir")
@pytest.mark.parametrize("depth", [2, 3, 4])
def test_ls_depth(crash_manager: CrashReportsManager, depth: int) -> None:
    path = PATH_COMPONENT * depth
    path_list = [PATH_COMPONENT * i for i in range(1, depth + 1)]
    crash_manager.afc.makedirs(path)
    crash_list = crash_manager.ls(depth=depth)
    for item in path_list:
        assert item in crash_list


@pytest.mark.usefixtures("delete_test_dir")
def test_ls_depth_minus_one(crash_manager: CrashReportsManager) -> None:
    path_list = [PATH_COMPONENT, PATH_COMPONENT * 2, PATH_COMPONENT * 3]
    crash_manager.afc.makedirs(path_list[-1])
    crash_list = crash_manager.ls(depth=-1)
    for path in path_list:
        assert path in crash_list


def test_clear(crash_manager, delete_test_dir: None) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    # true indication device time we can assure that every other file should create after it
    test_dir_birth_time = crash_manager.afc.stat(PATH_COMPONENT)["st_birthtime"]
    crash_manager.clear()
    crash_dirlist = crash_manager.ls(depth=-1)
    assert PATH_COMPONENT not in crash_dirlist
    for path in crash_dirlist:
        if path != crash_manager.APPSTORED_PATH:
            assert crash_manager.afc.stat(path)["st_birthtime"] > test_dir_birth_time


@pytest.mark.usefixtures("delete_test_dir")
def test_pull(crash_manager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    dir_list = crash_manager.ls(depth=-1)
    crash_manager.pull(BASENAME)
    pulled_list = [file[len(BASENAME) :] for file in glob.glob(f"{BASENAME}/**", recursive=True)][
        1:
    ]  # ignore root path
    assert sorted(dir_list) == sorted(pulled_list)
    shutil.rmtree(BASENAME)


@pytest.mark.usefixtures("delete_test_dir")
def test_parse(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    filename = f"{PATH_COMPONENT}/parse_test_report.ips"
    _create_crash_report(crash_manager, filename)

    parsed = crash_manager.parse(filename)
    assert parsed.filename == filename
    assert parsed.name == "parse_test_report"
    assert parsed.incident_id == "parse_test_report"


@pytest.mark.usefixtures("delete_test_dir")
def test_parse_invalid_raises(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    filename = f"{PATH_COMPONENT}/invalid_report.ips"
    crash_manager.afc.set_file_contents(filename, b"not-json\n{}")

    with pytest.raises(JSONDecodeError):
        crash_manager.parse(filename)


@pytest.mark.parametrize(
    ("end_time", "return_value"),
    ((-1, True), (0, True), (time.monotonic() + 1000, False), (None, False)),
)
def test_check_timeout(crash_manager: CrashReportsManager, end_time: int, return_value: bool) -> None:
    assert crash_manager._check_timeout(end_time) is return_value


@pytest.mark.usefixtures("delete_test_dir")
def test_parse_latest(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    older = f"{PATH_COMPONENT}/quite_old.ips"
    newer = f"{PATH_COMPONENT}/quite_new.ips"

    _create_crash_report(crash_manager, older)
    _create_crash_report(crash_manager, newer)

    parsed = crash_manager.parse_latest()
    assert len(parsed) == 1
    assert parsed[0].filename == newer


@pytest.mark.usefixtures("delete_test_dir")
@pytest.mark.parametrize(
    ("match", "match_insensitive"),
    (
        ([r"ite_old"], None),
        ([r"old", r"quite"], None),
        (None, [r"iTe_Old"]),
        (None, [r"olD", r"QUIte"]),
    ),
)
def test_parse_latest_filter_variants(
    crash_manager: CrashReportsManager,
    match: Optional[list[str]],
    match_insensitive: Optional[list[str]],
) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    oldest = f"{PATH_COMPONENT}/quite_old.ips"
    _create_crash_report(crash_manager, oldest)
    for i in range(10):
        _create_crash_report(crash_manager, f"{PATH_COMPONENT}/too_old_{i}.ips")
    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/quite_new.ips")

    parsed = crash_manager.parse_latest(match=match, match_insensitive=match_insensitive)

    assert len(parsed) == 1
    assert parsed[0].filename == oldest


@pytest.mark.usefixtures("delete_test_dir")
def test_parse_latest_match_and_match_insensitive_combined(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)

    report_paths = [f"{PATH_COMPONENT}/one_two{i}.ips" for i in range(5)]
    report_paths += [f"{PATH_COMPONENT}/Two_Three{i}.ips" for i in range(5)]

    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/just_here.ips")
    for report_path in report_paths:
        _create_crash_report(crash_manager, report_path)
    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/three_sensitive.ips")
    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/Three_but_no_t_w_o.ips")

    parsed = crash_manager.parse_latest(match=["Three"], match_insensitive=["two"])
    assert len(parsed) == 1
    assert parsed[0].filename == report_paths[-1]


@pytest.mark.usefixtures("delete_test_dir")
def test_parse_latest_ignores_matching_directories(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    matching_dir = f"{PATH_COMPONENT}/report_dir"
    another_matching_dir = f"{PATH_COMPONENT}/report"
    matching_file = f"{matching_dir}/report_file.ips"

    crash_manager.afc.makedirs(matching_dir)
    crash_manager.afc.makedirs(another_matching_dir)
    _create_crash_report(crash_manager, matching_file)

    parsed = crash_manager.parse_latest(match=[r"report"], count=3)
    assert len(parsed) == 1
    assert parsed[0].filename == matching_file


@pytest.mark.usefixtures("delete_test_dir")
def test_parse_latest_count(crash_manager: CrashReportsManager) -> None:
    COUNT = 3
    crash_manager.afc.makedirs(PATH_COMPONENT)
    report_paths = [f"{PATH_COMPONENT}/report{i}.ips" for i in range(2 * COUNT)]
    for report_path in report_paths:
        _create_crash_report(crash_manager, report_path)

    parsed = crash_manager.parse_latest(match=[r"report"], count=COUNT)
    assert [p.filename for p in parsed] == sorted(report_paths, reverse=True)[:COUNT]


@pytest.mark.usefixtures("delete_test_dir")
def test_parse_latest_count_larger_than_available_reports(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    report_paths = [f"{PATH_COMPONENT}/report{i}.ips" for i in range(5)]
    more_report_paths = [f"{PATH_COMPONENT}/noiseee{i}.ips" for i in range(10)]
    for report_path in report_paths + more_report_paths:
        _create_crash_report(crash_manager, report_path)

    parsed = crash_manager.parse_latest(match=[r"report"], count=100)
    assert [p.filename for p in parsed] == sorted(report_paths, reverse=True)


@pytest.mark.usefixtures("delete_test_dir")
def test_parse_latest_count_match_and_match_insensitive_combined(crash_manager: CrashReportsManager) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)

    report_paths = [f"{PATH_COMPONENT}/One_Two{i}.ips" for i in range(5)]
    more_report_paths = [f"{PATH_COMPONENT}/one_two{i}.ips" for i in range(5)]

    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/just_here.ips")
    for report_path in report_paths + more_report_paths:
        _create_crash_report(crash_manager, report_path)
    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/one_but_not_T-w-o.ips")
    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/Two_but_not_o-n-e.ips")

    parsed = crash_manager.parse_latest(match=["Two"], match_insensitive=["one"], count=len(report_paths))
    assert [p.filename for p in parsed] == sorted(report_paths, reverse=True)


@pytest.mark.usefixtures("delete_test_dir")
def test_parse_latest_invalid_count_raises(crash_manager: CrashReportsManager) -> None:
    with pytest.raises(ValueError):
        crash_manager.parse_latest(count=0)


@pytest.mark.usefixtures("delete_test_dir")
@pytest.mark.parametrize(
    ("match", "match_insensitive"),
    (
        (["missing"], None),
        (None, ["also-missing"]),
        (["missing"], ["also-missing"]),
    ),
)
def test_parse_latest_no_matches(
    crash_manager: CrashReportsManager,
    match: Optional[list[str]],
    match_insensitive: Optional[list[str]],
) -> None:
    crash_manager.afc.makedirs(PATH_COMPONENT)
    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/hello.ips")
    _create_crash_report(crash_manager, f"{PATH_COMPONENT}/world.ips")

    with pytest.raises(ValueError):
        crash_manager.parse_latest(match=match, match_insensitive=match_insensitive)
