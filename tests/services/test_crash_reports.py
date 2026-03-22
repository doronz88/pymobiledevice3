import posixpath
from collections.abc import AsyncGenerator
from contextlib import suppress
from datetime import datetime, timezone
from json import JSONDecodeError
from pathlib import Path
from typing import Optional

import pytest
import pytest_asyncio

from pymobiledevice3.exceptions import AfcFileNotFoundError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.crash_reports import CrashReportsManager

BASENAME = "__pymobiledevice3_tests"
PATH_COMPONENT = f"/{BASENAME}"


@pytest_asyncio.fixture(scope="function")
async def crash_manager(lockdown: LockdownClient):
    async with CrashReportsManager(lockdown) as crash_manager:
        yield crash_manager


@pytest_asyncio.fixture(scope="function")
async def remote_temp_directory(lockdown: LockdownClient) -> AsyncGenerator[str]:
    async with CrashReportsManager(lockdown) as crash_manager:
        with suppress(AfcFileNotFoundError):
            await crash_manager.afc.rm(BASENAME)
        await crash_manager.afc.makedirs(PATH_COMPONENT)
    yield PATH_COMPONENT
    async with CrashReportsManager(lockdown) as crash_manager:
        with suppress(AfcFileNotFoundError):
            await crash_manager.afc.rm(BASENAME)


async def _create_crash_report(crash_manager: CrashReportsManager, filename: str, name: Optional[str] = None) -> None:
    creation_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f +0000")
    name_str = posixpath.splitext(posixpath.basename(filename))[0] if name is None else name

    await crash_manager.afc.set_file_contents(
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


def _nested_paths(root: str, depth: int) -> list[str]:
    paths = [root]
    for _ in range(1, depth):
        paths.append(posixpath.join(paths[-1], BASENAME))
    return paths


async def test_ls_default(crash_manager: CrashReportsManager, remote_temp_directory: str) -> None:
    assert remote_temp_directory in await crash_manager.ls()


async def test_ls_path(crash_manager: CrashReportsManager, remote_temp_directory: str) -> None:
    remote_nested_directory = posixpath.join(remote_temp_directory, BASENAME)
    await crash_manager.afc.makedirs(remote_nested_directory)
    assert remote_nested_directory in await crash_manager.ls(path=remote_temp_directory)


@pytest.mark.parametrize("depth", [2, 3, 4])
async def test_ls_depth(crash_manager: CrashReportsManager, remote_temp_directory: str, depth: int) -> None:
    remote_path_list = _nested_paths(remote_temp_directory, depth)
    await crash_manager.afc.makedirs(remote_path_list[-1])
    crash_list = await crash_manager.ls(depth=depth)
    for item in remote_path_list:
        assert item in crash_list


async def test_ls_depth_minus_one(crash_manager: CrashReportsManager, remote_temp_directory: str) -> None:
    remote_path_list = _nested_paths(remote_temp_directory, 3)
    await crash_manager.afc.makedirs(remote_path_list[-1])
    crash_list = await crash_manager.ls(depth=-1)
    for path in remote_path_list:
        assert path in crash_list


async def test_clear(crash_manager: CrashReportsManager, remote_temp_directory: str) -> None:
    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "clear_test_report.ips"))
    await crash_manager.afc.makedirs(posixpath.join(remote_temp_directory, "nested"))
    await _create_crash_report(
        crash_manager, posixpath.join(remote_temp_directory, "nested", "clear_test_nested_report.ips")
    )

    files = await crash_manager.afc.listdir(remote_temp_directory)
    assert len(files) > 0

    await crash_manager.clear(remote_temp_directory)

    files = await crash_manager.afc.listdir(remote_temp_directory)
    assert len(files) == 0


async def test_pull_file(crash_manager: CrashReportsManager, remote_temp_directory: str, tmp_path: Path) -> None:
    remote_file = posixpath.join(remote_temp_directory, "pull_test_report.ips")
    await _create_crash_report(crash_manager, remote_file)

    local_output_dir = tmp_path
    await crash_manager.pull(str(local_output_dir), remote_file)

    local_file = local_output_dir / "pull_test_report.ips"
    assert local_file.exists()


async def test_pull_directory(crash_manager: CrashReportsManager, remote_temp_directory: str, tmp_path: Path) -> None:
    remote_file = posixpath.join(remote_temp_directory, "pull_test_report.ips")
    remote_nested_directory = posixpath.join(remote_temp_directory, "nested")
    remote_nested_file = posixpath.join(remote_nested_directory, "pull_test_nested_report.ips")
    await _create_crash_report(crash_manager, remote_file)
    await crash_manager.afc.makedirs(remote_nested_directory)
    await _create_crash_report(crash_manager, remote_nested_file)

    local_output_dir = tmp_path
    await crash_manager.pull(str(local_output_dir), remote_temp_directory)

    pulled_directories = [path for path in local_output_dir.iterdir() if path.is_dir()]
    assert len(pulled_directories) == 1
    local_pulled_directory = pulled_directories[0]
    assert local_pulled_directory.is_dir()
    assert (local_pulled_directory / "nested").is_dir()
    assert (local_pulled_directory / "nested" / "pull_test_nested_report.ips").is_file()
    assert (local_pulled_directory / "pull_test_report.ips").is_file()


async def test_parse(crash_manager: CrashReportsManager, remote_temp_directory: str) -> None:
    filename = posixpath.join(remote_temp_directory, "parse_test_report.ips")
    await _create_crash_report(crash_manager, filename)

    parsed = await crash_manager.parse(filename)
    assert parsed.filename == filename
    assert parsed.name == "parse_test_report"
    assert parsed.incident_id == "parse_test_report"


async def test_parse_invalid_raises(crash_manager: CrashReportsManager, remote_temp_directory: str) -> None:
    filename = posixpath.join(remote_temp_directory, "invalid_report.ips")
    await crash_manager.afc.set_file_contents(filename, b"not-json\n{}")

    with pytest.raises(JSONDecodeError):
        await crash_manager.parse(filename)


@pytest.mark.parametrize(
    ("end_time", "return_value"),
    ((-1, True), (0, True), (float("inf"), False), (None, False)),
)
def test_check_timeout(crash_manager: CrashReportsManager, end_time: int, return_value: bool) -> None:
    assert crash_manager._check_timeout(end_time) is return_value


async def test_parse_latest(crash_manager: CrashReportsManager, remote_temp_directory: str) -> None:
    older = posixpath.join(remote_temp_directory, "quite_old.ips")
    newer = posixpath.join(remote_temp_directory, "quite_new.ips")

    await _create_crash_report(crash_manager, older)
    await _create_crash_report(crash_manager, newer)

    parsed = await crash_manager.parse_latest(path=remote_temp_directory)
    assert len(parsed) == 1
    assert parsed[0].filename == newer


@pytest.mark.parametrize(
    ("match", "match_insensitive"),
    (
        ([r"ite_old"], None),
        ([r"old", r"quite"], None),
        (None, [r"iTe_Old"]),
        (None, [r"olD", r"QUIte"]),
    ),
)
async def test_parse_latest_filter_variants(
    crash_manager: CrashReportsManager,
    remote_temp_directory: str,
    match: Optional[list[str]],
    match_insensitive: Optional[list[str]],
) -> None:
    oldest = posixpath.join(remote_temp_directory, "quite_old.ips")
    await _create_crash_report(crash_manager, oldest)
    for i in range(10):
        await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, f"too_old_{i}.ips"))
    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "quite_new.ips"))

    parsed = await crash_manager.parse_latest(
        path=remote_temp_directory, match=match, match_insensitive=match_insensitive
    )

    assert len(parsed) == 1
    assert parsed[0].filename == oldest


async def test_parse_latest_match_and_match_insensitive_combined(
    crash_manager: CrashReportsManager, remote_temp_directory: str
) -> None:
    report_paths = [posixpath.join(remote_temp_directory, f"one_two{i}.ips") for i in range(5)]
    report_paths += [posixpath.join(remote_temp_directory, f"Two_Three{i}.ips") for i in range(5)]

    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "just_here.ips"))
    for report_path in report_paths:
        await _create_crash_report(crash_manager, report_path)
    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "three_sensitive.ips"))
    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "Three_but_no_t_w_o.ips"))

    parsed = await crash_manager.parse_latest(path=remote_temp_directory, match=["Three"], match_insensitive=["two"])
    assert len(parsed) == 1
    assert parsed[0].filename == report_paths[-1]


async def test_parse_latest_ignores_nested_matches(
    crash_manager: CrashReportsManager, remote_temp_directory: str
) -> None:
    matching_dir = posixpath.join(remote_temp_directory, "report_dir")
    another_matching_dir = posixpath.join(remote_temp_directory, "report")
    matching_file = posixpath.join(matching_dir, "report_file.ips")

    await crash_manager.afc.makedirs(matching_dir)
    await crash_manager.afc.makedirs(another_matching_dir)
    await _create_crash_report(crash_manager, matching_file)

    with pytest.raises(ValueError, match="No reports found"):
        await crash_manager.parse_latest(path=remote_temp_directory, match=[r"report"], count=3)


async def test_parse_latest_prefers_top_level_matches(
    crash_manager: CrashReportsManager, remote_temp_directory: str
) -> None:
    matching_dir = posixpath.join(remote_temp_directory, "report_dir")
    another_matching_dir = posixpath.join(remote_temp_directory, "report")
    matching_file = posixpath.join(matching_dir, "report_file.ips")
    top_level_file = posixpath.join(remote_temp_directory, "report_top_level.ips")

    await crash_manager.afc.makedirs(matching_dir)
    await crash_manager.afc.makedirs(another_matching_dir)
    await _create_crash_report(crash_manager, matching_file)
    await _create_crash_report(crash_manager, top_level_file)

    parsed = await crash_manager.parse_latest(path=remote_temp_directory, match=[r"report"], count=3)
    assert len(parsed) == 1
    assert parsed[0].filename == top_level_file


async def test_parse_latest_count(crash_manager: CrashReportsManager, remote_temp_directory: str) -> None:
    count = 3
    report_paths = [posixpath.join(remote_temp_directory, f"report{i}.ips") for i in range(2 * count)]
    for report_path in report_paths:
        await _create_crash_report(crash_manager, report_path)

    parsed = await crash_manager.parse_latest(path=remote_temp_directory, match=[r"report"], count=count)
    assert [p.filename for p in parsed] == list(reversed(report_paths))[:count]


async def test_parse_latest_count_larger_than_available_reports(
    crash_manager: CrashReportsManager, remote_temp_directory: str
) -> None:
    report_paths = [posixpath.join(remote_temp_directory, f"report{i}.ips") for i in range(5)]
    more_report_paths = [posixpath.join(remote_temp_directory, f"noiseee{i}.ips") for i in range(10)]
    for report_path in report_paths + more_report_paths:
        await _create_crash_report(crash_manager, report_path)

    parsed = await crash_manager.parse_latest(path=remote_temp_directory, match=[r"report"], count=100)
    assert [p.filename for p in parsed] == list(reversed(report_paths))


async def test_parse_latest_count_match_and_match_insensitive_combined(
    crash_manager: CrashReportsManager, remote_temp_directory: str
) -> None:
    report_paths = [posixpath.join(remote_temp_directory, f"One_Two{i}.ips") for i in range(5)]
    more_report_paths = [posixpath.join(remote_temp_directory, f"one_two{i}.ips") for i in range(5)]

    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "just_here.ips"))
    for report_path in report_paths + more_report_paths:
        await _create_crash_report(crash_manager, report_path)
    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "one_but_not_T-w-o.ips"))
    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "Two_but_not_o-n-e.ips"))

    parsed = await crash_manager.parse_latest(
        path=remote_temp_directory, match=["Two"], match_insensitive=["one"], count=len(report_paths)
    )
    assert [p.filename for p in parsed] == list(reversed(report_paths))


async def test_parse_latest_invalid_count_raises(crash_manager: CrashReportsManager) -> None:
    with pytest.raises(ValueError):
        await crash_manager.parse_latest(count=0)


@pytest.mark.parametrize(
    ("match", "match_insensitive"),
    (
        (["missing"], None),
        (None, ["also-missing"]),
        (["missing"], ["also-missing"]),
    ),
)
async def test_parse_latest_no_matches(
    crash_manager: CrashReportsManager,
    remote_temp_directory: str,
    match: Optional[list[str]],
    match_insensitive: Optional[list[str]],
) -> None:
    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "hello.ips"))
    await _create_crash_report(crash_manager, posixpath.join(remote_temp_directory, "world.ips"))

    with pytest.raises(ValueError):
        await crash_manager.parse_latest(path=remote_temp_directory, match=match, match_insensitive=match_insensitive)
