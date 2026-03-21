import json
from io import StringIO

import pytest
import typer

from pymobiledevice3.cli.developer.dvt.sysmon import process as process_module
from pymobiledevice3.cli.developer.dvt.sysmon.process import (
    ProcessSelectionMode,
    _describe_process,
    _describe_processes,
    _duration_elapsed,
    _format_byte_count,
    _get_process_identifier,
    _humanize_process_values,
    _matches_filters,
    _matches_selected_process,
    _parse_process_filters,
    _process_sort_key,
    _select_process_from_candidates,
    _select_process_from_snapshot,
    _select_process_from_sysmon,
    _select_process_output_keys,
    _serialize_process,
    _validate_process_keys,
    _write_json,
    _write_process,
    iter_initialized_processes,
)


def test_parse_process_filters_groups_values_by_key():
    assert _parse_process_filters(["name=abc", "name=def", "pid=7"]) == {
        "name": ["abc", "def"],
        "pid": ["7"],
    }


@pytest.mark.parametrize("raw_filter", ["no_value", "=no_key"])
def test_parse_process_filters_rejects_invalid_input(raw_filter):
    with pytest.raises(typer.BadParameter):
        _parse_process_filters([raw_filter])


def test_validate_process_keys_rejects_unknown_keys():
    with pytest.raises(typer.BadParameter, match="does not have the following keys"):
        _validate_process_keys({"pid": 1, "name": "abc"}, ["pid", "missing"])


def test_matches_filters_requires_all_keys_and_any_value_per_key():
    process = {"pid": 123, "name": "abc", "realAppName": "Calculator"}
    assert _matches_filters(process, {"pid": ["123"], "name": ["abc", "def"]})
    assert not _matches_filters(process, {"pid": ["999"]})
    assert not _matches_filters(process, {"bundleIdentifier": ["com.example.app"]})


def test_select_process_output_keys_returns_process_when_no_keys_requested():
    process = {"pid": 1, "name": "abc"}
    assert _select_process_output_keys(process, None) == process


def test_select_process_output_keys_filters_selected_keys():
    assert _select_process_output_keys({"pid": 1, "name": "abc", "cpuUsage": 7.5}, ["pid", "name"]) == {
        "pid": 1,
        "name": "abc",
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (10, "10B"),
        (1024, "1.0KB"),
        (10 * 1024, "10KB"),
        (1024 * 1024, "1.0MB"),
    ],
)
def test_format_byte_count(value, expected):
    assert _format_byte_count(value) == expected


def test_humanize_process_values_formats_only_known_byte_fields():
    assert _humanize_process_values({"physFootprint": 2048, "name": "abc", "cpuUsage": 2.0}) == {
        "physFootprint": "2.0KB",
        "name": "abc",
        "cpuUsage": 2.0,
    }


def test_serialize_process_filters_selected_keys():
    serialized = _serialize_process({"pid": 1, "name": "abc", "cpuUsage": 7.5}, ["pid", "name"])
    assert serialized["pid"] == 1
    assert serialized["name"] == "abc"
    assert "cpuUsage" not in serialized
    assert "timestamp" in serialized


def test_serialize_process_humanizes_selected_values():
    serialized = _serialize_process({"physFootprint": 2048, "cpuUsage": 1.5}, ["physFootprint"], human=True)
    assert serialized["physFootprint"] == "2.0KB"
    assert "cpuUsage" not in serialized
    assert "timestamp" in serialized


def test_write_process_writes_jsonl_to_output_stream():
    out = StringIO()
    _write_process(out, {"pid": 1})
    assert out.getvalue() == '{"pid": 1}\n'


def test_write_process_prints_json_when_out_is_none(monkeypatch):
    captured = {}

    def fake_print_json(value):
        captured["value"] = value

    monkeypatch.setattr(process_module, "print_json", fake_print_json)

    _write_process(None, {"pid": 1})

    assert captured["value"] == {"pid": 1}


def test_write_json_writes_formatted_json_to_output_stream():
    out = StringIO()
    _write_json(out, [{"pid": 1}])
    assert json.loads(out.getvalue()) == [{"pid": 1}]


def test_write_json_prints_json_when_out_is_none(monkeypatch):
    captured = {}

    def fake_print_json(value):
        captured["value"] = value

    monkeypatch.setattr(process_module, "print_json", fake_print_json)

    _write_json(None, [{"pid": 1}])

    assert captured["value"] == [{"pid": 1}]


def test_describe_process_includes_pid_ppid_name():
    assert _describe_process({"pid": 7, "ppid": 1, "name": "abc", "comm": "abc"}) == "pid=7, ppid=1, name=abc"


def test_describe_process_falls_back_to_comm():
    assert _describe_process({"pid": 7, "ppid": 1, "comm": "abc"}) == "pid=7, ppid=1, name=abc"


def test_describe_process_falls_back_to_unknown():
    assert _describe_process({"pid": 7, "ppid": 1}) == "pid=7, ppid=1, name=<unknown>"


def test_describe_processes_joins_descriptions():
    assert (
        _describe_processes([
            {"pid": 7, "ppid": 1, "name": "abc"},
            {"pid": 8, "ppid": 2, "name": "def"},
        ])
        == "pid=7, ppid=1, name=abc; pid=8, ppid=2, name=def"
    )


def test_duration_elapsed_false_when_duration_is_none():
    assert _duration_elapsed(10.0, None) is False


@pytest.mark.parametrize(
    ("start_time", "duration_ms", "current_time", "expected"),
    [
        (1.0, 1000, 1.5, False),
        (1.0, 1000, 2.0, True),
        (1.0, 0, 1.0, True),
    ],
)
def test_duration_elapsed(monkeypatch, start_time, duration_ms, current_time, expected):
    fake_loop = type("FakeLoop", (), {"time": lambda self: current_time})()
    monkeypatch.setattr(process_module.asyncio, "get_running_loop", lambda: fake_loop)
    assert _duration_elapsed(start_time, duration_ms) is expected


class _FakeSysmontap:
    def __init__(self, snapshots):
        self._snapshots = snapshots

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def iter_processes(self):
        for snapshot in self._snapshots:
            yield snapshot


@pytest.mark.asyncio
async def test_iter_initialized_processes_skips_first_snapshot():
    sysmon = _FakeSysmontap([
        [{"pid": 10, "ppid": 1, "name": "first-snapshot"}],
        [{"pid": 20, "ppid": 2, "name": "second-snapshot"}],
        [{"pid": 30, "ppid": 3, "name": "third-snapshot"}],
    ])

    snapshots = [snapshot async for snapshot in iter_initialized_processes(sysmon)]

    assert snapshots == [
        [{"pid": 20, "ppid": 2, "name": "second-snapshot"}],
        [{"pid": 30, "ppid": 3, "name": "third-snapshot"}],
    ]


@pytest.mark.asyncio
async def test_iter_initialized_processes_empty_when_only_warmup_snapshot_exists():
    sysmon = _FakeSysmontap([[{"pid": 10, "ppid": 1, "name": "first-snapshot"}]])

    snapshots = [snapshot async for snapshot in iter_initialized_processes(sysmon)]

    assert snapshots == []


def test_process_sort_key_normalizes_missing_values():
    assert _process_sort_key({"name": "abc"}) == (-1, -1, "abc")


def test_select_process_from_candidates_returns_single_match():
    process = {"pid": 7, "name": "abc"}
    assert _select_process_from_candidates([process], ProcessSelectionMode.PROMPT) == process


def test_select_process_from_candidates_first_is_deterministic():
    first = {"pid": 3, "name": "abc", "startAbsTime": 10}
    second = {"pid": 2, "name": "abc", "startAbsTime": 20}
    assert _select_process_from_candidates([second, first], ProcessSelectionMode.FIRST) == first


def test_select_process_from_candidates_last_is_deterministic():
    first = {"pid": 3, "name": "abc", "startAbsTime": 10}
    last = {"pid": 2, "name": "abc", "startAbsTime": 20}
    assert _select_process_from_candidates([last, first], ProcessSelectionMode.LAST) == last


def test_select_process_from_candidates_multiple_non_tty_raises(monkeypatch):
    monkeypatch.setattr(process_module.sys, "stdin", type("FakeStdin", (), {"isatty": lambda self: False})())

    with pytest.raises(typer.BadParameter, match='Re-run with "--choose first", "--choose last"'):
        _select_process_from_candidates(
            [{"pid": 1, "ppid": 0, "name": "a"}, {"pid": 2, "ppid": 0, "name": "b"}],
            ProcessSelectionMode.PROMPT,
        )


def test_select_process_from_candidates_prompt_uses_sorted_choices(monkeypatch):
    monkeypatch.setattr(process_module.sys, "stdin", type("FakeStdin", (), {"isatty": lambda self: True})())

    captured = {}

    def fake_prompt_selection(choices, message, idx=False):
        captured["choices"] = choices
        captured["message"] = message
        captured["idx"] = idx
        return 1

    monkeypatch.setattr(process_module, "prompt_selection", fake_prompt_selection)

    processes = [
        {"pid": 20, "ppid": 2, "name": "later", "startAbsTime": 20},
        {"pid": 10, "ppid": 1, "name": "earlier", "startAbsTime": 10},
    ]

    selected = _select_process_from_candidates(processes, ProcessSelectionMode.PROMPT)

    assert selected == processes[0]
    assert captured["choices"] == [
        "pid=10, ppid=1, name=earlier",
        "pid=20, ppid=2, name=later",
    ]
    assert captured["message"] == "Choose process to monitor"
    assert captured["idx"] is True


def test_get_process_identifier_prefers_unique_id_then_start_time_then_pid():
    assert _get_process_identifier({"uniqueID": 11, "startAbsTime": 22, "pid": 33}) == ("uniqueID", 11)
    assert _get_process_identifier({"startAbsTime": 22, "pid": 33}) == ("startAbsTime", 22)
    assert _get_process_identifier({"pid": 33}) == ("pid", 33)


def test_matches_selected_process_uses_identifier_tuple():
    assert _matches_selected_process({"uniqueID": 11}, ("uniqueID", 11))
    assert not _matches_selected_process({"uniqueID": 12}, ("uniqueID", 11))


def test_select_process_from_snapshot_filters_current_snapshot_only():
    process_snapshot = [
        {"pid": 10, "ppid": 1, "name": "alpha"},
        {"pid": 20, "ppid": 1, "name": "beta"},
    ]

    selected = _select_process_from_snapshot(process_snapshot, {"name": ["beta"]}, ProcessSelectionMode.FIRST)

    assert selected == {"pid": 20, "ppid": 1, "name": "beta"}


def test_select_process_from_snapshot_rejects_unknown_filter_keys():
    with pytest.raises(typer.BadParameter, match="does not have the following keys"):
        _select_process_from_snapshot(
            [{"pid": 10, "ppid": 1, "name": "alpha"}],
            {"missing": ["value"]},
            ProcessSelectionMode.FIRST,
        )


def test_select_process_from_snapshot_raises_when_no_match():
    with pytest.raises(typer.BadParameter, match="current snapshot"):
        _select_process_from_snapshot(
            [{"pid": 10, "ppid": 1, "name": "alpha"}],
            {"name": ["beta"]},
            ProcessSelectionMode.FIRST,
        )


@pytest.mark.asyncio
async def test_select_process_from_sysmon_skips_first_snapshot(monkeypatch):
    async def fake_create(_dvt):
        return _FakeSysmontap([
            [{"pid": 10, "ppid": 1, "name": "first-snapshot"}],
            [{"pid": 20, "ppid": 2, "name": "second-snapshot"}],
        ])

    monkeypatch.setattr(process_module.Sysmontap, "create", fake_create)

    selected = await _select_process_from_sysmon(
        object(), {"name": ["second-snapshot"]}, None, ProcessSelectionMode.FIRST
    )

    assert selected == {"pid": 20, "ppid": 2, "name": "second-snapshot"}


@pytest.mark.asyncio
async def test_select_process_from_sysmon_raises_when_no_usable_snapshot(monkeypatch):
    async def fake_create(_dvt):
        return _FakeSysmontap([])

    monkeypatch.setattr(process_module.Sysmontap, "create", fake_create)

    with pytest.raises(typer.BadParameter, match="failed to collect a process snapshot"):
        await _select_process_from_sysmon(object(), {}, None, ProcessSelectionMode.FIRST)
