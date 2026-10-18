import asyncio
import inspect
import io
import json
import sys
from typing import Any, cast

import pytest
from pykdebugparser.trace_codes import syscall_eventids
from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.cli.developer.dvt import core_profile_session
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


@pytest.mark.parametrize("command", ["parse_live_profile_session", "callstacks_live_profile_session"])
def test_live_commands_stream_endlessly_by_default(command: str) -> None:
    # The count is passed to itertools.islice, which rejects -1 as "no limit".
    count = inspect.signature(getattr(core_profile_session, command)).parameters["count"]
    assert count.default is None


LOCKDOWN = cast(LockdownServiceProvider, object())


def test_parse_live_rejects_an_unknown_syscall_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_device(_service_provider: object) -> None:
        raise AssertionError("connected to the device")

    monkeypatch.setattr(core_profile_session, "DvtProvider", no_device)
    monkeypatch.delenv("PYMOBILEDEVICE3_UDID", raising=False)

    result = CliRunner().invoke(
        __main__.app, ["developer", "dvt", "core-profile-session", "parse-live", "-s", "open", "--syscall", "nosuch"]
    )

    assert result.exit_code == 2
    assert "unknown syscalls: nosuch" in result.output
    assert "core-profile-session syscalls" in result.output


def test_syscall_names_are_what_parse_live_accepts() -> None:
    names = core_profile_session.syscall_names()
    assert {"open", "openat", "read"} <= set(names)
    assert "open_nocancel" not in names  # covered by `open`
    assert not [name for name in names if "#" in name]
    assert syscall_eventids(names)


def _run_parse_live(monkeypatch: pytest.MonkeyPatch, **options: Any) -> tuple[Any, Any]:
    """Run parse-live against fakes; return the device filters it requested and its parser."""
    requested: dict[str, Any] = {}
    parsers: list[Any] = []

    class FakeDvtProvider:
        def __init__(self, _service_provider: object) -> None:
            pass

        async def __aenter__(self) -> "FakeDvtProvider":
            return self

        async def __aexit__(self, *exc_info: object) -> None:
            return None

    class FakeCoreProfileSessionTap(FakeDvtProvider):
        def __init__(self, dvt: object, time_config: object, filters: object, sample_callstacks: bool) -> None:
            requested["filters"] = filters

        @staticmethod
        async def get_time_config(dvt: object) -> dict[str, object]:
            return {"numer": 1, "denom": 1, "mach_absolute_time": 0, "usecs_since_epoch": 0, "timezone": None}

        def get_kdbuf_stream(self, chunk_queue: object, **kwargs: object) -> object:
            return object()

        async def pump_kdbuf_chunks(self, chunk_queue: object) -> None:
            await asyncio.Event().wait()

    class FakeParser:
        def __init__(self) -> None:
            parsers.append(self)

        def formatted_traces(self, stream: object) -> list[str]:
            return []

        def dict_traces(self, stream: object) -> list[dict[str, object]]:
            return [{"event": "BSC_open", "fields": {"fd": 3}, "text": "open(), fd: 3"}]

    monkeypatch.setattr(core_profile_session, "DvtProvider", FakeDvtProvider)
    monkeypatch.setattr(core_profile_session, "CoreProfileSessionTap", FakeCoreProfileSessionTap)
    monkeypatch.setattr(core_profile_session, "PyKdebugParser", FakeParser)

    core_profile_session.parse_live_profile_session(
        service_provider=LOCKDOWN, class_filters=[], subclass_filters=[], **{"syscalls": [], "events": [], **options}
    )
    (parser,) = parsers
    return requested["filters"], parser


def test_parse_live_syscall_filters_on_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    filters, parser = _run_parse_live(monkeypatch, syscalls=["open"])

    # The device can only filter subclasses: it sends every syscall, with the VFS lookups that hold the paths.
    assert filters == core_profile_session.parse_filters([core_profile_session.BSC_SUBCLASS], [])
    assert parser.filter_subclass == []
    assert parser.filter_eventid == syscall_eventids(["open"])


def test_syscall_groups_are_known_syscalls() -> None:
    names = set(core_profile_session.syscall_names())
    for group, members in core_profile_session.SYSCALL_GROUPS.items():
        assert set(members) <= names, group


def test_parse_live_fs_and_dyld(monkeypatch: pytest.MonkeyPatch) -> None:
    filters, parser = _run_parse_live(monkeypatch, fs=True, dyld=True)

    assert filters == {
        core_profile_session.BSC_SUBCLASS << 16,
        *core_profile_session.VFS_AND_TRACES_SET,
        (core_profile_session.DBG_DYLD << 24) | 0x00FF0000,  # dyld is filtered on the device
        core_profile_session.TRACE_CLASS_FILTER,  # with the strings its events refer to
    }
    assert parser.filter_class == [core_profile_session.DBG_DYLD]
    assert parser.filter_subclass == []
    assert parser.filter_eventid == syscall_eventids(core_profile_session.SYSCALL_GROUPS["fs"])


def test_parse_live_event(monkeypatch: pytest.MonkeyPatch) -> None:
    filters, parser = _run_parse_live(monkeypatch, events=["DBG_DYLD_TIMING_DLOPEN"])

    # Only the event's subclass is requested from the device, with the strings dyld events refer to.
    assert filters == {0x1F080000, core_profile_session.TRACE_CLASS_FILTER}
    assert parser.filter_class == []
    assert parser.filter_eventid == {0x1F080000}


def test_event_eventids() -> None:
    assert core_profile_session.event_eventids(["BSC_open", "VFS_LOOKUP"]) == {0x40C0014, 0x3010090}
    # A name that several codes share gives all of them.
    assert len(core_profile_session.event_eventids(["CPUPM_FORCED_IDLE"])) > 1
    with pytest.raises(ValueError, match="unknown events: nosuch"):
        core_profile_session.event_eventids(["BSC_open", "nosuch"])


def test_mach_trap_groups_are_known_events() -> None:
    for group, members in core_profile_session.MACH_TRAP_GROUPS.items():
        assert group in core_profile_session.SYSCALL_GROUPS, group
        assert all(name.startswith("MSC_") for name in members), group
        core_profile_session.event_eventids(list(members))


def test_parse_live_groups_add_up(monkeypatch: pytest.MonkeyPatch) -> None:
    filters, parser = _run_parse_live(monkeypatch, fs=True, io=True, mach=True)

    syscalls = [*core_profile_session.SYSCALL_GROUPS["fs"], *core_profile_session.SYSCALL_GROUPS["io"]]
    traps = core_profile_session.event_eventids(list(core_profile_session.group_mach_traps("mach")))
    assert parser.filter_eventid == syscall_eventids(syscalls) | traps
    # Syscalls come in their subclass, Mach traps in theirs.
    assert filters == {
        core_profile_session.BSC_SUBCLASS << 16,
        *core_profile_session.VFS_AND_TRACES_SET,
        0x010C0000,
        core_profile_session.TRACE_CLASS_FILTER,
    }


def test_parse_live_restores_line_buffered_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    # On a terminal stdout is line-buffered; parse-live writes in batches meanwhile and restores it.
    stdout = io.TextIOWrapper(io.BytesIO(), line_buffering=True)
    monkeypatch.setattr(sys, "stdout", stdout)
    _run_parse_live(monkeypatch, io=True)
    assert stdout.line_buffering


def test_mach_group_is_the_parsed_mach_traps() -> None:
    traps = core_profile_session.group_mach_traps("mach")
    assert {"MSC_mach_msg2_trap", "MSC_task_for_pid"} <= set(traps)
    assert all(name.startswith("MSC_") for name in traps)
    assert set(core_profile_session.group_mach_traps("mem")) <= set(traps)


def test_parse_live_json(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _run_parse_live(monkeypatch, json_output=True)

    # Only the traces, one JSON object per line: no status or column header lines.
    assert [json.loads(line) for line in capsys.readouterr().out.splitlines()] == [
        {"event": "BSC_open", "fields": {"fd": 3}, "text": "open(), fd: 3"}
    ]
