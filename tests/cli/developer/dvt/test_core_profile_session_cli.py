import asyncio
import inspect
import io
import json
import sys
from typing import Any, cast

import pytest
from pykdebugparser.trace_codes import default_trace_codes, syscall_eventids
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


def test_live_trace_codes_fall_back_to_pykdebugparser() -> None:
    codes = core_profile_session.live_trace_codes({0x29000044: "DEVICE_NAME", 0x40C0014: "BSC_open"})
    # The device's names win; the events its table does not name get pykdebugparser's.
    assert codes[0x29000044] == "DEVICE_NAME"
    assert codes[0x40C0014] == "BSC_open"
    assert codes[0x2E030004] == "DISPATCH_MACH_MSG_hdr_move"


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
    assert "core-profile-session events" in result.output


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
        service_provider=LOCKDOWN,
        **{"class_filters": [], "subclass_filters": [], "syscalls": [], "events": [], **options},
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


def test_parse_live_user_space_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    filters, parser = _run_parse_live(monkeypatch, xpc=True, dispatch=True, runloop=True)

    names = [name for group in ("xpc", "dispatch", "runloop") for name in core_profile_session.group_events(group)]
    # The events have no decoder: asking for them by id is what prints them (as their name and raw arguments).
    assert parser.filter_eventid == core_profile_session.event_eventids(names)
    # Only their subclasses are requested from the device.
    assert filters == {
        0x29000000,  # libxpc
        0x2BDC0000,  # libdispatch
        0x2E020000,
        0x2E030000,
        0x14130000,  # CoreFoundation run loop
        0x21110000,
        0x21120000,
        core_profile_session.TRACE_CLASS_FILTER,
    }


def _events(*args: str) -> list[str]:
    result = CliRunner().invoke(__main__.app, ["developer", "dvt", "core-profile-session", "events", *args])
    assert result.exit_code == 0, result.output
    return result.output.split()


@pytest.mark.parametrize(("group", "prefix"), [("xpc", "XPC_"), ("dispatch", "DISPATCH_"), ("runloop", "CFRL_")])
def test_events_lists_a_user_space_group(group: str, prefix: str) -> None:
    names = _events(f"--{group}")

    assert names
    assert all(name.startswith(prefix) for name in names)
    assert names == list(core_profile_session.group_events(group))


def test_events_lists_what_a_syscall_group_prints() -> None:
    names = _events("--mem")

    # Its syscalls, with their _nocancel variants, and its Mach traps: exactly what --mem filters.
    assert "BSC_mmap" in names
    assert "MSC_mach_vm_allocate_trap" in names
    eventids = syscall_eventids(core_profile_session.SYSCALL_GROUPS["mem"])
    eventids |= core_profile_session.event_eventids(list(core_profile_session.group_mach_traps("mem")))
    assert core_profile_session.event_eventids(names) == eventids


def test_events_lists_the_dyld_events_dyld_prints() -> None:
    names = _events("--dyld")

    assert "DBG_DYLD_TIMING_DLSYM" in names
    assert "DYLD_uuid_map_a" in names  # image loads
    # A class filter prints only the events pykdebugparser decodes; the others are dropped, so they are not listed.
    assert "DYLD_NSAddImage" not in names


def test_events_lists_what_a_syscall_selects() -> None:
    # Opening with a data protection class is the same call.
    assert _events("-s", "open") == ["BSC_open", "BSC_open_dprotected_np", "BSC_open_nocancel"]


def test_events_shows_that_a_class_filter_drops_undecoded_events() -> None:
    # parse-live -cf 0x29 prints nothing: XPC events have no decoder. --xpc selects them by id instead.
    assert _events("-cf", "0x29") == []
    assert _events("--xpc")


def test_events_finds_names_by_text() -> None:
    assert _events("dlsym") == ["DBG_DYLD_TIMING_DLSYM"]
    assert _events("--xpc", "send_message") == [
        "XPC_connection_send_message",
        "XPC_connection_send_message_with_reply",
        "XPC_connection_send_message_with_reply_sync",
    ]


@pytest.mark.parametrize(
    ("args", "options"),
    [
        (["--bsc"], {"bsc": True}),
        (["--fs", "--io"], {"fs": True, "io": True}),
        (["--mach", "-s", "open"], {"mach": True, "syscalls": ["open"]}),
        (["--dyld", "--xpc"], {"dyld": True, "xpc": True}),
        (["-e", "DBG_DYLD_TIMING_DLSYM", "--runloop"], {"events": ["DBG_DYLD_TIMING_DLSYM"], "runloop": True}),
        (["-sf", "0x0301"], {"subclass_filters": [0x0301]}),
    ],
)
def test_events_lists_what_parse_live_prints(monkeypatch: pytest.MonkeyPatch, args: list[str], options: Any) -> None:
    _filters, parser = _run_parse_live(monkeypatch, **options)

    # What parse-live's parser prints: the events it asks for by id, and the decoded events of its classes and
    # subclasses.
    parsed = core_profile_session._parsed_events()
    printed = sorted({
        name
        for eventid, name in default_trace_codes().items()
        if eventid in parser.filter_eventid
        or ((eventid >> 24 in parser.filter_class or eventid >> 16 in parser.filter_subclass) and name in parsed)
    })
    assert _events(*args) == printed


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
