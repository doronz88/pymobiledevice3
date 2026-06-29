import json
import re
from datetime import datetime
from io import StringIO
from uuid import UUID

import pytest

from pymobiledevice3.cli import syslog as syslog_module
from pymobiledevice3.services.os_trace import (
    OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT,
    OsActivityStreamFlag,
    SyslogEntry,
    SyslogLabel,
    SyslogLogLevel,
)

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = object()


class _FakeOsTraceService:
    last_pid = None
    last_stream_flags = None

    def __init__(self, entries):
        self._entries = entries

    async def syslog(self, pid=-1, stream_flags=OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT, **_kwargs):
        type(self).last_pid = pid
        type(self).last_stream_flags = stream_flags
        for entry in self._entries:
            yield entry


def _create_syslog_entry(message: str) -> SyslogEntry:
    return SyslogEntry(
        pid=123,
        timestamp=datetime(2024, 1, 1, 0, 0, 0),
        level=SyslogLogLevel.INFO,
        image_name="/usr/libexec/test-process",
        image_offset=0,
        filename="/usr/libexec/test-process",
        message=message,
    )


def _create_syslog_entry_with_level(message: str, level: SyslogLogLevel) -> SyslogEntry:
    entry = _create_syslog_entry(message)
    entry.level = level
    return entry


def _create_syslog_entries(messages: list[str]) -> list[SyslogEntry]:
    return [_create_syslog_entry(message) for message in messages]


async def _run_syslog_live(
    monkeypatch, capsys, entries: list[SyslogEntry], **syslog_live_kwargs
) -> tuple[list[str], str]:
    monkeypatch.setattr(syslog_module, "OsTraceService", lambda lockdown: _FakeOsTraceService(entries))
    monkeypatch.setattr(syslog_module, "user_requested_colored_output", lambda: False)

    out = syslog_live_kwargs.pop("out", None)
    kwargs = {
        "pid": -1,
        "process_name": None,
        "match": [],
        "invert_match": [],
        "match_insensitive": [],
        "invert_match_insensitive": [],
        "include_label": False,
        "regex": [],
        "insensitive_regex": [],
        "no_debug": False,
        "no_info": False,
    }
    kwargs.update(syslog_live_kwargs)

    await syslog_module.syslog_live(
        service_provider=_FAKE_SERVICE_PROVIDER,
        out=out,
        **kwargs,
    )

    printed_lines = capsys.readouterr().out.strip().splitlines()
    return printed_lines, "" if out is None else out.getvalue()


@pytest.mark.parametrize(
    ("invert_match", "invert_match_insensitive", "expected"),
    [
        ([], [], False),
        (["match"], [], True),
        (["MobileSafari"], [], True),
        (["dont"], [], False),
        ([], ["MaTCh"], True),
        ([], ["mobilesafari"], True),
        ([], ["missing"], False),
        (["match"], ["missing"], True),
        (["dont"], ["MaTCh"], True),
        (["dont"], ["missing"], False),
        (["match", "dont"], [], True),
        ([], ["missing", "MaTCh"], True),
        (["dont", "missing"], ["absent"], False),
    ],
)
def test_should_skip_line(invert_match: list[str], invert_match_insensitive: list[str], expected: bool) -> None:
    assert (
        syslog_module._should_skip_line(
            "MobileSafari match",
            invert_match,
            invert_match_insensitive,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("match", "match_insensitive", "match_regex", "expected"),
    [
        ([], [], [], True),
        (["match"], [], [], True),
        (["MobileSafari"], [], [], True),
        (["missing"], [], [], False),
        (["MobileSafari", "match"], [], [], True),
        (["MobileSafari", "missing"], [], [], False),
        ([], ["mobilesafari"], [], True),
        ([], ["match"], [], True),
        ([], ["missing"], [], False),
        ([], ["mobilesafari", "match"], [], True),
        ([], ["mobilesafari", "missing"], [], False),
        (["match"], ["mobilesafari"], [], True),
        (["MobileSafari"], ["match"], [], True),
        (["match"], ["missing"], [], False),
        (["missing"], ["mobilesafari"], [], False),
        (["MobileSafari", "match"], ["mobilesafari", "match"], [], True),
        (["MobileSafari", "match"], ["mobilesafari", "missing"], [], False),
        ([], [], [syslog_module.re.compile(r".*(match).*")], True),
        ([], [], [syslog_module.re.compile(r".*(missing).*")], False),
        ([], [], [syslog_module.re.compile(r".*(match).*"), syslog_module.re.compile(r".*(missing).*")], True),
        (["match"], [], [syslog_module.re.compile(r".*(MobileSafari).*")], True),
        (["match"], [], [syslog_module.re.compile(r".*(missing).*")], False),
        ([], ["mobilesafari"], [syslog_module.re.compile(r".*(match).*")], True),
        ([], ["mobilesafari"], [syslog_module.re.compile(r".*(missing).*")], False),
    ],
)
def test_should_keep_line(
    match: list[str], match_insensitive: list[str], match_regex: list[re.Pattern[str]], expected: bool
) -> None:
    assert (
        syslog_module._should_keep_line(
            "MobileSafari match",
            match,
            match_insensitive,
            match_regex,
        )
        == expected
    )


@pytest.mark.asyncio
async def test_syslog_live_invert_match(monkeypatch, capsys):
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        _create_syslog_entries(["keep this line", "skip this line"]),
        invert_match=["skip"],
    )
    assert len(printed_lines) == 1
    assert printed_lines[0].endswith("keep this line")


@pytest.mark.asyncio
async def test_syslog_live_match(monkeypatch, capsys):
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        _create_syslog_entries(["daemon ready", "daemon error", "worker ready"]),
        match=["daemon"],
        invert_match=["error"],
    )
    assert len(printed_lines) == 1
    assert printed_lines[0].endswith("daemon ready")


@pytest.mark.asyncio
async def test_syslog_live_invert_match_uses_disjunction_for_repeated_values(monkeypatch, capsys):
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        _create_syslog_entries(["daemon ready", "daemon ready error", "worker error"]),
        invert_match=["daemon", "error"],
    )
    assert len(printed_lines) == 0


@pytest.mark.asyncio
async def test_syslog_live_match_insensitive(monkeypatch, capsys):
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        _create_syslog_entries(["MobileSafari ready", "backboardd ready", "Worker READY"]),
        match_insensitive=["mobilesafari"],
        invert_match_insensitive=["ready"],
    )
    assert len(printed_lines) == 0


@pytest.mark.asyncio
async def test_syslog_live_process_name_and_start_after_filter_output(monkeypatch, capsys):
    entries = [
        _create_syslog_entry("warmup"),
        SyslogEntry(
            pid=123,
            timestamp=datetime(2024, 1, 1, 0, 0, 1),
            level=SyslogLogLevel.INFO,
            image_name="/usr/libexec/other-process",
            image_offset=0,
            filename="/usr/libexec/other-process",
            message="START now",
        ),
        _create_syslog_entry("before START"),
        _create_syslog_entry("START now"),
        _create_syslog_entry("after start"),
    ]

    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        entries,
        process_name="test-process",
        start_after="START",
    )
    assert len(printed_lines) == 4
    assert printed_lines[0] == 'Waiting for "START" ...'
    assert printed_lines[1].endswith("before START")
    assert printed_lines[2].endswith("START now")
    assert printed_lines[3].endswith("after start")


@pytest.mark.asyncio
async def test_syslog_live_regex_filters_and_writes_plain_output_to_out(monkeypatch, capsys):
    entries = [
        _create_syslog_entry("daemon ready"),
        _create_syslog_entry("worker ready"),
        _create_syslog_entry("springboard ready"),
    ]
    out = StringIO()

    printed_lines, out_value = await _run_syslog_live(
        monkeypatch,
        capsys,
        entries,
        out=out,
        regex=["daemon", "worker"],
    )
    out_lines = out_value.strip().splitlines()
    assert len(printed_lines) == 2
    assert len(out_lines) == 2
    assert printed_lines[0].endswith("daemon ready")
    assert printed_lines[1].endswith("worker ready")
    assert out_lines == printed_lines


@pytest.mark.asyncio
async def test_syslog_live_no_debug_suppresses_only_debug(monkeypatch, capsys):
    entries = [
        _create_syslog_entry_with_level("info line", SyslogLogLevel.INFO),
        _create_syslog_entry_with_level("debug line", SyslogLogLevel.DEBUG),
        _create_syslog_entry_with_level("notice line", SyslogLogLevel.NOTICE),
        _create_syslog_entry_with_level("error line", SyslogLogLevel.ERROR),
    ]

    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        entries,
        no_debug=True,
    )

    assert len(printed_lines) == 3
    assert printed_lines[0].endswith("info line")
    assert printed_lines[1].endswith("notice line")
    assert printed_lines[2].endswith("error line")
    assert _FakeOsTraceService.last_stream_flags == (OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT & ~OsActivityStreamFlag.DEBUG)


@pytest.mark.asyncio
async def test_syslog_live_no_info_suppresses_only_info(monkeypatch, capsys):
    entries = [
        _create_syslog_entry_with_level("info line", SyslogLogLevel.INFO),
        _create_syslog_entry_with_level("debug line", SyslogLogLevel.DEBUG),
        _create_syslog_entry_with_level("notice line", SyslogLogLevel.NOTICE),
    ]

    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        entries,
        no_info=True,
    )

    assert len(printed_lines) == 2
    assert printed_lines[0].endswith("debug line")
    assert printed_lines[1].endswith("notice line")
    assert _FakeOsTraceService.last_stream_flags == (OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT & ~OsActivityStreamFlag.INFO)


def test_format_json_line_with_label():
    entry = SyslogEntry(
        pid=42,
        timestamp=datetime(2026, 4, 18, 10, 15, 32, 123456),
        level=SyslogLogLevel.ERROR,
        image_name="/p/App",
        image_offset=16,
        filename="/p/App",
        message="hello",
        label=SyslogLabel(subsystem="com.foo.bar", category="cat"),
        procid=42,
        thread_id=4321,
        image_uuid=UUID("016e54e1-6f01-3644-941d-5073a6134a7b"),
        process_image_uuid=UUID("7870bc32-030d-3497-80eb-d80b2de7dfaf"),
        mach_timestamp=135126255336423432,
    )
    obj = json.loads(syslog_module.format_json_line(entry))
    assert obj == {
        "pid": 42,
        "procid": 42,
        "thread_id": 4321,
        "timestamp": "2026-04-18T10:15:32.123456",
        "level": "ERROR",
        "image_name": "/p/App",
        "image_offset": 16,
        "image_uuid": "016e54e1-6f01-3644-941d-5073a6134a7b",
        "process_image_uuid": "7870bc32-030d-3497-80eb-d80b2de7dfaf",
        "filename": "/p/App",
        "mach_timestamp": 135126255336423432,
        "message": "hello",
        "label": {"subsystem": "com.foo.bar", "category": "cat"},
    }


def test_format_json_line_handles_null_label():
    entry = _create_syslog_entry("plain")  # no label
    obj = json.loads(syslog_module.format_json_line(entry))
    assert obj["label"] is None
    assert obj["message"] == "plain"


def test_format_json_line_preserves_unicode():
    entry = _create_syslog_entry("hello 🚀 мир")
    raw = syslog_module.format_json_line(entry)
    assert "🚀" in raw  # ensure_ascii=False keeps raw unicode
    assert json.loads(raw)["message"] == "hello 🚀 мир"


@pytest.mark.asyncio
async def test_syslog_live_json_emits_valid_ndjson(monkeypatch, capsys):
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        _create_syslog_entries(["hello", "world"]),
        output_format=syslog_module.SyslogFormat.JSON,
    )
    assert len(printed_lines) == 2
    parsed = [json.loads(line) for line in printed_lines]
    assert [p["message"] for p in parsed] == ["hello", "world"]
    assert all(p["level"] == "INFO" for p in parsed)
    assert all(p["pid"] == 123 for p in parsed)


@pytest.mark.asyncio
async def test_syslog_live_json_ignores_text_filters(monkeypatch, capsys):
    # Every text-mode filter flag must be ignored in JSON mode.
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        _create_syslog_entries(["keep this", "skip this"]),
        output_format=syslog_module.SyslogFormat.JSON,
        match=["keep"],
        invert_match=["skip"],
        match_insensitive=["KEEP"],
        invert_match_insensitive=["SKIP"],
        regex=["keep"],
        insensitive_regex=["KEEP"],
        start_after="never-appears",
        include_label=True,
        image_offset=True,
    )
    # All entries emitted; none are filtered out.
    assert len(printed_lines) == 2
    messages = [json.loads(line)["message"] for line in printed_lines]
    assert messages == ["keep this", "skip this"]


@pytest.mark.asyncio
async def test_syslog_live_json_applies_process_name_filter(monkeypatch, capsys):
    entries = [
        _create_syslog_entry("from test-process"),
        SyslogEntry(
            pid=456,
            timestamp=datetime(2024, 1, 1, 0, 0, 1),
            level=SyslogLogLevel.INFO,
            image_name="/usr/libexec/other",
            image_offset=0,
            filename="/usr/libexec/other",
            message="from other",
        ),
    ]
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        entries,
        output_format=syslog_module.SyslogFormat.JSON,
        process_name="test-process",
    )
    assert len(printed_lines) == 1
    assert json.loads(printed_lines[0])["message"] == "from test-process"


@pytest.mark.asyncio
async def test_syslog_live_json_applies_pid_filter(monkeypatch, capsys):
    entries = [
        _create_syslog_entry("pid 123"),  # default pid is 123
        SyslogEntry(
            pid=999,
            timestamp=datetime(2024, 1, 1, 0, 0, 1),
            level=SyslogLogLevel.INFO,
            image_name="/usr/libexec/test-process",
            image_offset=0,
            filename="/usr/libexec/test-process",
            message="pid 999",
        ),
    ]
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        entries,
        output_format=syslog_module.SyslogFormat.JSON,
        pid=999,
    )
    assert len(printed_lines) == 1
    assert json.loads(printed_lines[0])["pid"] == 999


@pytest.mark.asyncio
async def test_syslog_live_json_tees_to_out(monkeypatch, capsys):
    out = StringIO()
    printed_lines, out_value = await _run_syslog_live(
        monkeypatch,
        capsys,
        _create_syslog_entries(["one", "two"]),
        output_format=syslog_module.SyslogFormat.JSON,
        out=out,
    )
    out_lines = out_value.strip().splitlines()
    assert out_lines == printed_lines  # same NDJSON to both stdout and file
    assert [json.loads(line)["message"] for line in out_lines] == ["one", "two"]


@pytest.mark.asyncio
async def test_syslog_live_json_suppresses_start_after_banner(monkeypatch, capsys):
    # In text mode, `--start-after` prints a "Waiting for..." banner to stdout.
    # That would corrupt NDJSON; JSON mode must suppress it.
    printed_lines, _ = await _run_syslog_live(
        monkeypatch,
        capsys,
        _create_syslog_entries(["one"]),
        output_format=syslog_module.SyslogFormat.JSON,
        start_after="anything",
    )
    assert len(printed_lines) == 1
    # The single line must parse as valid JSON — no banner contamination.
    assert json.loads(printed_lines[0])["message"] == "one"
