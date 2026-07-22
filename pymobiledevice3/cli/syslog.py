import json
import logging
import os
import posixpath
import re
from contextlib import nullcontext
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional, TextIO

import typer
from typer_injector import InjectingTyper
from typing_extensions import assert_never

from pymobiledevice3.cli.cli_common import (
    ServiceProviderDep,
    async_command,
    get_last_used_terminal_formatting,
    user_requested_colored_output,
)
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.os_trace import (
    OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT,
    OsActivityStreamFlag,
    OsTraceService,
    SyslogEntry,
    SyslogLogLevel,
)
from pymobiledevice3.services.syslog import SyslogService

logger = logging.getLogger(__name__)

cli = InjectingTyper(
    name="syslog",
    help="Watch syslog messages",
    no_args_is_help=True,
)


class SyslogFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


def format_json_line(syslog_entry: SyslogEntry) -> str:
    label: Optional[dict[str, str]] = None
    if syslog_entry.label is not None:
        label = {"subsystem": syslog_entry.label.subsystem, "category": syslog_entry.label.category}
    return json.dumps(
        {
            "pid": syslog_entry.pid,
            "procid": syslog_entry.procid,
            "thread_id": syslog_entry.thread_id,
            "timestamp": syslog_entry.timestamp.isoformat(),
            "level": syslog_entry.level.name,
            "image_name": syslog_entry.image_name,
            "image_offset": syslog_entry.image_offset,
            "image_uuid": str(syslog_entry.image_uuid) if syslog_entry.image_uuid else None,
            "process_image_uuid": str(syslog_entry.process_image_uuid) if syslog_entry.process_image_uuid else None,
            "filename": syslog_entry.filename,
            "mach_timestamp": syslog_entry.mach_timestamp,
            "message": syslog_entry.message,
            "label": label,
        },
        ensure_ascii=False,
    )


@cli.command("live-old")
@async_command
async def syslog_live_old(service_provider: ServiceProviderDep) -> None:
    """view live syslog lines in raw bytes form from old relay"""
    async with SyslogService(service_provider=service_provider) as service:
        async for line in service.watch():
            print(line)


def format_line(syslog_entry: SyslogEntry, *, include_label: bool, image_offset: bool, color: bool) -> str:
    log_level_colors = {
        SyslogLogLevel.NOTICE.name: "white",
        SyslogLogLevel.INFO.name: "white",
        SyslogLogLevel.DEBUG.name: "green",
        SyslogLogLevel.ERROR.name: "red",
        SyslogLogLevel.FAULT.name: "red",
        SyslogLogLevel.USER_ACTION.name: "white",
    }

    syslog_pid = syslog_entry.pid
    timestamp = syslog_entry.timestamp
    level = syslog_entry.level.name
    filename = syslog_entry.filename
    image_name = posixpath.basename(syslog_entry.image_name)
    message = syslog_entry.message
    process_name = posixpath.basename(filename)
    image_offset_str = f"+0x{syslog_entry.image_offset:x}" if image_offset and image_name else ""
    label = ""

    if syslog_entry.label is not None:
        label = f"[{syslog_entry.label.subsystem}][{syslog_entry.label.category}]"

    if color:
        timestamp = typer.style(str(timestamp), "green")
        process_name = typer.style(process_name, "magenta")
        if len(image_name) > 0:
            image_name = typer.style(image_name, "magenta")
        if image_offset:
            image_offset_str = typer.style(image_offset_str, "blue")
        syslog_pid = typer.style(syslog_pid, "cyan")
        log_level_color = log_level_colors[level]
        level = typer.style(level, log_level_color)
        label = typer.style(label, "cyan")
        message = typer.style(message, log_level_color)

    line_format = "{timestamp} {process_name}{{{image_name}{image_offset_str}}}[{pid}] <{level}>: {message}"

    if include_label:
        line_format += f" {label}"

    line = line_format.format(
        timestamp=timestamp,
        process_name=process_name,
        image_name=image_name,
        pid=syslog_pid,
        level=level,
        message=message,
        image_offset_str=image_offset_str,
    )

    return line


def _should_skip_line(line: str, invert_match: list[str], invert_match_insensitive: list[str]) -> bool:
    for m in invert_match:
        if m in line:
            return True

    line_lower = line.lower()
    return any(m.lower() in line_lower for m in invert_match_insensitive)


def _should_keep_line(
    line: str, match: list[str], match_insensitive: list[str], match_regex: list[re.Pattern[str]]
) -> bool:
    for m in match:
        if m not in line:
            return False

    line_lower = line.lower()
    if not all(m.lower() in line_lower for m in match_insensitive):
        return False

    if not match_regex:
        return True

    return any(regex.search(line) for regex in match_regex)


def _highlight_match_filters(styled_line: str, match: list[str], match_insensitive: list[str]) -> str:
    for m in match:
        styled_line = styled_line.replace(m, typer.style(m, bold=True, underline=True))

    for m in match_insensitive:
        m = m.lower()
        start = styled_line.lower().index(m)
        end = start + len(m)
        last_color_formatting = get_last_used_terminal_formatting(styled_line[:start])
        styled_line = (
            styled_line[:start]
            + typer.style(styled_line[start:end], bold=True, underline=True)
            + last_color_formatting
            + styled_line[end:]
        )

    return styled_line


def _highlight_regex_filters(styled_line: str, match_regex: list[re.Pattern[str]]) -> str:
    def replace(m):
        if len(m.groups()):
            return styled_line.replace(m.group(1), typer.style(m.group(1), bold=True, underline=True))
        return ""

    for regex in match_regex:
        if regex.search(styled_line):
            styled_line = re.sub(regex, replace, styled_line)

    return styled_line


def _emit_line(line: str, out: Optional[TextIO]) -> None:
    print(line, flush=True)
    if out:
        print(line, file=out, flush=True)


async def syslog_live(
    service_provider: LockdownServiceProvider,
    out: Optional[TextIO],
    pid: int,
    process_name: Optional[str],
    match: list[str],
    invert_match: list[str],
    match_insensitive: list[str],
    invert_match_insensitive: list[str],
    include_label: bool,
    regex: list[str],
    insensitive_regex: list[str],
    no_debug: bool = False,
    no_info: bool = False,
    image_offset: bool = False,
    start_after: Optional[str] = None,
    output_format: SyslogFormat = SyslogFormat.TEXT,
) -> None:
    match_regex = [re.compile(f".*({r}).*", re.DOTALL) for r in regex]
    match_regex += [re.compile(f".*({r}).*", re.IGNORECASE | re.DOTALL) for r in insensitive_regex]
    started = start_after is None

    if start_after is not None and output_format is SyslogFormat.TEXT:
        print(f'Waiting for "{start_after}" ...', flush=True)

    should_color_output = output_format is SyslogFormat.TEXT and user_requested_colored_output()
    stream_flags = OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT
    if no_debug:
        stream_flags &= ~OsActivityStreamFlag.DEBUG
    if no_info:
        stream_flags &= ~OsActivityStreamFlag.INFO

    async for syslog_entry in OsTraceService(lockdown=service_provider).syslog(pid=pid, stream_flags=stream_flags):
        if process_name and posixpath.basename(syslog_entry.filename) != process_name:
            continue

        if pid != -1 and syslog_entry.pid != pid:
            continue

        if no_debug and syslog_entry.level == SyslogLogLevel.DEBUG:
            continue

        if no_info and syslog_entry.level == SyslogLogLevel.INFO:
            # I don't really understand why INFO is retrieved when not requested, but this is imitating
            # Console.app behavior
            continue

        if output_format is SyslogFormat.JSON:
            json_line = format_json_line(syslog_entry)
            _emit_line(json_line, out)

        elif output_format is SyslogFormat.TEXT:
            line = format_line(
                syslog_entry,
                include_label=include_label,
                image_offset=image_offset,
                color=False,
            )

            if not started:
                assert start_after is not None  # started is initialized True when start_after is None
                if start_after not in line:
                    continue
                started = True

            if _should_skip_line(line, invert_match, invert_match_insensitive):
                continue

            if not _should_keep_line(line, match, match_insensitive, match_regex):
                continue

            if should_color_output:
                styled_line = format_line(
                    syslog_entry,
                    include_label=include_label,
                    image_offset=image_offset,
                    color=True,
                )
                styled_line = _highlight_match_filters(styled_line, match, match_insensitive)
                styled_line = _highlight_regex_filters(styled_line, match_regex)
            else:
                styled_line = line

            _emit_line(styled_line, out)

        else:
            assert_never(output_format)


@cli.command("live")
@async_command
async def cli_syslog_live(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Optional[Path],
        typer.Option(
            "--out",
            "-o",
            help="Save every log entry to this file. NOTE: stdout is not suppressed — entries are "
            "printed to both stdout and the file (tee-like). Redirect stdout with '>/dev/null' to keep "
            "only the file.",
        ),
    ] = None,
    pid: Annotated[
        int,
        typer.Option(help="pid to filter. -1 for all"),
    ] = -1,
    process_name: Annotated[
        Optional[str],
        typer.Option(
            "--process-name",
            "-pn",
            help="process name to filter",
        ),
    ] = None,
    match: Annotated[
        Optional[list[str]],
        typer.Option(
            "--match",
            "-m",
            help="filter only logs matching this expression "
            "(repeatable; all must match - conjunction). Text mode only.",
        ),
    ] = None,
    invert_match: Annotated[
        Optional[list[str]],
        typer.Option(
            "--invert-match",
            "-v",
            help="filter only logs not matching this expression "
            "(repeatable; any match excludes - disjunction). Text mode only.",
        ),
    ] = None,
    match_insensitive: Annotated[
        Optional[list[str]],
        typer.Option(
            "--match-insensitive",
            "-mi",
            help="filter only logs matching this expression, case-insensitively "
            "(repeatable; all must match - conjunction). Text mode only.",
        ),
    ] = None,
    invert_match_insensitive: Annotated[
        Optional[list[str]],
        typer.Option(
            "--invert-match-insensitive",
            "-vi",
            help="filter only logs not matching this expression, case-insensitively "
            "(repeatable; any match excludes - disjunction). Text mode only.",
        ),
    ] = None,
    include_label: Annotated[
        bool,
        typer.Option(
            "--label",
            help="should include label (text mode only; JSON always emits the label field).",
        ),
    ] = False,
    regex: Annotated[
        Optional[list[str]],
        typer.Option(
            "--regex",
            "-e",
            help="filter only lines matching given regex "
            "(repeatable; any match includes - disjunction). Text mode only.",
        ),
    ] = None,
    insensitive_regex: Annotated[
        Optional[list[str]],
        typer.Option(
            "--insensitive-regex",
            "-ei",
            help="filter only lines matching given regex, case-insensitively "
            "(repeatable; any match includes - disjunction). Text mode only.",
        ),
    ] = None,
    image_offset: Annotated[
        bool,
        typer.Option(
            "--image-offset",
            "-io",
            help="Include image offset in log line (text mode only; JSON always emits image_offset).",
        ),
    ] = False,
    no_debug: Annotated[
        bool,
        typer.Option(
            "--no-debug",
            help="Suppress DEBUG entries.",
        ),
    ] = False,
    no_info: Annotated[
        bool,
        typer.Option(
            "--no-info",
            help="Suppress INFO entries.",
        ),
    ] = False,
    start_after: Annotated[
        Optional[str],
        typer.Option(
            "--start-after",
            help="Start printing only after this string is seen. Text mode only.",
        ),
    ] = None,
    output_format: Annotated[
        SyslogFormat,
        typer.Option(
            "--format",
            help="Output format. 'json' emits one JSON per line (NDJSON); only --pid and --process-name "
            "apply, other filters are ignored.",
            case_sensitive=False,
        ),
    ] = SyslogFormat.TEXT,
) -> None:
    """view live syslog lines"""

    with out.open("wt") if out else nullcontext() as out_file:
        await syslog_live(
            service_provider,
            out_file,
            pid,
            process_name,
            match or [],
            invert_match or [],
            match_insensitive or [],
            invert_match_insensitive or [],
            include_label,
            regex or [],
            insensitive_regex or [],
            no_debug,
            no_info,
            image_offset,
            start_after,
            output_format,
        )


@cli.command("collect")
@async_command
async def syslog_collect(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(
            exists=False,
            dir_okay=True,
            file_okay=False,
        ),
    ],
    size_limit: Annotated[
        Optional[int],
        typer.Option(
            "--size-limit",
            help="Maximum size in bytes of logarchive",
        ),
    ] = None,
    age_limit: Annotated[
        Optional[int],
        typer.Option(
            "--age-limit",
            help="Maximum age in days",
        ),
    ] = None,
    start_time: Annotated[
        Optional[int],
        typer.Option(
            "--start-time",
            help="Start time of logarchive as a unix timestamp",
        ),
    ] = None,
) -> None:
    """
    Collect the system logs into a .logarchive that can be viewed later with tools such as log or Console.
    If the filename doesn't exist, system_logs.logarchive will be created in the given directory.
    """
    if not os.path.exists(out):
        os.makedirs(out)

    if out.suffix != ".logarchive":
        logger.warning(
            "given out path doesn't end with a .logarchive - consider renaming to be able to view "
            "the file with the likes of the Console.app and the `log show` utilities"
        )

    await OsTraceService(lockdown=service_provider).collect(
        str(out), size_limit=size_limit, age_limit=age_limit, start_time=start_time
    )
