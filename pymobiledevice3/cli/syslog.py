import logging
import os
import posixpath
import re
from contextlib import nullcontext
from pathlib import Path
from typing import Annotated, Optional, TextIO

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    ServiceProviderDep,
    get_last_used_terminal_formatting,
    user_requested_colored_output,
)
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.os_trace import OsTraceService, SyslogEntry, SyslogLogLevel
from pymobiledevice3.services.syslog import SyslogService

logger = logging.getLogger(__name__)

cli = InjectingTyper(
    name="syslog",
    help="Watch syslog messages",
    no_args_is_help=True,
)


@cli.command("live-old")
def syslog_live_old(service_provider: ServiceProviderDep) -> None:
    """view live syslog lines in raw bytes form from old relay"""
    for line in SyslogService(service_provider=service_provider).watch():
        print(line)


def format_line(
    color: bool, pid: int, syslog_entry: SyslogEntry, include_label: bool, image_offset: bool = False
) -> Optional[str]:
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

    if (pid != -1) and (syslog_pid != pid):
        return None

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


def syslog_live(
    service_provider: LockdownServiceProvider,
    out: Optional[TextIO],
    pid: int,
    process_name: Optional[str],
    match: list[str],
    match_insensitive: list[str],
    include_label: bool,
    regex: list[str],
    insensitive_regex: list[str],
    image_offset: bool = False,
) -> None:
    match_regex = [re.compile(f".*({r}).*", re.DOTALL) for r in regex]
    match_regex += [re.compile(f".*({r}).*", re.IGNORECASE | re.DOTALL) for r in insensitive_regex]

    def replace(m):
        if len(m.groups()) and line:
            return line.replace(m.group(1), typer.style(m.group(1), bold=True, underline=True))
        return ""

    for syslog_entry in OsTraceService(lockdown=service_provider).syslog(pid=pid):
        if process_name and posixpath.basename(syslog_entry.filename) != process_name:
            continue

        line_no_style = format_line(False, pid, syslog_entry, include_label, image_offset)
        line = format_line(user_requested_colored_output(), pid, syslog_entry, include_label, image_offset)

        if line_no_style is None or line is None:
            continue

        skip = False

        if match is not None:
            for m in match:
                match_line = line
                if m not in match_line:
                    skip = True
                    break
                else:
                    if user_requested_colored_output():
                        match_line = match_line.replace(m, typer.style(m, bold=True, underline=True))
                        line = match_line

        if match_insensitive is not None:
            for m in match_insensitive:
                m = m.lower()
                if m not in line.lower():
                    skip = True
                    break
                else:
                    if user_requested_colored_output():
                        start = line.lower().index(m)
                        end = start + len(m)
                        last_color_formatting = get_last_used_terminal_formatting(line[:start])
                        line = (
                            line[:start]
                            + typer.style(line[start:end], bold=True, underline=True)
                            + last_color_formatting
                            + line[end:]
                        )

        if match_regex:
            skip = True
            for r in match_regex:
                if not r.findall(line_no_style):
                    continue
                line = re.sub(r, replace, line)
                skip = False

        if skip:
            continue

        print(line, flush=True)

        if out:
            if user_requested_colored_output():
                print(line, file=out, flush=True)
            else:
                print(line_no_style, file=out, flush=True)


@cli.command("live")
def cli_syslog_live(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Optional[Path],
        typer.Option(
            "--out",
            "-o",
            help="log file",
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
            help="match expression",
        ),
    ] = None,
    match_insensitive: Annotated[
        Optional[list[str]],
        typer.Option(
            "--match-insensitive",
            "-mi",
            help="case-insensitive match expression",
        ),
    ] = None,
    include_label: Annotated[
        bool,
        typer.Option(
            "--label",
            help="should include label",
        ),
    ] = False,
    regex: Annotated[
        Optional[list[str]],
        typer.Option(
            "--regex",
            "-e",
            help="filter only lines matching given regex",
        ),
    ] = None,
    insensitive_regex: Annotated[
        Optional[list[str]],
        typer.Option(
            "--insensitive-regex",
            "-ei",
            help="filter only lines matching given regex (insensitive)",
        ),
    ] = None,
    image_offset: Annotated[
        bool,
        typer.Option(
            "--image-offset",
            "-io",
            help="Include image offset in log line",
        ),
    ] = False,
) -> None:
    """view live syslog lines"""

    with out.open("wt") if out else nullcontext() as out_file:
        syslog_live(
            service_provider,
            out_file,
            pid,
            process_name,
            match or [],
            match_insensitive or [],
            include_label,
            regex or [],
            insensitive_regex or [],
        )


@cli.command("collect")
def syslog_collect(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(
            exists=False,
            dir_okay=True,
            file_okay=False,
        ),
    ],
    size_limit: int,
    age_limit: int,
    start_time: int,
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

    OsTraceService(lockdown=service_provider).collect(
        str(out), size_limit=size_limit, age_limit=age_limit, start_time=start_time
    )
