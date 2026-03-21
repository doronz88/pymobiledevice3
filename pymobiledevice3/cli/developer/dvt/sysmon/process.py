import asyncio
import contextlib
import json
import re
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional, TextIO

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    ServiceProviderDep,
    async_command,
    default_json_encoder,
    print_json,
    prompt_selection,
)
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap

cli = InjectingTyper(
    name="process",
    help="Process monitor options.",
    no_args_is_help=True,
)

monitor_cli = InjectingTyper(
    name="monitor",
    help="Continuously stream process metrics.",
    no_args_is_help=True,
)
cli.add_typer(monitor_cli)

_BYTE_FIELDS = {
    "anonMemoryUsage",
    "diskBytesRead",
    "diskBytesWritten",
    "memAnon",
    "memCompressed",
    "memResidentSize",
    "memVirtualSize",
    "physFootprint",
    "purgeableMemory",
    "wiredMemory",
}

_PROCESS_FILTER_PATTERN = re.compile(r"(?P<key>[^=]+)=(?P<value>.*)")


class ProcessSelectionMode(str, Enum):
    PROMPT = "prompt"
    FIRST = "first"
    LAST = "last"


def _parse_process_filters(filter_expressions: Optional[list[str]]) -> dict[str, list[str]]:
    parsed_filters: dict[str, list[str]] = {}
    if filter_expressions:
        for raw in filter_expressions:
            match = _PROCESS_FILTER_PATTERN.fullmatch(raw)
            if match is None:
                raise typer.BadParameter(f'Invalid filter "{raw}". Expected key=value.')
            key = match.group("key")
            value = match.group("value")
            parsed_filters.setdefault(key, []).append(value)
    return parsed_filters


def _validate_process_keys(process: dict, keys: list[str]) -> None:
    unknown_keys = [key for key in keys if key not in process]
    if unknown_keys:
        raise typer.BadParameter(
            f"The process does not have the following keys: {unknown_keys}. Possible keys={list(process.keys())}"
        )


def _matches_filters(proc: dict, parsed_filters: dict[str, list[str]]) -> bool:
    if len(parsed_filters) == 0:
        return True
    return all(str(proc.get(key)) in values for key, values in parsed_filters.items())


def _select_process_output_keys(process: dict, output_keys: Optional[list[str]]) -> dict:
    if not output_keys:
        return process

    _validate_process_keys(process, output_keys)
    return {key: process[key] for key in output_keys}


def _format_byte_count(value: int) -> str:
    suffixes = ("B", "KB", "MB", "GB", "TB", "PB")
    size = float(value)
    suffix_index = 0
    while size >= 1024 and suffix_index < len(suffixes) - 1:
        size /= 1024
        suffix_index += 1
    if suffix_index == 0:
        return f"{int(size)}{suffixes[suffix_index]}"
    return f"{size:.1f}{suffixes[suffix_index]}" if size < 10 else f"{size:.0f}{suffixes[suffix_index]}"


def _humanize_process_values(process: dict) -> dict:
    humanized = dict(process)
    for key, value in humanized.items():
        if key in _BYTE_FIELDS and isinstance(value, int):
            humanized[key] = _format_byte_count(value)
    return humanized


def _serialize_process(process: dict, keys: Optional[list[str]] = None, human: bool = False) -> dict:
    selected = dict(_select_process_output_keys(process, keys))
    if human:
        selected = _humanize_process_values(selected)
    selected["timestamp"] = datetime.now(timezone.utc).isoformat()
    return selected


def _write_process(out: Optional[TextIO], process: dict) -> None:
    if out is None:
        print_json(process)
        return

    json_output = json.dumps(process, default=default_json_encoder)
    out.write(json_output + "\n")
    out.flush()


def _write_json(out: Optional[TextIO], value) -> None:
    if out is None:
        print_json(value)
        return

    out.write(json.dumps(value, sort_keys=True, indent=4, default=default_json_encoder) + "\n")
    out.flush()


def _write_status(line: str) -> None:
    print(line, flush=True)


def _describe_process(process: dict) -> str:
    name = process.get("name") or process.get("comm") or "<unknown>"
    pid = process.get("pid")
    ppid = process.get("ppid")
    return f"pid={pid}, ppid={ppid}, name={name}"


def _describe_processes(processes: list[dict]) -> str:
    return "; ".join(_describe_process(process) for process in processes)


def _duration_elapsed(start_time: float, duration_ms: Optional[int]) -> bool:
    if duration_ms is None:
        return False
    return ((asyncio.get_running_loop().time() - start_time) * 1000) >= duration_ms


async def iter_initialized_processes(sysmon: Sysmontap):
    sample_index = 0
    async for process_snapshot in sysmon.iter_processes():
        sample_index += 1
        # The first sample does not contain initialized cpuUsage values.
        if sample_index < 2:
            continue
        yield process_snapshot


def _process_sort_key(process: dict) -> tuple:
    # Sort from oldest to newest process. "first" picks the oldest match and "last" picks the newest match.
    start_abs_time = process.get("startAbsTime")
    if not isinstance(start_abs_time, int):
        start_abs_time = -1
    pid = process.get("pid")
    if not isinstance(pid, int):
        pid = -1
    name = process.get("name") or process.get("comm") or ""
    return start_abs_time, pid, str(name)


def _select_process_from_candidates(processes: list[dict], selection_mode: ProcessSelectionMode) -> dict:
    if len(processes) == 1:
        return processes[0]

    sorted_processes = sorted(processes, key=_process_sort_key)

    if selection_mode == ProcessSelectionMode.FIRST:
        return sorted_processes[0]
    if selection_mode == ProcessSelectionMode.LAST:
        return sorted_processes[-1]

    if not sys.stdin.isatty():
        raise typer.BadParameter(
            f'Multiple processes matched the given filters. Re-run with "--choose first", "--choose last", or refine the filters. '
            f"Matches: {_describe_processes(processes)}"
        )

    selection_index = prompt_selection(
        [_describe_process(process) for process in sorted_processes],
        "Choose process to monitor",
        idx=True,
    )
    return sorted_processes[selection_index]


def _get_process_identifier(process: dict) -> tuple[str, object]:
    if process.get("uniqueID") is not None:
        return "uniqueID", process["uniqueID"]
    if process.get("startAbsTime") is not None:
        return "startAbsTime", process["startAbsTime"]
    return "pid", process["pid"]


def _matches_selected_process(process: dict, selected_process_identifier: tuple[str, object]) -> bool:
    identifier_key, identifier_value = selected_process_identifier
    return process.get(identifier_key) == identifier_value


def _select_process_from_snapshot(
    process_snapshot: list[dict],
    parsed_filters: dict[str, list[str]],
    selection_mode: ProcessSelectionMode,
) -> dict:
    if process_snapshot:
        # All process entries in a sysmon sample share the same schema, so validating one entry is sufficient.
        _validate_process_keys(process_snapshot[0], list(parsed_filters))

    matching_processes = [process for process in process_snapshot if _matches_filters(process, parsed_filters)]
    if len(matching_processes) == 0:
        raise typer.BadParameter(f"Failed to find a process matching the given filters in the current snapshot")

    return _select_process_from_candidates(matching_processes, selection_mode)


async def _select_process_from_sysmon(
    dvt, parsed_filters: dict[str, list[str]], keys: Optional[list[str]], selection_mode: ProcessSelectionMode
) -> dict:
    async with await Sysmontap.create(dvt) as selection_sysmon:
        async for process_snapshot in iter_initialized_processes(selection_sysmon):
            # All process entries in a sysmon sample share the same schema, so validating one entry is sufficient.
            _validate_process_keys(process_snapshot[0], keys or [])
            return _select_process_from_snapshot(process_snapshot, parsed_filters, selection_mode)

    raise typer.BadParameter("Failed to collect a process snapshot")


@cli.command("single")
@async_command
async def sysmon_process_single(
    service_provider: ServiceProviderDep,
    filter_expressions: Annotated[
        Optional[list[str]],
        typer.Option(
            "--filter",
            "-f",
            help="filter processes by key=value. Can be specified multiple times.",
        ),
    ] = None,
    keys: Annotated[
        Optional[list[str]],
        typer.Option(
            "--key",
            "-k",
            help="show only selected process keys for each emitted record. Can be specified multiple times.",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="output file path for JSON format (optional, defaults to stdout)",
        ),
    ] = None,
    human: Annotated[
        bool,
        typer.Option(
            "--human",
            help="format known byte-count fields such as physFootprint using human-readable units.",
        ),
    ] = False,
) -> None:
    """show a single snapshot of currently running processes."""
    with contextlib.ExitStack() as stack:
        out = stack.enter_context(open(output, "w")) if output else None
        await sysmon_process_single_task(service_provider, filter_expressions, keys, human, out)


async def sysmon_process_single_task(
    service_provider: ServiceProviderDep,
    filter_expressions: Optional[list[str]] = None,
    keys: Optional[list[str]] = None,
    human: bool = False,
    out: Optional[TextIO] = None,
) -> None:
    parsed_filters = _parse_process_filters(filter_expressions)
    result = []
    async with (
        DvtProvider(service_provider) as dvt,
        DeviceInfo(dvt) as device_info,
        await Sysmontap.create(dvt) as sysmon,
    ):
        async for process_snapshot in iter_initialized_processes(sysmon):
            if process_snapshot and parsed_filters:
                # All process entries in a sysmon sample share the same schema, so validating one entry is sufficient.
                _validate_process_keys(process_snapshot[0], list(parsed_filters))

            for process in process_snapshot:
                if not _matches_filters(process, parsed_filters):
                    continue

                process = dict(process)
                process["execName"] = await device_info.execname_for_pid(process["pid"])
                result.append(_serialize_process(process, keys, human))

            break

    if len(result) == 0:
        if parsed_filters:
            raise typer.BadParameter("Failed to find a process matching the given filters in the current snapshot")
        raise typer.BadParameter("Failed to find any processes in the current snapshot")

    _write_json(out, result)


@monitor_cli.command("threshold")
@async_command
async def sysmon_process_monitor_threshold(
    service_provider: ServiceProviderDep,
    threshold: Annotated[float, typer.Argument(help="minimum cpuUsage value to emit")],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="output file path for JSONL format (optional, defaults to stdout)",
        ),
    ] = None,
    duration: Annotated[
        Optional[int],
        typer.Option(
            "--duration",
            "-d",
            help="maximum duration in milliseconds to run monitoring (optional)",
        ),
    ] = None,
    keys: Annotated[
        Optional[list[str]],
        typer.Option(
            "--key",
            "-k",
            help="show only selected process keys for each emitted record. Can be specified multiple times.",
        ),
    ] = None,
    human: Annotated[
        bool,
        typer.Option(
            "--human",
            help="format known byte-count fields such as physFootprint using human-readable units.",
        ),
    ] = False,
) -> None:
    """Continuously monitor processes above a cpuUsage threshold."""

    with contextlib.ExitStack() as stack:
        out = stack.enter_context(open(output, "w")) if output else None
        await sysmon_process_monitor_threshold_task(service_provider, threshold, duration, keys, human, out)


@monitor_cli.command("process")
@async_command
async def sysmon_process_monitor_process(
    service_provider: ServiceProviderDep,
    filter_expressions: Annotated[
        Optional[list[str]],
        typer.Option(
            "--filter",
            "-f",
            help="filter processes by key=value. Can be specified multiple times.",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output file path for JSONL format (optional, defaults to stdout)",
        ),
    ] = None,
    interval: Annotated[
        int,
        typer.Option(
            "--interval",
            "-i",
            help="Minimum interval in milliseconds between outputs (optional)",
        ),
    ] = Sysmontap.DEFAULT_INTERVAL,
    duration: Annotated[
        Optional[int],
        typer.Option(
            "--duration",
            "-d",
            help="Maximum duration in milliseconds to run monitoring (optional)",
        ),
    ] = None,
    choose: Annotated[
        ProcessSelectionMode,
        typer.Option(
            "--choose",
            help=(
                'how to resolve multiple matching processes: "prompt" asks interactively; '
                '"first" selects the oldest matching process; "last" selects the newest matching process. '
                "Automatic ordering is by startAbsTime, then pid, then name."
            ),
        ),
    ] = ProcessSelectionMode.PROMPT,
    keys: Annotated[
        Optional[list[str]],
        typer.Option(
            "--key",
            "-k",
            help="Show only selected process keys for each emitted record. Can be specified multiple times.",
        ),
    ] = None,
    human: Annotated[
        bool,
        typer.Option(
            "--human",
            help="Format known byte-count fields such as physFootprint using human-readable units.",
        ),
    ] = False,
) -> None:
    """Continuously monitor one process selected from the current snapshot by key=value filters."""

    with contextlib.ExitStack() as stack:
        out = stack.enter_context(open(output, "w")) if output else None
        await sysmon_process_monitor_process_task(
            service_provider, filter_expressions, interval, duration, choose, keys, human, out
        )


async def sysmon_process_monitor_threshold_task(
    service_provider: ServiceProviderDep,
    threshold: float,
    duration: Optional[int] = None,
    keys: Optional[list[str]] = None,
    human: bool = False,
    out: Optional[TextIO] = None,
) -> None:
    """Continuously monitor processes above a cpuUsage threshold."""

    start_time = None

    async with DvtProvider(service_provider) as dvt, await Sysmontap.create(dvt) as sysmon:
        async for process_snapshot in iter_initialized_processes(sysmon):
            if start_time is None:
                start_time = asyncio.get_running_loop().time()

            if _duration_elapsed(start_time, duration):
                break

            if process_snapshot:
                # All process entries in a sysmon sample share the same schema, so validating one entry is sufficient.
                _validate_process_keys(process_snapshot[0], keys or [])

            for process in process_snapshot:
                if process.get("cpuUsage") is None or process["cpuUsage"] < threshold:
                    continue

                _write_process(out, _serialize_process(process, keys, human))

            if _duration_elapsed(start_time, duration):
                # Avoid waiting for the next snapshot
                break


async def sysmon_process_monitor_process_task(
    service_provider: ServiceProviderDep,
    filter_expressions: Optional[list[str]] = None,
    interval: int = Sysmontap.DEFAULT_INTERVAL,
    duration: Optional[int] = None,
    choose: ProcessSelectionMode = ProcessSelectionMode.PROMPT,
    keys: Optional[list[str]] = None,
    human: bool = False,
    out: Optional[TextIO] = None,
) -> None:
    """Continuously monitor one process selected from the current snapshot by key=value filters."""

    parsed_filters = _parse_process_filters(filter_expressions)

    async with DvtProvider(service_provider) as dvt:
        selected_process = await _select_process_from_sysmon(dvt, parsed_filters, keys, choose)
        selected_process_identifier = _get_process_identifier(selected_process)
        selected_process_description = _describe_process(selected_process)

        _write_status(f"Monitoring {selected_process_description}")

        monitoring_start_time = None
        async with await Sysmontap.create(dvt, interval=interval) as monitor_sysmon:
            async for process_snapshot in iter_initialized_processes(monitor_sysmon):
                if monitoring_start_time is None:
                    monitoring_start_time = asyncio.get_running_loop().time()

                if _duration_elapsed(monitoring_start_time, duration):
                    break

                if len(process_snapshot) == 0:
                    continue

                # All process entries in a sysmon sample share the same schema, so validating one entry is sufficient.
                _validate_process_keys(process_snapshot[0], keys or [])

                selected_process_matches = [
                    process
                    for process in process_snapshot
                    if _matches_selected_process(process, selected_process_identifier)
                ]

                if len(selected_process_matches) == 0:
                    _write_status(f"Selected process exited: {selected_process_description}")
                    break

                if len(selected_process_matches) > 1:
                    matching_processes_description = [
                        _describe_process(process) for process in selected_process_matches
                    ]
                    raise typer.BadParameter(
                        f"Selected process identity is ambiguous for {selected_process_description!r}. "
                        f"Matching processes: {matching_processes_description}. Please refine the filters."
                    )

                _write_process(out, _serialize_process(selected_process_matches[0], keys, human))

                if _duration_elapsed(monitoring_start_time, duration):
                    # Avoid waiting for the next snapshot
                    break
