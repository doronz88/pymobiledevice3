import asyncio
import contextlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, default_json_encoder, print_json
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


def _parse_attribute_filters(attributes: Optional[list[str]]) -> dict[str, list[str]]:
    parsed_filters: dict[str, list[str]] = {}
    if attributes:
        for raw in attributes:
            key, value = raw.split("=", 1)
            parsed_filters.setdefault(key, []).append(value)
    return parsed_filters


def _matches_filters(proc: dict, parsed_filters: dict[str, list[str]]) -> bool:
    if not parsed_filters:
        return True
    return all(str(proc.get(key)) in values for key, values in parsed_filters.items())


def _select_process_keys(process: dict, keys: Optional[list[str]]) -> dict:
    if not keys:
        return process

    missing_keys = [key for key in keys if key not in process]
    if missing_keys:
        raise typer.BadParameter(f"unknown process keys: {', '.join(sorted(missing_keys))}")

    return {key: process[key] for key in keys}


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
    selected = dict(_select_process_keys(process, keys))
    if human:
        selected = _humanize_process_values(selected)
    selected["timestamp"] = datetime.now(timezone.utc).isoformat()
    return selected


def _write_process(output_file, process: dict) -> None:
    if output_file is None:
        print_json(process)
        return

    json_output = json.dumps(process, default=default_json_encoder)
    output_file.write(json_output + "\n")
    output_file.flush()


@cli.command("single")
@async_command
async def sysmon_process_single(
    service_provider: ServiceProviderDep,
    attributes: Annotated[
        Optional[list[str]],
        typer.Option(
            "--attributes",
            "-a",
            help="filter processes by given attribute value given as key=value. Can be specified multiple times.",
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

    count = 0
    parsed_filters = _parse_attribute_filters(attributes)
    result = []
    async with (
        DvtProvider(service_provider) as dvt,
        DeviceInfo(dvt) as device_info,
        await Sysmontap.create(dvt) as sysmon,
    ):
        async for process_snapshot in sysmon.iter_processes():
            count += 1

            if count < 2:
                # first sample doesn't contain an initialized value for cpuUsage
                continue

            for process in process_snapshot:
                if not _matches_filters(process, parsed_filters):
                    continue

                process = dict(process)
                process["execName"] = await device_info.execname_for_pid(process["pid"])
                if human:
                    process = _humanize_process_values(process)
                result.append(process)

            break

    print_json(result)


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
    interval: Annotated[
        Optional[int],
        typer.Option(
            "--interval",
            "-i",
            help="minimum interval in milliseconds between outputs (optional)",
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

    count = 0
    start_time = None

    with contextlib.ExitStack() as stack:
        output_file = stack.enter_context(open(output, "w")) if output else None

        async with DvtProvider(service_provider) as dvt, await Sysmontap.create(dvt) as sysmon:
            async for process_snapshot in sysmon.iter_processes():
                count += 1

                if count < 2:
                    continue

                if start_time is None:
                    start_time = asyncio.get_running_loop().time()

                if duration is not None and ((asyncio.get_running_loop().time() - start_time) * 1000) >= duration:
                    break

                for process in process_snapshot:
                    if process.get("cpuUsage") is None or process["cpuUsage"] < threshold:
                        continue

                    _write_process(output_file, _serialize_process(process, keys, human))

                if interval:
                    await asyncio.sleep(interval / 1000.0)

                if duration is not None and ((asyncio.get_running_loop().time() - start_time) * 1000) >= duration:
                    break


@monitor_cli.command("pid")
@async_command
async def sysmon_process_monitor_pid(
    service_provider: ServiceProviderDep,
    pid: Annotated[int, typer.Argument(help="process identifier to monitor")],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="output file path for JSONL format (optional, defaults to stdout)",
        ),
    ] = None,
    interval: Annotated[
        Optional[int],
        typer.Option(
            "--interval",
            "-i",
            help="minimum interval in milliseconds between outputs (optional)",
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
    """Continuously monitor a single pid."""

    count = 0
    start_time = None

    with contextlib.ExitStack() as stack:
        output_file = stack.enter_context(open(output, "w")) if output else None

        async with DvtProvider(service_provider) as dvt, await Sysmontap.create(dvt) as sysmon:
            async for process_snapshot in sysmon.iter_processes():
                count += 1

                if count < 2:
                    continue

                if start_time is None:
                    start_time = asyncio.get_running_loop().time()

                if duration is not None and ((asyncio.get_running_loop().time() - start_time) * 1000) >= duration:
                    break

                for process in process_snapshot:
                    if process.get("pid") != pid:
                        continue

                    _write_process(output_file, _serialize_process(process, keys, human))

                if interval:
                    await asyncio.sleep(interval / 1000.0)

                if duration is not None and ((asyncio.get_running_loop().time() - start_time) * 1000) >= duration:
                    break
