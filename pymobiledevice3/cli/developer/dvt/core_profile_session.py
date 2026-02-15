import asyncio
import contextlib
import importlib.resources
import json
import logging
import queue
from enum import Enum
from itertools import islice
from pathlib import Path
from typing import Annotated, Optional

import typer
from pykdebugparser.pykdebugparser import PyKdebugParser
from typer_injector import InjectingTyper

import pymobiledevice3.resources
from pymobiledevice3.cli.cli_common import (
    BASED_INT,
    ServiceProviderDep,
    async_command,
    default_json_encoder,
    print_json,
    user_requested_colored_output,
)
from pymobiledevice3.exceptions import DvtException, ExtractingStackshotError
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap

logger = logging.getLogger(__name__)

BSC_SUBCLASS = 0x40C
BSC_CLASS = 0x4
VFS_AND_TRACES_SET = {0x03010000, 0x07FF0000}


cli = InjectingTyper(
    name="core-profile-session",
    help="Access tailspin features",
    no_args_is_help=True,
)


BSCFilter = Annotated[
    bool,
    typer.Option(help="Whether to print BSC events or not."),
]
ClassFilter = Annotated[
    list[int],
    typer.Option(
        "--class-filters",
        "-cf",
        click_type=BASED_INT,
        default_factory=list,
        show_default=False,
        help="Events class filter. Omit for all. Can be specified multiple times.",
    ),
]
SubclassFilter = Annotated[
    list[int],
    typer.Option(
        "--subclass-filters",
        "-sf",
        click_type=BASED_INT,
        default_factory=list,
        show_default=False,
        help="Events subclass filter. Omit for all. Can be specified multiple times.",
    ),
]
Count = Annotated[
    Optional[int],
    typer.Option(
        "--count",
        "-c",
        help="Number of events to print. Omit to endless sniff.",
    ),
]
ThreadID = Annotated[
    Optional[int],
    typer.Option(help="Thread ID to filter. Omit for all."),
]
ShowThreadID = Annotated[
    bool,
    typer.Option(help="Whether to print thread ID or not."),
]


class TraceColorMode(str, Enum):
    FAST = "fast"
    RICH = "rich"


_ANSI_RESET = "\033[0m"
_ANSI_TS = "\033[2;36m"
_ANSI_TID = "\033[35m"
_ANSI_PROCESS = "\033[33m"
_ANSI_EVENT = "\033[32m"


def _colorize_parse_live_trace(trace: str, *, show_tid: bool) -> str:
    # Keep this lightweight: fixed-width slicing of _format_trace() output.
    ts_end = 27
    tid_end = ts_end + (12 if show_tid else 0)
    process_end = tid_end + 34
    if len(trace) < process_end:
        return trace

    ts = trace[:ts_end]
    tid = trace[ts_end:tid_end]
    process = trace[tid_end:process_end]
    event = trace[process_end:]

    colored_trace = f"{_ANSI_TS}{ts}{_ANSI_RESET}"
    if show_tid:
        colored_trace += f"{_ANSI_TID}{tid}{_ANSI_RESET}"
    colored_trace += f"{_ANSI_PROCESS}{process}{_ANSI_RESET}"
    colored_trace += f"{_ANSI_EVENT}{event}{_ANSI_RESET}"
    return colored_trace


def parse_filters(subclasses: list[int], classes: list[int]) -> Optional[set[int]]:
    if not subclasses and not classes:
        return None
    parsed: set[int] = set()
    for subclass in subclasses:
        if subclass == BSC_SUBCLASS:
            parsed |= VFS_AND_TRACES_SET
        parsed.add(subclass << 16)
    for class_ in classes:
        if class_ == BSC_CLASS:
            parsed |= VFS_AND_TRACES_SET
        parsed.add((class_ << 24) | 0x00FF0000)
    return parsed


@cli.command("live")
@async_command
async def live_profile_session(
    service_provider: ServiceProviderDep,
    *,
    count: Count = -1,
    bsc: BSCFilter = False,
    class_filters: ClassFilter,
    subclass_filters: SubclassFilter,
    tid: ThreadID = None,
    timestamp: Annotated[
        bool,
        typer.Option(help="Whether to print timestamp or not."),
    ] = True,
    event_name: Annotated[
        bool,
        typer.Option(help="Whether to print event name or not."),
    ] = True,
    func_qual: Annotated[
        bool,
        typer.Option(help="Whether to print function qualifier or not."),
    ] = True,
    show_tid: ShowThreadID = True,
    process_name: Annotated[
        bool,
        typer.Option(help="Whether to print process name or not."),
    ] = True,
    args: Annotated[
        bool,
        typer.Option(help="Whether to print event arguments or not."),
    ] = True,
) -> None:
    """Print kevents received from the device in real time."""
    parser = PyKdebugParser()
    class_filters = class_filters
    subclass_filters = subclass_filters
    parser.filter_class = class_filters
    if bsc:
        subclass_filters.append(BSC_SUBCLASS)
    parser.filter_subclass = subclass_filters
    filters = parse_filters(subclass_filters, class_filters)
    parser.filter_tid = tid
    parser.show_timestamp = timestamp
    parser.show_name = event_name
    parser.show_func_qual = func_qual
    parser.show_tid = show_tid
    parser.show_process = process_name
    parser.show_args = args
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        trace_codes_map = await CoreProfileSessionTap.get_trace_codes(dvt)
        time_config = await CoreProfileSessionTap.get_time_config(dvt)
        parser.numer = time_config["numer"]
        parser.denom = time_config["denom"]
        parser.mach_absolute_time = time_config["mach_absolute_time"]
        parser.usecs_since_epoch = time_config["usecs_since_epoch"]
        parser.timezone = time_config["timezone"]
        async with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            chunk_queue = queue.Queue()
            stream = tap.get_kdbuf_stream(chunk_queue)
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            def _print_events() -> None:
                for i, event in enumerate(parser.formatted_kevents(stream, trace_codes_map)):
                    print(event)
                    if i == count:
                        break

            try:
                await asyncio.to_thread(_print_events)
            finally:
                producer_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await producer_task
                chunk_queue.put(None)


@cli.command("save")
@async_command
async def save_profile_session(
    service_provider: ServiceProviderDep,
    out: Path,
    *,
    bsc: BSCFilter = False,
    class_filters: ClassFilter,
    subclass_filters: SubclassFilter,
) -> None:
    """Dump core profiling information."""
    if bsc:
        subclass_filters.append(BSC_SUBCLASS)
    filters = parse_filters(subclass_filters, class_filters)
    async with (
        DvtSecureSocketProxyService(lockdown=service_provider) as dvt,
        CoreProfileSessionTap(dvt, {}, filters) as tap,
    ):
        with out.open("wb") as out_file:
            await tap.dump(out_file)


@cli.command("stackshot")
@async_command
async def stackshot(
    service_provider: ServiceProviderDep,
    out: Annotated[Optional[Path], typer.Option()] = None,
) -> None:
    """Dump stackshot information."""
    max_retries = 5
    retry_delay_sec = 0.5
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        for attempt in range(max_retries + 1):
            try:
                async with CoreProfileSessionTap(dvt, {}) as tap:
                    data = await tap.get_stackshot()
                break
            except DvtException as e:
                message = str(e)
                if "could not lock kperf" in message and attempt < max_retries:
                    logger.warning(
                        "Stackshot recording is busy (kperf lock). Retrying in %.1fs (%d/%d)...",
                        retry_delay_sec,
                        attempt + 1,
                        max_retries,
                    )
                    await asyncio.sleep(retry_delay_sec)
                    continue
                logger.error(f"Extracting stackshot failed: {e}")
                return
            except ExtractingStackshotError as e:
                logger.error(f"Extracting stackshot failed: {e}")
                return

        if out is not None:
            out.write_text(json.dumps(data, indent=4, default=default_json_encoder))
        else:
            print_json(data)


@cli.command("parse-live")
@async_command
async def parse_live_profile_session(
    service_provider: ServiceProviderDep,
    *,
    count: Count = None,
    bsc: BSCFilter = False,
    class_filters: ClassFilter,
    subclass_filters: SubclassFilter,
    tid: ThreadID = None,
    show_tid: ShowThreadID = False,
    process: Annotated[
        Optional[str],
        typer.Option(help="Process ID / name to filter. Omit for all."),
    ] = None,
    color_mode: Annotated[
        TraceColorMode,
        typer.Option(
            help="Trace color style. 'fast' uses low-overhead ANSI coloring, 'rich' uses syntax highlighting.",
            case_sensitive=False,
        ),
    ] = TraceColorMode.FAST,
) -> None:
    """Print traces (syscalls, thread events, etc.) received from the device in real time."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print("Receiving time information")
        time_config = await CoreProfileSessionTap.get_time_config(dvt)
        parser = PyKdebugParser()
        parser.filter_class = list(class_filters)
        if bsc:
            subclass_filters.append(BSC_SUBCLASS)
        parser.filter_subclass = subclass_filters
        filters = parse_filters(subclass_filters, class_filters)
        parser.numer = time_config["numer"]
        parser.denom = time_config["denom"]
        parser.mach_absolute_time = time_config["mach_absolute_time"]
        parser.usecs_since_epoch = time_config["usecs_since_epoch"]
        parser.timezone = time_config["timezone"]
        parser.filter_tid = tid
        parser.filter_process = process
        parser.show_tid = show_tid
        enable_color = user_requested_colored_output()
        parser.color = enable_color and color_mode == TraceColorMode.RICH

        async with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            if show_tid:
                print("{:^32}|{:^11}|{:^33}|   Event".format("Time", "Thread", "Process"))
            else:
                print("{:^32}|{:^33}|   Event".format("Time", "Process"))

            chunk_queue = queue.Queue()
            stream = tap.get_kdbuf_stream(chunk_queue)
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            def _print_traces() -> None:
                for trace in islice(parser.formatted_traces(stream), count):
                    if enable_color and color_mode == TraceColorMode.FAST:
                        trace = _colorize_parse_live_trace(trace, show_tid=show_tid)
                    print(trace, flush=True)

            try:
                await asyncio.to_thread(_print_traces)
            finally:
                producer_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await producer_task
                chunk_queue.put(None)


def get_image_name(dsc_uuid_map, image_uuid, current_dsc_map):
    if not current_dsc_map:
        for dsc_mapping in dsc_uuid_map.values():
            if image_uuid in dsc_mapping:
                current_dsc_map.update(dsc_mapping)

    return current_dsc_map.get(image_uuid, image_uuid)


def format_callstack(callstack: str, dsc_uuid_map, current_dsc_map) -> str:
    lines = callstack.splitlines()
    for i, line in enumerate(lines[1:]):
        if ":" in line:
            uuid = line.split(":")[0].strip()
            lines[i + 1] = line.replace(uuid, get_image_name(dsc_uuid_map, uuid, current_dsc_map))
    return "\n".join(lines)


@cli.command("callstacks-live")
@async_command
async def callstacks_live_profile_session(
    service_provider: ServiceProviderDep,
    count: Count = -1,
    process: Annotated[
        Optional[str],
        typer.Option(help="Process ID / name to filter. Omit for all."),
    ] = None,
    tid: ThreadID = None,
    show_tid: ShowThreadID = False,
) -> None:
    """Print callstacks received from the device in real time."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print("Receiving time information")
        time_config = await CoreProfileSessionTap.get_time_config(dvt)
        parser = PyKdebugParser()
        parser.numer = time_config["numer"]
        parser.denom = time_config["denom"]
        parser.mach_absolute_time = time_config["mach_absolute_time"]
        parser.usecs_since_epoch = time_config["usecs_since_epoch"]
        parser.timezone = time_config["timezone"]
        parser.filter_tid = tid
        parser.filter_process = process
        parser.color = user_requested_colored_output()
        parser.show_tid = show_tid

        with importlib.resources.open_text(pymobiledevice3.resources, "dsc_uuid_map.json") as fd:
            dsc_uuid_map = json.load(fd)

        current_dsc_map = {}
        async with CoreProfileSessionTap(dvt, time_config) as tap:
            chunk_queue = queue.Queue()
            stream = tap.get_kdbuf_stream(chunk_queue)
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            def _print_callstacks() -> None:
                for callstack in islice(parser.formatted_callstacks(stream), count):
                    print(format_callstack(callstack, dsc_uuid_map, current_dsc_map))

            try:
                await asyncio.to_thread(_print_callstacks)
            finally:
                producer_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await producer_task
                chunk_queue.put(None)
