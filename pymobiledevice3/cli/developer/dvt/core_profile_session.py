import asyncio
import contextlib
import importlib.resources
import json
import logging
import queue
from collections.abc import Mapping
from enum import Enum
from itertools import islice
from pathlib import Path
from typing import Annotated, Any, Optional, cast

import typer
from pykdebugparser.pykdebugparser import PyKdebugParser
from typer_injector import InjectingTyper

import pymobiledevice3.resources
from pymobiledevice3.cli.cli_common import (
    ServiceProviderDep,
    async_command,
    based_int,
    default_json_encoder,
    print_json,
    user_requested_colored_output,
)
from pymobiledevice3.exceptions import DvtException, ExtractingStackshotError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap
from pymobiledevice3.services.dvt.instruments.device_support_symbols import (
    DeviceSupportSymbols,
    find_device_support_symbols,
)
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.kernel_symbols import KernelSymbols
from pymobiledevice3.services.dvt.instruments.stackshot import (
    StackshotFrame,
    StackshotProcess,
    kernel_image_uuids,
    resolve_stackshot,
)

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
        parser=based_int,
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
        parser=based_int,
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
    parser: Any = PyKdebugParser()
    class_filters = class_filters
    subclass_filters = subclass_filters
    parser.filter_class = class_filters
    if bsc:
        subclass_filters.append(BSC_SUBCLASS)
    parser.filter_subclass = subclass_filters
    filters = parse_filters(subclass_filters, class_filters)
    # PyKdebugParser initializes its filter attributes to None without annotations,
    # so pyright infers their type as None
    parser.filter_tid = tid  # pyright: ignore[reportAttributeAccessIssue]
    parser.show_timestamp = timestamp
    parser.show_name = event_name
    parser.show_func_qual = func_qual
    parser.show_tid = show_tid
    parser.show_process = process_name
    parser.show_args = args
    async with DvtProvider(service_provider) as dvt:
        trace_codes_map = await CoreProfileSessionTap.get_trace_codes(dvt)
        time_config = cast(dict[str, object], await CoreProfileSessionTap.get_time_config(dvt))
        parser.numer = time_config["numer"]
        parser.denom = time_config["denom"]
        parser.mach_absolute_time = time_config["mach_absolute_time"]
        parser.usecs_since_epoch = time_config["usecs_since_epoch"]
        parser.timezone = time_config["timezone"]
        async with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            chunk_queue: queue.Queue[Any] = queue.Queue()
            stream = tap.get_kdbuf_stream(chunk_queue)
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            def _print_events() -> None:
                # KdBufStream is a duck-typed stream; pykdebugparser annotates the parameter as io.IOBase
                for i, event in enumerate(
                    parser.formatted_kevents(stream, trace_codes_map)  # pyright: ignore[reportArgumentType]
                ):
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
    async with DvtProvider(service_provider) as dvt, CoreProfileSessionTap(dvt, {}, filters) as tap:
        with out.open("wb") as out_file:
            await tap.dump(out_file)


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def _format_stackshot_frame(index: int, frame: StackshotFrame, image_width: int, colored: bool) -> str:
    def style(text: str, **kwargs: Any) -> str:
        return typer.style(text, **kwargs) if colored else text

    if frame.image is None:
        location = style(f"0x{frame.address:x}", fg="bright_blue")
    else:
        if frame.symbol is not None:
            position = f"{style(frame.symbol, fg='green')} + 0x{frame.symbol_offset:x}"
        else:
            position = style(f"0x{frame.image_offset:x}", fg="bright_blue")
        location = f"{style(frame.image.ljust(image_width), fg='cyan')}  {position}"
    if frame.kernel:
        location += style("  (kernel)", dim=True)
    return f"    {index:>3}  {location}"


def format_stackshot(processes: list[StackshotProcess], colored: bool = False) -> str:
    """Format the call stacks of the given processes, one block per process and thread."""

    def style(text: str, **kwargs: Any) -> str:
        return typer.style(text, **kwargs) if colored else text

    lines: list[str] = []
    for process in processes:
        title = [style(f"{process.name} [{process.pid}]", fg="yellow", bold=True)]
        if process.task_size:
            title.append(f"size {_format_size(process.task_size)}")
        if process.max_resident_size:
            title.append(f"max rss {_format_size(process.max_resident_size)}")
        if process.suspend_count:
            title.append(f"suspended x{process.suspend_count}")
        title.append(f"{len(process.threads)} threads")
        lines.append("  ".join(title))

        for thread in process.threads:
            title = [style(f"Thread {thread.thread_id}", bold=True)]
            title += [style(name, fg="magenta") for name in (thread.name, thread.dispatch_queue) if name]
            title += thread.states
            if thread.qos is not None:
                title.append(thread.qos)
            if thread.sched_priority is not None:
                title.append(f"pri {thread.sched_priority}")
            if thread.user_usec is not None and thread.system_usec is not None:
                title.append(f"cpu {thread.user_usec / 1e6:.3f}s user, {thread.system_usec / 1e6:.3f}s sys")
            if thread.wait_event:
                title.append(f"wait 0x{thread.wait_event:x}")
            if thread.continuation is not None:
                title.append(f"continuation {thread.continuation}")
            lines.append("  " + "  ".join(title))

            image_width = max((len(frame.image) for frame in thread.frames if frame.image is not None), default=0)
            lines.extend(
                _format_stackshot_frame(i, frame, image_width, colored) for i, frame in enumerate(thread.frames)
            )
        lines.append("")
    return "\n".join(lines)


def _load_stackshot_symbols(
    service_provider: LockdownServiceProvider, symbols: Optional[Path]
) -> Optional[DeviceSupportSymbols]:
    if symbols is None:
        symbols = find_device_support_symbols(service_provider)
        if symbols is None:
            logger.warning(
                f"No Xcode device support was found for {service_provider.product_type} "
                f"{service_provider.product_version} ({service_provider.product_build_version}), so call stacks are "
                f"not symbolicated. Run `pymobiledevice3 developer fetch-symbols download` to get it."
            )
            return None
    loaded_symbols = DeviceSupportSymbols.load(symbols)
    if not loaded_symbols.has_shared_cache_images:
        logger.warning(
            f"{symbols} holds no images of the dyld shared cache, so call stacks are mostly not symbolicated. "
            f"Run `pymobiledevice3 developer fetch-symbols download --force` to get them."
        )
    return loaded_symbols


def _load_stackshot_kernel_symbols(
    kernelcache: Optional[Path], signatures: Optional[Path], stackshot: Mapping[str, Any]
) -> Optional[KernelSymbols]:
    if kernelcache is None:
        return None
    try:
        kernel_symbols = KernelSymbols.load(kernelcache, signatures)
    except OSError as e:
        logger.error(f"Reading the kernel symbols of {kernelcache} failed: {e}")
        raise typer.Exit(1) from e

    if not any(kernel_symbols.image_by_uuid(image_uuid) is not None for image_uuid in kernel_image_uuids(stackshot)):
        logger.warning(
            f"{kernelcache} is not the kernelcache the device runs, so kernel frames are not symbolicated. "
            f"Use the one of the firmware the device has installed."
        )
    elif not kernel_symbols.has_symbols:
        logger.warning(
            f"{kernelcache} holds no symbols, so kernel frames only get the name of their image. "
            f"Pass --kernel-signatures to symbolicate them."
        )
    return kernel_symbols


@cli.command("stackshot")
@async_command
async def stackshot(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Optional[Path],
        typer.Option(help="Write the raw stackshot as JSON into this file instead of printing it."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the raw stackshot as JSON instead of the call stacks."),
    ] = False,
    process: Annotated[
        Optional[str],
        typer.Option(help="Process ID / name to filter. Omit for all."),
    ] = None,
    symbols: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=False,
            help="Directory of symbols to use (as created by `developer fetch-symbols download`), instead of "
            "the Xcode device support of the device.",
        ),
    ] = None,
    kernelcache: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            dir_okay=False,
            help="Kernelcache of the firmware the device runs (as found in its IPSW), to name the kernel "
            "images of kernel frames. Requires `ipsw` unless it is already decompressed.",
        ),
    ] = None,
    kernel_signatures: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=False,
            help="Directory of `ipsw` kernel symbolication signatures (the `kernel` directory of "
            "https://github.com/blacktop/symbolicator), to symbolicate kernel frames of --kernelcache. "
            "Requires `ipsw`.",
        ),
    ] = None,
) -> None:
    """
    Print the call stacks of all threads of all processes.

    The call stacks are symbolicated using the Xcode device support of the device, which
    `developer fetch-symbols download` creates. Kernel frames are symbolicated when given
    --kernelcache and --kernel-signatures.
    """
    if kernel_signatures is not None and kernelcache is None:
        raise typer.BadParameter("--kernel-signatures requires --kernelcache")

    max_retries = 5
    retry_delay_sec = 0.5
    async with DvtProvider(service_provider) as dvt:
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
                raise typer.Exit(1) from e
            except ExtractingStackshotError as e:
                logger.error(f"Extracting stackshot failed: {e}")
                raise typer.Exit(1) from e
        else:
            # All retries were exhausted without capturing a stackshot; the loop
            # only reaches here if every attempt failed non-fatally.
            return

    if out is not None:
        out.write_text(json.dumps(data, indent=4, default=default_json_encoder))
        return
    if json_output:
        print_json(data)
        return

    processes = resolve_stackshot(
        data,
        _load_stackshot_symbols(service_provider, symbols),
        _load_stackshot_kernel_symbols(kernelcache, kernel_signatures, data),
    )
    if process is not None:
        processes = [p for p in processes if process in (str(p.pid), p.name)]
    print(format_stackshot(processes, colored=user_requested_colored_output()))


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
    async with DvtProvider(service_provider) as dvt:
        print("Receiving time information")
        time_config = cast(dict[str, object], await CoreProfileSessionTap.get_time_config(dvt))
        parser: Any = PyKdebugParser()
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
        # PyKdebugParser initializes its filter attributes to None without annotations,
        # so pyright infers their type as None
        parser.filter_tid = tid  # pyright: ignore[reportAttributeAccessIssue]
        parser.filter_process = process  # pyright: ignore[reportAttributeAccessIssue]
        parser.show_tid = show_tid
        enable_color = user_requested_colored_output()
        parser.color = enable_color and color_mode == TraceColorMode.RICH

        async with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            if show_tid:
                print("{:^32}|{:^11}|{:^33}|   Event".format("Time", "Thread", "Process"))
            else:
                print("{:^32}|{:^33}|   Event".format("Time", "Process"))

            chunk_queue: queue.Queue[Any] = queue.Queue()
            stream = tap.get_kdbuf_stream(chunk_queue)
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            def _print_traces() -> None:
                # KdBufStream is a duck-typed stream; pykdebugparser annotates the parameter as io.IOBase
                for trace in islice(parser.formatted_traces(stream), count):  # pyright: ignore[reportArgumentType]
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


def get_image_name(dsc_uuid_map: dict[str, dict[str, str]], image_uuid: str, current_dsc_map: dict[str, str]) -> str:
    if not current_dsc_map:
        for dsc_mapping in dsc_uuid_map.values():
            if image_uuid in dsc_mapping:
                current_dsc_map.update(dsc_mapping)

    return current_dsc_map.get(image_uuid, image_uuid)


def format_callstack(callstack: str, dsc_uuid_map: dict[str, dict[str, str]], current_dsc_map: dict[str, str]) -> str:
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
    async with DvtProvider(service_provider) as dvt:
        print("Receiving time information")
        time_config = cast(dict[str, object], await CoreProfileSessionTap.get_time_config(dvt))
        parser: Any = PyKdebugParser()
        parser.numer = time_config["numer"]
        parser.denom = time_config["denom"]
        parser.mach_absolute_time = time_config["mach_absolute_time"]
        parser.usecs_since_epoch = time_config["usecs_since_epoch"]
        parser.timezone = time_config["timezone"]
        # PyKdebugParser initializes its filter attributes to None without annotations,
        # so pyright infers their type as None
        parser.filter_tid = tid  # pyright: ignore[reportAttributeAccessIssue]
        parser.filter_process = process  # pyright: ignore[reportAttributeAccessIssue]
        parser.color = user_requested_colored_output()
        parser.show_tid = show_tid

        with importlib.resources.open_text(pymobiledevice3.resources, "dsc_uuid_map.json") as fd:
            dsc_uuid_map = json.load(fd)

        current_dsc_map: dict[str, str] = {}
        async with CoreProfileSessionTap(dvt, time_config) as tap:
            chunk_queue: queue.Queue[Any] = queue.Queue()
            stream = tap.get_kdbuf_stream(chunk_queue)
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            def _print_callstacks() -> None:
                # KdBufStream is a duck-typed stream; pykdebugparser annotates the parameter as io.IOBase
                for callstack in islice(parser.formatted_callstacks(stream), count):  # pyright: ignore[reportArgumentType]
                    print(format_callstack(callstack, dsc_uuid_map, current_dsc_map))

            try:
                await asyncio.to_thread(_print_callstacks)
            finally:
                producer_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await producer_task
                chunk_queue.put(None)
