import asyncio
import contextlib
import importlib.resources
import json
import logging
import queue
import re
import sys
import threading
from collections.abc import Callable, Mapping
from enum import Enum
from io import TextIOWrapper
from itertools import islice
from pathlib import Path
from typing import Annotated, Any, Optional, cast

import typer
from pykdebugparser.line_filter import MATCH_HELP, LineFilter, emphasize
from pykdebugparser.pykdebugparser import PyKdebugParser
from pykdebugparser.selection import GROUP_HELP, captured_events, parse_live_selection
from pykdebugparser.trace_codes import (
    default_trace_codes,
    event_eventids,
    syscall_eventids,
)
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
DBG_DYLD = 0x1F
# DBG_TRACE: thread names and the strings dyld events refer to.
TRACE_CLASS_FILTER = 0x07FF0000


# How far (in seconds) parse-live may fall behind the device before it skips ahead to recent events.
PARSE_LIVE_MAX_LAG = 2.0


class _LiveWorker:
    """
    Runs a live command's printing loop in a daemon thread, and stops it before the command returns.

    `asyncio.to_thread` joins its threads at exit, which hangs the exit when an interrupted command's thread still
    waits for the device's chunks; and a daemon thread still writing to stdout at interpreter shutdown aborts it. The
    loop gets a `threading.Event` that is set when it should stop, and checks it before each line it writes.
    """

    def __init__(self, func: Callable[[threading.Event], None]) -> None:
        self._func = func
        self.stopping = threading.Event()
        self._thread: Optional[threading.Thread] = None

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[None] = loop.create_future()

        def settle(error: Optional[BaseException]) -> None:
            if future.done():
                return
            if error is None:
                future.set_result(None)
            else:
                future.set_exception(error)

        def run() -> None:
            error: Optional[BaseException] = None
            try:
                self._func(self.stopping)
            except BaseException as e:
                error = e
            # The loop is closed if the command was abandoned.
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(settle, error)

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        await future

    def stop(self, chunk_queue: "queue.Queue[Any]", timeout: float = 5.0) -> None:
        """
        Stop the loop and wait for it: it stops before its next line, or at the end of the stream, which the chunks it
        has yet to parse are dropped from. Call it first when the command ends: it doesn't await, so a second
        cancellation of the command can't skip it.
        """
        self.stopping.set()
        with contextlib.suppress(queue.Empty):
            while True:
                chunk_queue.get_nowait()
        chunk_queue.put(None)
        if self._thread is not None:
            self._thread.join(timeout)


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


def _validate_syscalls(names: Any) -> list[str]:
    # An option callback runs while the arguments are parsed, so a typo fails before connecting to the device.
    # `names` is annotated `Any`: typer runs `issubclass()` on callback annotations, which fails for `list[str]`
    # on Python <= 3.10.
    try:
        syscall_eventids(names)
    except ValueError as e:
        raise typer.BadParameter(
            f"{e} (`pymobiledevice3 developer dvt core-profile-session events` lists them as BSC_<name>)"
        ) from e
    return names


def _validate_regexes(regexes: Any) -> list[str]:
    # See `_validate_syscalls`.
    for regex in regexes:
        try:
            re.compile(regex)
        except re.error as e:
            raise typer.BadParameter(f"{regex!r}: {e}") from e
    return regexes


def _validate_max_lag(value: float) -> float:
    if value <= 0:
        raise typer.BadParameter("must be positive")
    return value


def _validate_events(names: Any) -> list[str]:
    # See `_validate_syscalls`.
    try:
        event_eventids(names)
    except ValueError as e:
        raise typer.BadParameter(f"{e} (`pymobiledevice3 developer dvt core-profile-session events` lists them)") from e
    return names


def live_trace_codes(device_trace_codes: dict[int, str]) -> dict[int, str]:
    """
    The trace codes `live` names events with: the device's, plus pykdebugparser's for the events the device's
    table does not name (such as the XPC, dispatch and CFRunLoop events of user space).
    """
    return {**default_trace_codes(), **device_trace_codes}


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
        trace_codes_map = live_trace_codes(await CoreProfileSessionTap.get_trace_codes(dvt))
        time_config = cast(dict[str, object], await CoreProfileSessionTap.get_time_config(dvt))
        parser.numer = time_config["numer"]
        parser.denom = time_config["denom"]
        parser.mach_absolute_time = time_config["mach_absolute_time"]
        parser.usecs_since_epoch = time_config["usecs_since_epoch"]
        parser.timezone = time_config["timezone"]
        async with CoreProfileSessionTap(dvt, time_config, filters, sample_callstacks=False) as tap:
            chunk_queue: queue.Queue[Any] = queue.Queue()
            stream = tap.get_kdbuf_stream(chunk_queue)
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            def _print_events(stopping: threading.Event) -> None:
                # KdBufStream is a duck-typed stream; pykdebugparser annotates the parameter as io.IOBase
                for i, event in enumerate(
                    parser.formatted_kevents(stream, trace_codes_map)  # pyright: ignore[reportArgumentType]
                ):
                    if stopping.is_set():
                        break
                    print(event)
                    if i == count:
                        break

            worker = _LiveWorker(_print_events)
            try:
                await worker.run()
            finally:
                producer_task.cancel()
                worker.stop(chunk_queue)
                with contextlib.suppress(asyncio.CancelledError):
                    await producer_task


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


SyscallSelect = Annotated[
    list[str],
    typer.Option(
        "--syscall",
        "-s",
        default_factory=list,
        callback=_validate_syscalls,
        show_default=False,
        help="This syscall (e.g. open, openat; with its _nocancel and _dprotected_np variants), with its paths. Can be "
        "specified multiple times.",
    ),
]
EventSelect = Annotated[
    list[str],
    typer.Option(
        "--event",
        "-e",
        default_factory=list,
        show_default=False,
        callback=_validate_events,
        help="This event, by its trace code name (e.g. DBG_DYLD_TIMING_DLSYM; `events TEXT` finds the name). Can be "
        "specified multiple times.",
    ),
]
FsGroup = Annotated[bool, typer.Option("--fs", help=GROUP_HELP["fs"])]
NetGroup = Annotated[bool, typer.Option("--net", help=GROUP_HELP["net"])]
ProcGroup = Annotated[bool, typer.Option("--proc", help=GROUP_HELP["proc"])]
IoGroup = Annotated[bool, typer.Option("--io", help=GROUP_HELP["io"])]
MemGroup = Annotated[bool, typer.Option("--mem", help=GROUP_HELP["mem"])]
SignalGroup = Annotated[bool, typer.Option("--signal", help=GROUP_HELP["signal"])]
CredGroup = Annotated[bool, typer.Option("--cred", help=GROUP_HELP["cred"])]
SyncGroup = Annotated[bool, typer.Option("--sync", help=GROUP_HELP["sync"])]
MachGroup = Annotated[bool, typer.Option("--mach", help=GROUP_HELP["mach"])]
DyldGroup = Annotated[
    bool, typer.Option("--dyld", help="dyld events (image loads, dlopen, dlsym, ...), filtered on the device.")
]
XpcGroup = Annotated[bool, typer.Option("--xpc", help=GROUP_HELP["xpc"])]
DispatchGroup = Annotated[bool, typer.Option("--dispatch", help=GROUP_HELP["dispatch"])]
RunloopGroup = Annotated[bool, typer.Option("--runloop", help=GROUP_HELP["runloop"])]


def _enabled_groups(**groups: bool) -> list[str]:
    return [group for group, on in groups.items() if on]


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
    syscalls: SyscallSelect,
    events: EventSelect,
    fs: FsGroup = False,
    net: NetGroup = False,
    proc: ProcGroup = False,
    io: IoGroup = False,
    mem: MemGroup = False,
    signal: SignalGroup = False,
    cred: CredGroup = False,
    sync: SyncGroup = False,
    mach: MachGroup = False,
    dyld: DyldGroup = False,
    xpc: XpcGroup = False,
    dispatch: DispatchGroup = False,
    runloop: RunloopGroup = False,
    match: Annotated[
        list[str], typer.Option("--match", "-m", default_factory=list, show_default=False, help=MATCH_HELP["match"])
    ],
    invert_match: Annotated[
        list[str],
        typer.Option("--invert-match", "-v", default_factory=list, show_default=False, help=MATCH_HELP["invert_match"]),
    ],
    match_insensitive: Annotated[
        list[str],
        typer.Option(
            "--match-insensitive", "-mi", default_factory=list, show_default=False, help=MATCH_HELP["match_insensitive"]
        ),
    ],
    invert_match_insensitive: Annotated[
        list[str],
        typer.Option(
            "--invert-match-insensitive",
            "-vi",
            default_factory=list,
            show_default=False,
            help=MATCH_HELP["invert_match_insensitive"],
        ),
    ],
    regex: Annotated[
        list[str],
        typer.Option(
            "--regex",
            "-r",
            default_factory=list,
            show_default=False,
            callback=_validate_regexes,
            help=MATCH_HELP["regex"],
        ),
    ],
    insensitive_regex: Annotated[
        list[str],
        typer.Option(
            "--insensitive-regex",
            "-ri",
            default_factory=list,
            show_default=False,
            callback=_validate_regexes,
            help=MATCH_HELP["insensitive_regex"],
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Print each trace as a JSON object, one per line: its time, thread, process, event name, parsed fields "
            "and text. The filters match the line it would print.",
        ),
    ] = False,
    color_mode: Annotated[
        TraceColorMode,
        typer.Option(
            help="Trace color style: 'rich' also colors the event by what it shows (call, strings, numbers, errors, "
            "...), 'fast' colors only the columns.",
            case_sensitive=False,
        ),
    ] = TraceColorMode.RICH,
    skip_behind: Annotated[
        bool,
        typer.Option(
            help="Skip ahead to recent events whenever output falls more than --max-lag behind the device, instead of "
            "failing. Without class/subclass filters the device can emit events faster than they can be parsed.",
        ),
    ] = False,
    max_lag: Annotated[
        float,
        typer.Option(
            callback=_validate_max_lag,
            help="How far (in seconds) output may fall behind the device before it skips ahead (--skip-behind) or "
            "fails (--no-skip-behind).",
        ),
    ] = PARSE_LIVE_MAX_LAG,
) -> None:
    """
    Print traces (syscalls, thread events, etc.) received from the device in real time.

    The selections add up. The device filters by subclass at best, so the events not selected are dropped right
    after decoding, which keeps up with the device even over --userspace. `events` with the same options lists the
    events that are printed.
    """
    groups = _enabled_groups(
        fs=fs,
        net=net,
        proc=proc,
        io=io,
        mem=mem,
        signal=signal,
        cred=cred,
        sync=sync,
        mach=mach,
        xpc=xpc,
        dispatch=dispatch,
        runloop=runloop,
    )
    selection = parse_live_selection(
        bsc=bsc,
        class_filters=class_filters,
        subclass_filters=subclass_filters,
        syscalls=syscalls,
        events=events,
        groups=groups,
        dyld=dyld,
    )
    async with DvtProvider(service_provider) as dvt:
        if not json_output:
            print("Receiving time information")
        time_config = cast(dict[str, object], await CoreProfileSessionTap.get_time_config(dvt))
        parser: Any = PyKdebugParser()
        parser.filter_class = list(selection.classes)
        parser.filter_subclass = list(selection.subclasses)
        parser.filter_eventid = selection.eventids
        line_filter = LineFilter(
            match, invert_match, match_insensitive, invert_match_insensitive, regex, insensitive_regex
        )
        parser.line_filter = line_filter
        # The device filters by subclass at best: request every syscall (and the subclass of each event), and
        # filter the chosen ones on the host.
        device_subclasses = (
            [*selection.subclasses, BSC_SUBCLASS] if selection.syscall_ids else list(selection.subclasses)
        )
        device_subclasses += sorted({eventid >> 16 for eventid in selection.event_ids})
        filters = parse_filters(device_subclasses, selection.classes)
        if (dyld or selection.event_ids) and filters is not None:
            filters.add(TRACE_CLASS_FILTER)
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

        async with CoreProfileSessionTap(dvt, time_config, filters, sample_callstacks=False) as tap:
            if not json_output:
                if show_tid:
                    print("{:^32}|{:^11}|{:^33}|   Event".format("Time", "Thread", "Process"))
                else:
                    print("{:^32}|{:^33}|   Event".format("Time", "Process"))

            def _warn_skipped(events: int, lag: float) -> None:
                logger.warning(
                    f"Skipped {events} events to catch up ({lag:.1f}s behind); "
                    "narrow the trace with --class-filters/--subclass-filters/--bsc to see every event"
                )

            # Lines are written in batches, and flushed whenever the stream waits for the device: a write per line
            # (what a line-buffered terminal does) costs a busy trace up to half its speed.
            out = sys.stdout
            chunk_queue: queue.Queue[Any] = queue.Queue()
            stream = tap.get_kdbuf_stream(
                chunk_queue,
                max_lag=max_lag,
                on_skip=_warn_skipped,
                on_wait=out.flush,
                skip_behind=skip_behind,
            )
            producer_task = asyncio.create_task(tap.pump_kdbuf_chunks(chunk_queue))

            def _print_traces(stopping: threading.Event) -> None:
                write = out.write
                # KdBufStream is a duck-typed stream; pykdebugparser annotates the parameter as io.IOBase
                if json_output:
                    for trace in islice(parser.dict_traces(stream), count):  # pyright: ignore[reportArgumentType]
                        if stopping.is_set():
                            break
                        write(json.dumps(trace) + "\n")
                else:
                    for line in islice(parser.formatted_traces(stream), count):  # pyright: ignore[reportArgumentType]
                        if stopping.is_set():
                            break
                        if enable_color and color_mode == TraceColorMode.FAST:
                            plain = line
                            line = _colorize_parse_live_trace(line, show_tid=show_tid)
                            if line_filter:
                                line = emphasize(line, line_filter.spans(plain))
                        write(line + "\n")
                out.flush()

            line_buffering = getattr(out, "line_buffering", False)
            if line_buffering and isinstance(out, TextIOWrapper):
                out.reconfigure(line_buffering=False)
            worker = _LiveWorker(_print_traces)
            try:
                await worker.run()
            finally:
                producer_task.cancel()
                worker.stop(chunk_queue)
                with contextlib.suppress(asyncio.CancelledError):
                    await producer_task
                if line_buffering and isinstance(out, TextIOWrapper):
                    out.flush()
                    out.reconfigure(line_buffering=True)
                # Whether the trace kept up with the device: nothing dropped by its kernel, nothing skipped.
                print(
                    f"Read {stream.events} events, the kernel dropped events {stream.lost_events} times, "
                    f"{stream.skipped_events} events were skipped to catch up",
                    file=sys.stderr,
                )


@cli.command("events")
def list_events(
    *,
    pattern: Annotated[
        Optional[str],
        typer.Argument(help="Only list the names containing this text, ignoring case (e.g. dlsym)."),
    ] = None,
    bsc: BSCFilter = False,
    class_filters: ClassFilter,
    subclass_filters: SubclassFilter,
    syscalls: SyscallSelect,
    events: EventSelect,
    fs: FsGroup = False,
    net: NetGroup = False,
    proc: ProcGroup = False,
    io: IoGroup = False,
    mem: MemGroup = False,
    signal: SignalGroup = False,
    cred: CredGroup = False,
    sync: SyncGroup = False,
    mach: MachGroup = False,
    dyld: DyldGroup = False,
    xpc: XpcGroup = False,
    dispatch: DispatchGroup = False,
    runloop: RunloopGroup = False,
) -> None:
    """
    List the events `parse-live` prints with the same options (e.g. `events --fs`, `events -s open`), or every event
    name `parse-live --event` accepts.
    """
    groups = _enabled_groups(
        fs=fs,
        net=net,
        proc=proc,
        io=io,
        mem=mem,
        signal=signal,
        cred=cred,
        sync=sync,
        mach=mach,
        xpc=xpc,
        dispatch=dispatch,
        runloop=runloop,
    )
    if bsc or class_filters or subclass_filters or syscalls or events or groups or dyld:
        names = captured_events(
            parse_live_selection(
                bsc=bsc,
                class_filters=class_filters,
                subclass_filters=subclass_filters,
                syscalls=syscalls,
                events=events,
                groups=groups,
                dyld=dyld,
            )
        )
    else:
        names = sorted(set(default_trace_codes().values()))
    if pattern is not None:
        names = [name for name in names if pattern.lower() in name.lower()]
    for name in names:
        print(name)


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
    count: Count = None,
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

            def _print_callstacks(stopping: threading.Event) -> None:
                # KdBufStream is a duck-typed stream; pykdebugparser annotates the parameter as io.IOBase
                for callstack in islice(parser.formatted_callstacks(stream), count):  # pyright: ignore[reportArgumentType]
                    if stopping.is_set():
                        break
                    print(format_callstack(callstack, dsc_uuid_map, current_dsc_map))

            worker = _LiveWorker(_print_callstacks)
            try:
                await worker.run()
            finally:
                producer_task.cancel()
                worker.stop(chunk_queue)
                with contextlib.suppress(asyncio.CancelledError):
                    await producer_task
