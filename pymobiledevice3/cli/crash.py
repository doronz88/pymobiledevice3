from pathlib import Path
from typing import Annotated, Optional

import typer
from apple_symbols import KernelSymbols
from pycrashreport.crash_report import SERVER_ENVVAR, CrashReportBase
from pycrashreport.symbols import SymbolServerError
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    OutputFormat,
    OutputFormatOption,
    ServiceProviderDep,
    ShellHostToolsOption,
    WebDavBindPortOption,
    WebDavHostOption,
    WebDavMountOption,
    WebDavPathArgument,
    WebDavReadonlyOption,
    async_command,
    print_json_line,
    run_afc_webdav_cli,
)
from pymobiledevice3.services.crash_reports import (
    CrashReportsManager,
    CrashReportsShell,
    load_kernel_symbols,
    print_crash_report,
)

KernelcacheOption = Annotated[
    Optional[Path],
    typer.Option(
        exists=True,
        dir_okay=False,
        help="Kernelcache of the firmware the device ran (as found in its IPSW), to name the kernel "
        "images of a panic or a stackshot report.",
    ),
]
KernelSignaturesOption = Annotated[
    Optional[Path],
    typer.Option(
        exists=True,
        file_okay=False,
        help="Directory of `ipsw` kernel symbolication signatures (the `kernel` directory of "
        "https://github.com/blacktop/symbolicator), to name the kernel functions of a panic or a stackshot "
        "report. "
        "Requires --kernelcache and the `ipsw` tool.",
    ),
]


ProcessOption = Annotated[
    Optional[list[str]],
    typer.Option(
        "--process",
        "-p",
        help="Name or pid of a process of a panic, a stackshot or a spindump report to print the call stacks "
        "of. "
        "May be given several times.",
    ),
]
AllProcessesOption = Annotated[
    bool,
    typer.Option(
        "--all",
        help="Print the call stacks of every process of a panic, a stackshot or a spindump report, or of every "
        "thread of a crash.",
    ),
]
RunningOption = Annotated[
    bool,
    typer.Option("--running", "-r", help="Print the threads of a panic or a stackshot report which were on a CPU."),
]
SymbolServerOption = Annotated[
    Optional[str],
    typer.Option(
        envvar=SERVER_ENVVAR,
        help="URL of a symbolicator server (https://github.com/netanelc305/symbolicator-server), e.g. "
        "http://localhost:3993, to name frames with the symbols it holds. Frames it does not name are left to "
        "the Xcode device support of this host and to --kernelcache.",
    ),
]


def _load_kernel_symbols(kernelcache: Optional[Path], signatures: Optional[Path]) -> Optional[KernelSymbols]:
    try:
        return load_kernel_symbols(kernelcache, signatures)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e


def _print_report(
    report: CrashReportBase,
    kernel_symbols: Optional[KernelSymbols],
    processes: Optional[list[str]] = None,
    all_processes: bool = False,
    running: bool = False,
    symbol_server: Optional[str] = None,
) -> None:
    try:
        print_crash_report(report, kernel_symbols, processes or [], all_processes, running, symbol_server)
    except (ValueError, SymbolServerError) as e:
        raise typer.BadParameter(str(e)) from e


cli = InjectingTyper(
    name="crash",
    help="List, pull, parse, watch and delete crash reports (and sysdiagnose archives).",
    no_args_is_help=True,
)


@cli.command("clear")
@async_command
async def crash_clear(
    service_provider: ServiceProviderDep,
    remote_file: Annotated[str, typer.Argument(help="Path under the crash reports directory to clear.")] = "/",
    flush: Annotated[
        bool,
        typer.Option(
            "--flush",
            "-f",
            help="Run `flush` first, so pending reports are deleted too.",
        ),
    ] = False,
    match: Annotated[
        Optional[str],
        typer.Option(
            "--match",
            "-m",
            help="Only remove what `pull --match` would pull for the given basename regex (without copying).",
        ),
    ] = None,
) -> None:
    """Delete all crash reports under a path (default: everything; no confirmation)."""
    async with CrashReportsManager(service_provider) as crash_manager:
        if flush:
            await crash_manager.flush()
        await crash_manager.clear(remote_file, match=match)


@cli.command("parse")
@async_command
async def crash_parse(
    service_provider: ServiceProviderDep,
    remote_file: Annotated[str, typer.Argument(help="Crash report path, relative to the crash reports directory.")],
    kernelcache: KernelcacheOption = None,
    kernel_signatures: KernelSignaturesOption = None,
    process: ProcessOption = None,
    all_processes: AllProcessesOption = False,
    running: RunningOption = False,
    symbol_server: SymbolServerOption = None,
) -> None:
    """
    Print a crash report from the device in a readable, parsed form.

    Userland frames the report left unnamed, such as the user stacks of a panic report, are named
    using the Xcode device support of the device the report came from, which
    `developer fetch-symbols download` creates. Kernel frames are named given --kernelcache.
    --symbol-server asks a symbolicator server for both first.
    --process, --all and --running list the threads of the processes of a panic or a stackshot
    report (`stacks-*.ips`), --process and --all the call trees of a spindump report
    (`*.diskwrites_resource-*.ips` and the like), and --all every thread of a crash.
    """
    kernel_symbols = _load_kernel_symbols(kernelcache, kernel_signatures)
    async with CrashReportsManager(service_provider) as crash_manager:
        _print_report(
            await crash_manager.parse(remote_file), kernel_symbols, process, all_processes, running, symbol_server
        )


@cli.command("parse-latest")
@async_command
async def crash_parse_latest(
    service_provider: ServiceProviderDep,
    remote_file: Annotated[str, typer.Argument(help="Path whose top-level reports should be searched.")] = "/",
    match: Annotated[
        Optional[list[str]],
        typer.Option(
            "--match",
            "-m",
            help="Case-sensitive basename regex filter (repeatable; all must match).",
        ),
    ] = None,
    match_insensitive: Annotated[
        Optional[list[str]],
        typer.Option(
            "--match-insensitive",
            "-mi",
            help="Case-insensitive basename regex filter (repeatable; all must match).",
        ),
    ] = None,
    count: Annotated[
        int,
        typer.Option(
            "--count",
            "-n",
            min=1,
            help="Maximum number of latest reports to parse.",
        ),
    ] = 1,
    kernelcache: KernelcacheOption = None,
    kernel_signatures: KernelSignaturesOption = None,
    process: ProcessOption = None,
    all_processes: AllProcessesOption = False,
    running: RunningOption = False,
    symbol_server: SymbolServerOption = None,
) -> None:
    """Parse the latest top-level crash report(s) under a path, newest first."""
    kernel_symbols = _load_kernel_symbols(kernelcache, kernel_signatures)
    async with CrashReportsManager(service_provider) as crash_manager:
        latest_reports = await crash_manager.parse_latest(
            path=remote_file,
            match=match or [],
            match_insensitive=match_insensitive or [],
            count=count,
        )
        for report in latest_reports:
            _print_report(report, kernel_symbols, process, all_processes, running, symbol_server)


@cli.command("pull")
@async_command
async def crash_pull(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(file_okay=False, help="Local directory to save the reports into."),
    ],
    remote_file: Annotated[
        str, typer.Argument(help="File or directory to pull, relative to the crash reports directory.")
    ] = "/",
    erase: Annotated[
        bool,
        typer.Option("--erase", "-e", help="Delete each report from the device after pulling it."),
    ] = False,
    match: Annotated[
        Optional[str],
        typer.Option(
            "--match",
            "-m",
            help="Only pull entries whose basename matches this regex.",
        ),
    ] = None,
) -> None:
    """Download crash reports from the device (all of them by default)."""
    async with CrashReportsManager(service_provider) as crash_manager:
        await crash_manager.pull(str(out), remote_file, erase, match)


@cli.command("shell")
@async_command
async def crash_shell(service_provider: ServiceProviderDep, tool: ShellHostToolsOption = None) -> None:
    """Open an interactive file shell rooted at the crash reports directory."""
    async with CrashReportsManager(service_provider) as crash_manager:
        await CrashReportsShell(crash_manager, host_tools=tool or []).interact()


@cli.command("webdav")
@async_command
async def crash_webdav(
    service_provider: ServiceProviderDep,
    path: WebDavPathArgument = "/",
    mount: WebDavMountOption = False,
    host: WebDavHostOption = "127.0.0.1",
    bind_port: WebDavBindPortOption = 0,
    readonly: WebDavReadonlyOption = False,
) -> None:
    """Serve the crash reports directory over WebDAV for local mounting; runs until Ctrl+C."""
    async with CrashReportsManager(service_provider) as crash_manager:
        label = f"pmd-{service_provider.udid or 'device'}-crash"
        await run_afc_webdav_cli(
            crash_manager.afc, path=path, mount=mount, host=host, bind_port=bind_port, readonly=readonly, label=label
        )


@cli.command("ls")
@async_command
async def crash_ls(
    service_provider: ServiceProviderDep,
    remote_file: Annotated[
        str, typer.Argument(help="Directory to list, relative to the crash reports directory.")
    ] = "/",
    depth: Annotated[
        int,
        typer.Option("--depth", "-d", help="How many levels deep to list (-1 for unlimited)."),
    ] = 1,
) -> None:
    """List crash reports and folders in the crash reports directory."""
    async with CrashReportsManager(service_provider) as crash_manager:
        for path in await crash_manager.ls(remote_file, depth):
            print(path)


@cli.command("flush")
@async_command
async def crash_mover_flush(service_provider: ServiceProviderDep) -> None:
    """Move pending crash reports into the crash reports directory (via crashreportmover)."""
    async with CrashReportsManager(service_provider) as crash_manager:
        await crash_manager.flush()


@cli.command("watch")
@async_command
async def crash_watch(
    service_provider: ServiceProviderDep,
    name: Annotated[Optional[str], typer.Argument(help="Only show reports of the process with this name.")] = None,
    raw: Annotated[
        bool,
        typer.Option("--raw", "-r", help="Print each report's raw text instead of the parsed report."),
    ] = False,
    output_format: OutputFormatOption = OutputFormat.TEXT,
) -> None:
    """Print each new crash report as the device creates it; runs until Ctrl+C."""
    async with CrashReportsManager(service_provider) as crash_manager:
        async for crash_report in crash_manager.watch(name=name, raw=raw):
            if output_format is OutputFormat.JSON:
                if isinstance(crash_report, str):
                    print_json_line({"content": crash_report})
                else:
                    print_json_line({
                        "name": crash_report.name,
                        "bug_type": crash_report.bug_type,
                        "bug_type_str": crash_report.bug_type_str,
                        "incident_id": crash_report.incident_id,
                        "timestamp": crash_report.timestamp,
                    })
            else:
                print(crash_report, flush=True)


@cli.command("sysdiagnose")
@async_command
async def crash_sysdiagnose(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(exists=False, dir_okay=True, file_okay=True, help="Local path to save the archive to."),
    ],
    erase: Annotated[
        bool,
        typer.Option(
            "--erase",
            "-e",
            help="Delete the archive from the device after pulling it.",
        ),
    ] = False,
    timeout: Annotated[
        Optional[float],
        typer.Option(
            "--timeout",
            "-t",
            help="Maximum time in seconds to wait for the sysdiagnose archive to complete (default: no limit).",
        ),
    ] = None,
) -> None:
    """Wait for a sysdiagnose you trigger on the device, then download it.

    This command does not start the sysdiagnose: press Power+VolUp+VolDown
    together briefly on the device (as prompted), then wait for the archive.
    """
    print("Press Power+VolUp+VolDown for 0.215 seconds")
    async with CrashReportsManager(service_provider) as crash_manager:
        await crash_manager.get_new_sysdiagnose(str(out), erase=erase, timeout=timeout)
