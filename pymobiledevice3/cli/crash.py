from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.services.crash_reports import CrashReportsManager, CrashReportsShell

cli = InjectingTyper(
    name="crash",
    help="Manage crash reports",
    no_args_is_help=True,
)


@cli.command("clear")
@async_command
async def crash_clear(
    service_provider: ServiceProviderDep,
    remote_file: Annotated[str, typer.Argument(help="Path to clear")] = "/",
    flush: Annotated[
        bool,
        typer.Option(
            "--flush",
            "-f",
            help="flush before clear",
        ),
    ] = False,
) -> None:
    """clear(/remove) all crash reports inside the remote_file argument"""
    async with CrashReportsManager(service_provider) as crash_manager:
        if flush:
            await crash_manager.flush()
        await crash_manager.clear(remote_file)


@cli.command("parse")
@async_command
async def crash_parse(
    service_provider: ServiceProviderDep,
    remote_file: str,
) -> None:
    """Parse a crash report file"""
    async with CrashReportsManager(service_provider) as crash_manager:
        print(await crash_manager.parse(remote_file))


@cli.command("parse-latest")
@async_command
async def crash_parse_latest(
    service_provider: ServiceProviderDep,
    remote_file: Annotated[str, typer.Argument(help="Path whose top-level reports should be searched")] = "/",
    match: Annotated[
        Optional[list[str]],
        typer.Option(
            "--match",
            "-m",
            help="Case-sensitive basename regex filter (repeatable; all must match)",
        ),
    ] = None,
    match_insensitive: Annotated[
        Optional[list[str]],
        typer.Option(
            "--match-insensitive",
            "-mi",
            help="Case-insensitive basename regex filter (repeatable; all must match)",
        ),
    ] = None,
    count: Annotated[
        int,
        typer.Option(
            "--count",
            "-n",
            min=1,
            help="Maximum number of latest reports to parse",
        ),
    ] = 1,
) -> None:
    """Parse latest top-level crash report(s) under a path, ordered by newest first"""
    async with CrashReportsManager(service_provider) as crash_manager:
        latest_reports = await crash_manager.parse_latest(
            path=remote_file,
            match=match or [],
            match_insensitive=match_insensitive or [],
            count=count,
        )
        for report in latest_reports:
            print(report)


@cli.command("pull")
@async_command
async def crash_pull(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(file_okay=False),
    ],
    remote_file: str = "/",
    erase: Annotated[
        bool,
        typer.Option("--erase", "-e"),
    ] = False,
    match: Annotated[
        Optional[str],
        typer.Option(
            "--match",
            "-m",
            help="Match given regex over enumerated basenames",
        ),
    ] = None,
) -> None:
    """pull all crash reports"""
    async with CrashReportsManager(service_provider) as crash_manager:
        await crash_manager.pull(str(out), remote_file, erase, match)


@cli.command("shell")
def crash_shell(service_provider: ServiceProviderDep) -> None:
    """start an afc shell"""
    CrashReportsShell.create(service_provider)


@cli.command("ls")
@async_command
async def crash_ls(
    service_provider: ServiceProviderDep,
    remote_file: str = "/",
    depth: Annotated[
        int,
        typer.Option("--depth", "-d"),
    ] = 1,
) -> None:
    """List"""
    async with CrashReportsManager(service_provider) as crash_manager:
        for path in await crash_manager.ls(remote_file, depth):
            print(path)


@cli.command("flush")
@async_command
async def crash_mover_flush(service_provider: ServiceProviderDep) -> None:
    """trigger com.apple.crashreportmover to flush all products into CrashReports directory"""
    async with CrashReportsManager(service_provider) as crash_manager:
        await crash_manager.flush()


@cli.command("watch")
@async_command
async def crash_watch(
    service_provider: ServiceProviderDep,
    name: Optional[str] = None,
    raw: Annotated[
        bool,
        typer.Option("--raw", "-r"),
    ] = False,
) -> None:
    """watch for crash report generation"""
    async with CrashReportsManager(service_provider) as crash_manager:
        async for crash_report in crash_manager.watch(name=name, raw=raw):
            print(crash_report)


@cli.command("sysdiagnose")
@async_command
async def crash_sysdiagnose(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(exists=False, dir_okay=True, file_okay=True),
    ],
    erase: Annotated[
        bool,
        typer.Option(
            "--erase",
            "-e",
            help="erase file after pulling",
        ),
    ] = False,
    timeout: Annotated[
        Optional[float],
        typer.Option(
            "--timeout",
            "-t",
            help="Maximum time in seconds to wait for the completion of sysdiagnose archive",
        ),
    ] = None,
) -> None:
    """get a sysdiagnose archive from device (requires user interaction)"""
    print("Press Power+VolUp+VolDown for 0.215 seconds")
    async with CrashReportsManager(service_provider) as crash_manager:
        await crash_manager.get_new_sysdiagnose(str(out), erase=erase, timeout=timeout)
