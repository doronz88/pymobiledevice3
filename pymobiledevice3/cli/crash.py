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
    flush: Annotated[
        bool,
        typer.Option(
            "--flush",
            "-f",
            help="flush before clear",
        ),
    ] = False,
) -> None:
    """clear(/remove) all crash reports"""
    crash_manager = CrashReportsManager(service_provider)
    if flush:
        await crash_manager.flush()
    await crash_manager.clear()


@cli.command("pull")
@async_command
async def crash_pull(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Path,
        typer.Argument(file_okay=False),
    ],
    remote_file: Optional[Path] = None,
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
    if remote_file is None:
        remote_file = Path("/")
    await CrashReportsManager(service_provider).pull(str(out), str(remote_file), erase, match)


@cli.command("shell")
def crash_shell(service_provider: ServiceProviderDep) -> None:
    """start an afc shell"""
    CrashReportsShell.create(service_provider)


@cli.command("ls")
@async_command
async def crash_ls(
    service_provider: ServiceProviderDep,
    remote_file: Optional[Path] = None,
    depth: Annotated[
        int,
        typer.Option("--depth", "-d"),
    ] = 1,
) -> None:
    """List"""
    if remote_file is None:
        remote_file = Path("/")
    for path in await CrashReportsManager(service_provider).ls(str(remote_file), depth):
        print(path)


@cli.command("flush")
@async_command
async def crash_mover_flush(service_provider: ServiceProviderDep) -> None:
    """trigger com.apple.crashreportmover to flush all products into CrashReports directory"""
    await CrashReportsManager(service_provider).flush()


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
    async for crash_report in CrashReportsManager(service_provider).watch(name=name, raw=raw):
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
    await CrashReportsManager(service_provider).get_new_sysdiagnose(str(out), erase=erase, timeout=timeout)
