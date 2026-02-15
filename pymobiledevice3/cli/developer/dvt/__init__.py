import asyncio
import contextlib
import logging
import os
import posixpath
import shlex
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Annotated, NamedTuple, Optional

import typer
from click.exceptions import BadParameter, MissingParameter, UsageError
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json, user_requested_colored_output
from pymobiledevice3.cli.developer.dvt import core_profile_session, simulate_location, sysmon
from pymobiledevice3.exceptions import DvtDirListError, UnrecognizedSelectorError
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.activity_trace_tap import ActivityTraceTap, decode_message_format
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.energy_monitor import EnergyMonitor
from pymobiledevice3.services.dvt.instruments.graphics import Graphics
from pymobiledevice3.services.dvt.instruments.network_monitor import ConnectionDetectionEvent, NetworkMonitor
from pymobiledevice3.services.dvt.instruments.notifications import Notifications
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.services.dvt.testmanaged.xcuitest import XCUITestListener, XCUITestService
from pymobiledevice3.services.remote_server import MessageAux

logger = logging.getLogger(__name__)


class MatchedProcessByPid(NamedTuple):
    name: str
    pid: int


cli = InjectingTyper(
    name="dvt",
    help="Drive DVT instrumentation APIs (process control, metrics, traces).",
    no_args_is_help=True,
)

cli.add_typer(sysmon.cli)
cli.add_typer(core_profile_session.cli)
cli.add_typer(simulate_location.cli)


@cli.command("proclist")
@async_command
async def proclist(service_provider: ServiceProviderDep) -> None:
    """Show processes (with start times) via DVT."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        processes = await DeviceInfo(dvt).proclist()
        for process in processes:
            if "startDate" in process:
                process["startDate"] = str(process["startDate"])

        print_json(processes)


@cli.command("is-running-pid")
@async_command
async def is_running_pid(service_provider: ServiceProviderDep, pid: int) -> None:
    """Check if a PID is currently running."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print_json(await DeviceInfo(dvt).is_running_pid(pid))


@cli.command("memlimitoff")
@async_command
async def memlimitoff(service_provider: ServiceProviderDep, pid: int) -> None:
    """Disable jetsam memory limit for a PID."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        await ProcessControl(dvt).disable_memory_limit_for_pid(pid)


@cli.command("applist")
@async_command
async def applist(service_provider: ServiceProviderDep) -> None:
    """List installed applications via DVT."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        apps = await ApplicationListing(dvt).applist()
        print_json(apps)


class Signals(IntEnum):
    """Platform-independent version of `signal.Signals`, allowing names to be used on Windows."""

    HUP = 1
    INT = 2
    QUIT = 3
    ILL = 4
    TRAP = 5
    ABRT = 6
    EMT = 7
    FPE = 8
    KILL = 9
    BUS = 10
    SEGV = 11
    SYS = 12
    PIPE = 13
    ALRM = 14
    TERM = 15
    URG = 16
    STOP = 17
    TSTP = 18
    CONT = 19
    CHLD = 20
    TTIN = 21
    TTOU = 22
    IO = 23
    XCPU = 24
    XFSZ = 25
    VTALRM = 26
    PROF = 27
    WINCH = 28
    INFO = 29
    USR1 = 30
    USR2 = 31


@cli.command("signal")
@async_command
async def send_signal(
    service_provider: ServiceProviderDep,
    pid: int,
    sig: Annotated[
        Optional[int],
        typer.Argument(),
    ] = None,
    signal_name: Annotated[
        Optional[str],
        typer.Option("--signal-name", "-s"),
    ] = None,
) -> None:
    """Send a signal to a PID (choose numeric SIG or --signal-name)."""
    if sig is not None and signal_name is not None:
        raise UsageError(message="Cannot give SIG and SIGNAL-NAME together")

    if signal_name is not None:
        normalized_signal_name = signal_name.upper().removeprefix("SIG")
        try:
            sig = Signals[normalized_signal_name]
        except KeyError:
            raise BadParameter(f"{signal_name!r} is not a valid signal") from None
    elif sig is not None:
        try:
            sig = Signals(sig)
        except ValueError:
            raise BadParameter(f"{sig} is not a valid signal") from None
    else:
        raise MissingParameter(param_type="argument|option", param_hint="'SIG|SIGNAL-NAME'")

    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        await ProcessControl(dvt).signal(pid, sig)


@cli.command("kill")
@async_command
async def kill(service_provider: ServiceProviderDep, pid: int) -> None:
    """Kill a process by PID."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        await ProcessControl(dvt).kill(pid)


@cli.command()
@async_command
async def process_id_for_bundle_id(service_provider: ServiceProviderDep, app_bundle_identifier: str) -> None:
    """Get PID of a bundle identifier (only returns a valid value if its running)."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print(await ProcessControl(dvt).process_identifier_for_bundle_identifier(app_bundle_identifier))


async def get_matching_processes(
    device_info: DeviceInfo,
    name: Optional[str] = None,
    bundle_identifier: Optional[str] = None,
) -> list[MatchedProcessByPid]:
    result: list[MatchedProcessByPid] = []
    for process in await device_info.proclist():
        current_name = process["name"]
        current_bundle_identifier = process.get("bundleIdentifier", "")
        pid = process["pid"]
        if (bundle_identifier is not None and bundle_identifier in current_bundle_identifier) or (
            name is not None and name in current_name
        ):
            result.append(MatchedProcessByPid(name=current_name, pid=pid))
    return result


@cli.command("pkill")
@async_command
async def pkill(
    service_provider: ServiceProviderDep,
    expressions: Annotated[
        list[str],
        typer.Argument(help="One or more process-name (or bundle id) expressions to match."),
    ],
    bundle: Annotated[
        bool,
        typer.Option(help="Treat given expressions as bundle-identifiers instead of process names"),
    ] = False,
) -> None:
    """Kill all processes containing each expression in their name."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        process_control = ProcessControl(dvt)

        for expression in expressions:
            matching_name = expression if not bundle else None
            matching_bundle_identifier = expression if bundle else None
            matching_processes = await get_matching_processes(
                device_info, name=matching_name, bundle_identifier=matching_bundle_identifier
            )

            for process in matching_processes:
                logger.info(f"Killing {process.name}({process.pid})")
                await process_control.kill(process.pid)


@cli.command("launch")
@async_command
async def launch(
    service_provider: ServiceProviderDep,
    arguments: str,
    kill_existing: Annotated[
        bool,
        typer.Option(help="Whether to kill an existing instance of this process"),
    ] = True,
    suspended: Annotated[
        bool,
        typer.Option(help="Same as WaitForDebugger"),
    ] = False,
    env: Annotated[
        Optional[list[str]],
        typer.Option(
            help="Environment variable to pass to process given as key=value (can be specified multiple times)"
        ),
    ] = None,
    stream: bool = False,
) -> None:
    """Launch a process."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        parsed_arguments = shlex.split(arguments)
        process_control = ProcessControl(dvt)
        pid = await process_control.launch(
            bundle_id=parsed_arguments[0],
            arguments=parsed_arguments[1:],
            kill_existing=kill_existing,
            start_suspended=suspended,
            environment=dict(var.split("=", 1) for var in env or ()),
        )
        print(f"Process launched with pid {pid}")
        if stream:
            async for output_received in process_control:
                logging.getLogger(f"PID:{output_received.pid}").info(output_received.message.strip())


@cli.command("shell")
def dvt_shell(service_provider: ServiceProviderDep) -> None:
    """Launch developer shell (used for pymobiledevice3 R&D)"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        dvt.shell()


async def show_dirlist(channel, dirname: str, recursive: bool = False) -> None:
    try:
        await channel.directoryListingForPath_(MessageAux().append_obj(dirname))
        filenames = await channel.receive_plist()
        if filenames is None:
            raise DvtDirListError()
    except DvtDirListError:
        return

    for filename in filenames:
        filename = posixpath.join(dirname, filename)
        print(filename)
        if recursive:
            await show_dirlist(channel, filename, recursive=recursive)


@cli.command("ls")
@async_command
async def ls(
    service_provider: ServiceProviderDep,
    path: Path,
    recursive: Annotated[
        bool,
        typer.Option("--recursive", "-r"),
    ] = False,
) -> None:
    """List directory"""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        channel = await dvt.make_channel(DeviceInfo.IDENTIFIER)
        await show_dirlist(channel, str(path), recursive=recursive)


@cli.command("device-information")
@async_command
async def device_information(service_provider: ServiceProviderDep) -> None:
    """Print system information"""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        info = {
            "hardware": await device_info.hardware_information(),
            "network": await device_info.network_information(),
            "kernel-name": await device_info.mach_kernel_name(),
            "kpep-database": await device_info.kpep_database(),
        }
        with contextlib.suppress(UnrecognizedSelectorError):
            info["system"] = await device_info.system_information()
        print_json(info)


@cli.command("netstat")
@async_command
async def netstat(service_provider: ServiceProviderDep) -> None:
    """Print information about current network activity."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, NetworkMonitor(dvt) as monitor:
        async for event in monitor:
            if isinstance(event, ConnectionDetectionEvent):
                logger.info(
                    f"Connection detected: {event.local_address.data.address}:{event.local_address.port} -> "
                    f"{event.remote_address.data.address}:{event.remote_address.port}"
                )


@cli.command("screenshot")
@async_command
async def dvt_screenshot(service_provider: ServiceProviderDep, out: Path) -> None:
    """Take device screenshot"""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        out.write_bytes(await Screenshot(dvt).get_screenshot())


@cli.command("xcuitest")
@async_command
async def xcuitest(
    service_provider: ServiceProviderDep,
    bundle_id: str,
    output_log: Annotated[
        Optional[Path],
        typer.Option(help="log debug output file location ( default to python logger )"),
    ] = None,
    timeout: Annotated[
        Optional[float],
        typer.Option(help="maximum execution time, in seconds"),
    ] = None,
    env: Annotated[
        Optional[list[str]],
        typer.Option(
            help="Environment variable to pass to process given as key=value (can be specified multiple times)"
        ),
    ] = None,
) -> None:
    """
    Start XCUITest

    \b
    Usage example:
    \b    python3 -m pymobiledevice3 developer dvt xcuitest com.facebook.WebDriverAgentRunner.xctrunner
    """
    s = XCUITestService(service_provider)
    consumer = await s.start(bundle_id, test_runner_env=dict(var.split("=", 1) for var in env or ()))

    async def stop_consumer_safely() -> None:
        try:
            await consumer.stop()
        except RuntimeError as e:
            if "no running event loop" not in str(e):
                raise
            logger.debug("Skipping consumer stop during event-loop teardown")

    if output_log is not None:

        class MyListener(XCUITestListener):
            def logDebugMessage_(self, args):
                output_log.write_text(args[0].value)

        consumer.set_listener(MyListener(consumer.main_dvt, consumer.main_chan, consumer.xctest_config))
    try:
        if timeout is not None:
            await asyncio.wait_for(consumer.consume(), timeout=timeout)
        else:
            await consumer.consume()
    except asyncio.TimeoutError:
        logger.warning("consumer task timed out, exiting")
        await stop_consumer_safely()
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("xcuitest interrupted, exiting")
        await stop_consumer_safely()
        raise


@cli.command("trace-codes")
@async_command
async def dvt_trace_codes(service_provider: ServiceProviderDep) -> None:
    """Print KDebug trace codes."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        print_json({hex(k): v for k, v in (await device_info.trace_codes()).items()})


@cli.command("name-for-uid")
@async_command
async def dvt_name_for_uid(service_provider: ServiceProviderDep, uid: int) -> None:
    """Print the assiciated username for the given uid."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        print(await device_info.name_for_uid(uid))


@cli.command("name-for-gid")
@async_command
async def dvt_name_for_gid(service_provider: ServiceProviderDep, gid: int) -> None:
    """Print the assiciated group name for the given gid."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        print(await device_info.name_for_gid(gid))


@cli.command("oslog")
def dvt_oslog(service_provider: ServiceProviderDep, pid: int) -> None:
    """Sniff device oslog (not very stable, but includes more data and normal syslog)"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, ActivityTraceTap(dvt) as tap:
        for message in tap:
            message_pid = message.process
            # without message_type maybe signpost have event_type
            message_type = (
                message.message_type
                if hasattr(message, "message_type")
                else message.event_type
                if hasattr(message, "event_type")
                else "unknown"
            )
            sender_image_path = message.sender_image_path
            image_name = os.path.basename(sender_image_path)
            subsystem = message.subsystem
            category = message.category
            timestamp = datetime.now()

            if pid is not None and message_pid != pid:
                continue

            formatted_message = decode_message_format(message.message) if message.message else message.name

            if user_requested_colored_output():
                timestamp = typer.style(str(timestamp), bold=True)
                message_pid = typer.style(str(message_pid), "magenta")
                subsystem = typer.style(subsystem, "green")
                category = typer.style(category, "green")
                image_name = typer.style(image_name, "yellow")
                message_type = typer.style(message_type, "cyan")

            print(
                f"[{timestamp}][{subsystem}][{category}][{message_pid}][{image_name}] "
                f"<{message_type}>: {formatted_message}"
            )


@cli.command("energy")
@async_command
async def dvt_energy(service_provider: ServiceProviderDep, pid_list: list[str]) -> None:
    """Monitor the energy consumption for given PIDs"""

    if len(pid_list) == 0:
        logger.error("pid_list must not be empty")
        return

    pid_int_list = [int(pid) for pid in pid_list]

    async with (
        DvtSecureSocketProxyService(lockdown=service_provider) as dvt,
        EnergyMonitor(dvt, pid_int_list) as energy_monitor,
    ):
        async for telemetry in energy_monitor:
            logger.info(telemetry)


@cli.command("notifications")
def dvt_notifications(service_provider: ServiceProviderDep) -> None:
    """Monitor memory and app notifications"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, Notifications(dvt) as notifications:
        for notification in notifications:
            logger.info(notification)


@cli.command("graphics")
@async_command
async def dvt_graphics(service_provider: ServiceProviderDep) -> None:
    """Monitor graphics-related information"""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, Graphics(dvt) as graphics:
        async for stats in graphics:
            logger.info(stats)


@cli.command("har")
def dvt_har(service_provider: ServiceProviderDep) -> None:
    """
    Enable har-logging

    \b
    For more information, please read:
    \b    https://github.com/doronz88/harlogger?tab=readme-ov-file#enable-http-instrumentation-method
    """
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print("> Press Ctrl-C to abort")
        with ActivityTraceTap(dvt, enable_http_archive_logging=True) as tap:
            while True:
                tap.channel.receive_message()
