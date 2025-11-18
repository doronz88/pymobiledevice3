import asyncio
import contextlib
import json
import logging
import os
import plistlib
import posixpath
import shlex
import signal
import struct
import subprocess
import sys
import time
from collections import namedtuple
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import IO, Optional

import click
from click.exceptions import MissingParameter, UsageError
from ipsw_parser.dsc import create_device_support_layout, get_device_support_path
from packaging.version import Version
from plumbum import local
from pykdebugparser.pykdebugparser import PyKdebugParser

import pymobiledevice3
from pymobiledevice3.cli.cli_common import (
    BASED_INT,
    Command,
    RSDCommand,
    default_json_encoder,
    print_json,
    user_requested_colored_output,
)
from pymobiledevice3.exceptions import (
    DeviceAlreadyInUseError,
    DvtDirListError,
    ExtractingStackshotError,
    RSDRequiredError,
    UnrecognizedSelectorError,
)
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService
from pymobiledevice3.remote.core_device.diagnostics_service import DiagnosticsServiceService
from pymobiledevice3.remote.core_device.file_service import APPLE_DOMAIN_DICT, FileServiceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit
from pymobiledevice3.services.crash_reports import CrashReportsManager
from pymobiledevice3.services.debugserver_applist import DebugServerAppList
from pymobiledevice3.services.device_arbitration import DtDeviceArbitration
from pymobiledevice3.services.dtfetchsymbols import DtFetchSymbols
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.activity_trace_tap import ActivityTraceTap, decode_message_format
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.energy_monitor import EnergyMonitor
from pymobiledevice3.services.dvt.instruments.graphics import Graphics
from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation
from pymobiledevice3.services.dvt.instruments.network_monitor import ConnectionDetectionEvent, NetworkMonitor
from pymobiledevice3.services.dvt.instruments.notifications import Notifications
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
from pymobiledevice3.services.dvt.testmanaged.xcuitest import XCUITestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.remote_fetch_symbols import RemoteFetchSymbolsService
from pymobiledevice3.services.remote_server import RemoteServer
from pymobiledevice3.services.screenshot import ScreenshotService
from pymobiledevice3.services.simulate_location import DtSimulateLocation
from pymobiledevice3.tcp_forwarder import LockdownTcpForwarder
from pymobiledevice3.utils import try_decode

OSUTILS = get_os_utils()
BSC_SUBCLASS = 0x40C
BSC_CLASS = 0x4
VFS_AND_TRACES_SET = {0x03010000, 0x07FF0000}
DEBUGSERVER_CONNECTION_STEPS = """
Follow the following connections steps from LLDB:

(lldb) platform select remote-ios
(lldb) target create /path/to/local/application.app
(lldb) script lldb.target.module[0].SetPlatformFileSpec(lldb.SBFileSpec('/private/var/containers/Bundle/Application/<APP-UUID>/application.app'))
(lldb) process connect connect://[{host}]:{port}   <-- ACTUAL CONNECTION DETAILS!
(lldb) process launch
"""

MatchedProcessByPid = namedtuple("MatchedProcess", "name pid")

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group()
def developer() -> None:
    """
    Perform developer operations (Requires enable of Developer-Mode)

    These options require the DeveloperDiskImage.dmg to be mounted on the device prior
    to execution. You can achieve this using:

    pymobiledevice3 mounter mount

    Also, starting at iOS 17.0, a tunnel must be created to the device for the services
    to be accessible. Therefore, every CLI command is retried with a `--tunnel` option
    for implicitly accessing tunneld when necessary
    """
    pass


@developer.command("shell", cls=Command)
@click.argument("service")
@click.option("-r", "--remove-ssl-context", is_flag=True)
def developer_shell(service_provider: LockdownClient, service, remove_ssl_context):
    """Launch developer IPython shell (used for pymobiledevice3 R&D)"""
    with RemoteServer(service_provider, service, remove_ssl_context) as service:
        service.shell()


@developer.group()
def dvt() -> None:
    """Access advanced instrumentation APIs"""
    pass


@dvt.command("proclist", cls=Command)
def proclist(service_provider: LockdownClient) -> None:
    """Show process list"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        processes = DeviceInfo(dvt).proclist()
        for process in processes:
            if "startDate" in process:
                process["startDate"] = str(process["startDate"])

        print_json(processes)


@dvt.command("is-running-pid", cls=Command)
@click.argument("pid", type=click.INT)
def is_running_pid(service_provider: LockdownClient, pid: int) -> None:
    """Simple check if PID is running"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print_json(DeviceInfo(dvt).is_running_pid(pid))


@dvt.command("memlimitoff", cls=Command)
@click.argument("pid", type=click.INT)
def memlimitoff(service_provider: LockdownServiceProvider, pid: int) -> None:
    """Disable process memory limit"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        ProcessControl(dvt).disable_memory_limit_for_pid(pid)


@dvt.command("applist", cls=Command)
def applist(service_provider: LockdownServiceProvider) -> None:
    """Show application list"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        apps = ApplicationListing(dvt).applist()
        print_json(apps)


@dvt.command("signal", cls=Command)
@click.argument("pid", type=click.INT)
@click.argument("sig", type=click.INT, required=False)
@click.option("-s", "--signal-name", type=click.Choice([s.name for s in signal.Signals]))
def send_signal(service_provider, pid, sig, signal_name) -> None:
    """Send a signal to process by its PID"""
    if not sig and not signal_name:
        raise MissingParameter(param_type="argument|option", param_hint="'SIG|SIGNAL-NAME'")
    if sig and signal_name:
        raise UsageError(message="Cannot give SIG and SIGNAL-NAME together")
    sig = sig or signal.Signals[signal_name].value
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        ProcessControl(dvt).signal(pid, sig)


@dvt.command("kill", cls=Command)
@click.argument("pid", type=click.INT)
def kill(service_provider: LockdownClient, pid) -> None:
    """Kill a process by its pid."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        ProcessControl(dvt).kill(pid)


@dvt.command(cls=Command)
@click.argument("app_bundle_identifier")
def process_id_for_bundle_id(service_provider: LockdownServiceProvider, app_bundle_identifier: str) -> None:
    """Get PID of a bundle identifier (only returns a valid value if its running)."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print(ProcessControl(dvt).process_identifier_for_bundle_identifier(app_bundle_identifier))


def get_matching_processes(
    service_provider: LockdownServiceProvider, name: Optional[str] = None, bundle_identifier: Optional[str] = None
) -> list[MatchedProcessByPid]:
    result = []
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        for process in device_info.proclist():
            current_name = process.get("name")
            current_bundle_identifier = process.get("bundleIdentifier", "")
            pid = process["pid"]
            if (bundle_identifier is not None and bundle_identifier in current_bundle_identifier) or (
                name is not None and name in current_name
            ):
                result.append(MatchedProcessByPid(name=current_name, pid=pid))
    return result


@dvt.command("pkill", cls=Command)
@click.argument("expression")
@click.option("--bundle", is_flag=True, help="Treat given expression as a bundle-identifier instead of a process name")
def pkill(service_provider: LockdownServiceProvider, expression: str, bundle: False) -> None:
    """kill all processes containing `expression` in their name."""
    matching_name = expression if not bundle else None
    matching_bundle_identifier = expression if bundle else None
    matching_processes = get_matching_processes(
        service_provider, name=matching_name, bundle_identifier=matching_bundle_identifier
    )

    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        process_control = ProcessControl(dvt)

        for process in matching_processes:
            logger.info(f"killing {process.name}({process.pid})")
            process_control.kill(process.pid)


@dvt.command("launch", cls=Command)
@click.argument("arguments", type=click.STRING)
@click.option(
    "--kill-existing/--no-kill-existing", default=True, help="Whether to kill an existing instance of this process"
)
@click.option("--suspended", is_flag=True, help="Same as WaitForDebugger")
@click.option(
    "--env",
    multiple=True,
    type=click.Tuple((str, str)),
    help="Environment variables to pass to process given as a list of key value",
)
@click.option("--stream", is_flag=True)
def launch(
    service_provider: LockdownClient, arguments: str, kill_existing: bool, suspended: bool, env: tuple, stream: bool
) -> None:
    """Launch a process."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        parsed_arguments = shlex.split(arguments)
        process_control = ProcessControl(dvt)
        pid = process_control.launch(
            bundle_id=parsed_arguments[0],
            arguments=parsed_arguments[1:],
            kill_existing=kill_existing,
            start_suspended=suspended,
            environment=dict(env),
        )
        print(f"Process launched with pid {pid}")
        while stream:
            for output_received in process_control:
                logging.getLogger(f"PID:{output_received.pid}").info(output_received.message.strip())


@dvt.command("shell", cls=Command)
def dvt_shell(service_provider: LockdownClient):
    """Launch developer shell (used for pymobiledevice3 R&D)"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        dvt.shell()


def show_dirlist(device_info: DeviceInfo, dirname, recursive=False):
    try:
        filenames = device_info.ls(dirname)
    except DvtDirListError:
        return

    for filename in filenames:
        filename = posixpath.join(dirname, filename)
        print(filename)
        if recursive:
            show_dirlist(device_info, filename, recursive=recursive)


@dvt.command("ls", cls=Command)
@click.argument("path", type=click.Path(exists=False, readable=False))
@click.option("-r", "--recursive", is_flag=True)
def ls(service_provider: LockdownClient, path, recursive):
    """List directory"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        show_dirlist(DeviceInfo(dvt), path, recursive=recursive)


@dvt.command("device-information", cls=Command)
def device_information(service_provider: LockdownClient):
    """Print system information"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        info = {
            "hardware": device_info.hardware_information(),
            "network": device_info.network_information(),
            "kernel-name": device_info.mach_kernel_name(),
            "kpep-database": device_info.kpep_database(),
        }
        with contextlib.suppress(UnrecognizedSelectorError):
            info["system"] = device_info.system_information()
        print_json(info)


@dvt.command("netstat", cls=Command)
def netstat(service_provider: LockdownClient):
    """Print information about current network activity."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, NetworkMonitor(dvt) as monitor:
        for event in monitor:
            if isinstance(event, ConnectionDetectionEvent):
                logger.info(
                    f"Connection detected: {event.local_address.data.address}:{event.local_address.port} -> "
                    f"{event.remote_address.data.address}:{event.remote_address.port}"
                )


@dvt.command("screenshot", cls=Command)
@click.argument("out", type=click.File("wb"))
def dvt_screenshot(service_provider: LockdownClient, out):
    """Take device screenshot"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        out.write(Screenshot(dvt).get_screenshot())


@dvt.command("xcuitest", cls=Command)
@click.argument("bundle-id")
def xcuitest(service_provider: LockdownClient, bundle_id: str) -> None:
    """\b
    Start XCUITest

    Usage example:
        python3 -m pymobiledevice3 developer dvt xcuitest com.facebook.WebDriverAgentRunner.xctrunner
    """
    XCUITestService(service_provider).run(bundle_id)


@dvt.group("sysmon")
def sysmon():
    """System monitor options."""


@sysmon.group("process")
def sysmon_process():
    """Process monitor options."""


@sysmon_process.command("monitor", cls=Command)
@click.argument("threshold", type=click.FLOAT)
def sysmon_process_monitor(service_provider: LockdownClient, threshold):
    """monitor all most consuming processes by given cpuUsage threshold."""

    Process = namedtuple("process", "pid name cpuUsage physFootprint")

    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, Sysmontap(dvt) as sysmon:
        for process_snapshot in sysmon.iter_processes():
            entries = []
            for process in process_snapshot:
                if (process["cpuUsage"] is not None) and (process["cpuUsage"] >= threshold):
                    entries.append(
                        Process(
                            pid=process["pid"],
                            name=process["name"],
                            cpuUsage=process["cpuUsage"],
                            physFootprint=process["physFootprint"],
                        )
                    )

            logger.info(entries)


@sysmon_process.command("single", cls=Command)
@click.option("-a", "--attributes", multiple=True, help="filter processes by given attribute value given as key=value")
def sysmon_process_single(service_provider: LockdownClient, attributes: list[str]):
    """show a single snapshot of currently running processes."""

    count = 0

    result = []
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)

        with Sysmontap(dvt) as sysmon:
            for process_snapshot in sysmon.iter_processes():
                count += 1

                if count < 2:
                    # first sample doesn't contain an initialized value for cpuUsage
                    continue

                for process in process_snapshot:
                    skip = False
                    if attributes is not None:
                        for filter_attr in attributes:
                            filter_attr, filter_value = filter_attr.split("=")
                            if str(process[filter_attr]) != filter_value:
                                skip = True
                                break

                    if skip:
                        continue

                    # adding "artificially" the execName field
                    process["execName"] = device_info.execname_for_pid(process["pid"])
                    result.append(process)

                # exit after single snapshot
                break
    print_json(result)


@sysmon.command("system", cls=Command)
@click.option("-f", "--fields", help='field names splitted by ",".')
def sysmon_system(service_provider: LockdownClient, fields):
    """show current system stats."""

    if fields is not None:
        fields = fields.split(",")

    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        sysmontap = Sysmontap(dvt)
        with sysmontap as sysmon:
            system = None
            system_usage = None
            system_usage_seen = False  # Tracks if the first occurrence of SystemCPUUsage

            for row in sysmon:
                if "System" in row and system is None:
                    system = sysmon.system_attributes_cls(*row["System"])

                if "SystemCPUUsage" in row:
                    if system_usage_seen:
                        system_usage = {
                            **row["SystemCPUUsage"],
                            **{
                                "CPUCount": row["CPUCount"],
                                "EnabledCPUs": row["EnabledCPUs"],
                            },
                        }
                    else:  # Ignore the first occurrence because first occurrence always gives a incorrect value - 100 or 0
                        system_usage_seen = True

                if system and system_usage:
                    break

    attrs_dict = {**asdict(system), **system_usage}
    for name, value in attrs_dict.items():
        if (fields is None) or (name in fields):
            print(f"{name}: {value}")


@dvt.group("core-profile-session")
def core_profile_session():
    """Access tailspin features"""


bsc_filter = click.option("--bsc/--no-bsc", default=False, help="Whether to print BSC events or not.")
class_filter = click.option(
    "-cf", "--class-filters", multiple=True, type=BASED_INT, help="Events class filter. Omit for all."
)
subclass_filter = click.option(
    "-sf", "--subclass-filters", multiple=True, type=BASED_INT, help="Events subclass filter. Omit for all."
)


def parse_filters(subclasses: list[int], classes: list[int]):
    if not subclasses and not classes:
        return None
    parsed = set()
    for subclass in subclasses:
        if subclass == BSC_SUBCLASS:
            parsed |= VFS_AND_TRACES_SET
        parsed.add(subclass << 16)
    for class_ in classes:
        if class_ == BSC_CLASS:
            parsed |= VFS_AND_TRACES_SET
        parsed.add((class_ << 24) | 0x00FF0000)
    return parsed


@core_profile_session.command("live", cls=Command)
@click.option("-c", "--count", type=click.INT, default=-1, help="Number of events to print. Omit to endless sniff.")
@bsc_filter
@class_filter
@subclass_filter
@click.option("--tid", type=click.INT, default=None, help="Thread ID to filter. Omit for all.")
@click.option("--timestamp/--no-timestamp", default=True, help="Whether to print timestamp or not.")
@click.option("--event-name/--no-event-name", default=True, help="Whether to print event name or not.")
@click.option("--func-qual/--no-func-qual", default=True, help="Whether to print function qualifier or not.")
@click.option("--show-tid/--no-show-tid", default=True, help="Whether to print thread id or not.")
@click.option("--process-name/--no-process-name", default=True, help="Whether to print process name or not.")
@click.option("--args/--no-args", default=True, help="Whether to print event arguments or not.")
def live_profile_session(
    service_provider: LockdownClient,
    count,
    bsc,
    class_filters,
    subclass_filters,
    tid,
    timestamp,
    event_name,
    func_qual,
    show_tid,
    process_name,
    args,
):
    """Print kevents received from the device in real time."""

    parser = PyKdebugParser()
    parser.filter_class = class_filters
    if bsc:
        subclass_filters = [*list(subclass_filters), BSC_SUBCLASS]
    parser.filter_subclass = subclass_filters
    filters = parse_filters(subclass_filters, class_filters)
    parser.filter_tid = tid
    parser.show_timestamp = timestamp
    parser.show_name = event_name
    parser.show_func_qual = func_qual
    parser.show_tid = show_tid
    parser.show_process = process_name
    parser.show_args = args
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()
        time_config = CoreProfileSessionTap.get_time_config(dvt)
        parser.numer = time_config["numer"]
        parser.denom = time_config["denom"]
        parser.mach_absolute_time = time_config["mach_absolute_time"]
        parser.usecs_since_epoch = time_config["usecs_since_epoch"]
        parser.timezone = time_config["timezone"]
        with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            for i, event in enumerate(parser.formatted_kevents(tap.get_kdbuf_stream(), trace_codes_map)):
                print(event)
                if i == count:
                    break


@core_profile_session.command("save", cls=Command)
@click.argument("out", type=click.File("wb"))
@bsc_filter
@class_filter
@subclass_filter
def save_profile_session(service_provider: LockdownClient, out, bsc, class_filters, subclass_filters):
    """Dump core profiling information."""
    if bsc:
        subclass_filters = [*list(subclass_filters), BSC_SUBCLASS]
    filters = parse_filters(subclass_filters, class_filters)
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, CoreProfileSessionTap(dvt, {}, filters) as tap:
        tap.dump(out)


@core_profile_session.command("stackshot", cls=Command)
@click.option("--out", type=click.File("w"), default=None)
def stackshot(service_provider: LockdownClient, out):
    """Dump stackshot information."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, CoreProfileSessionTap(dvt, {}) as tap:
        try:
            data = tap.get_stackshot()
        except ExtractingStackshotError:
            logger.exception("Extracting stackshot failed")
            return

        if out is not None:
            json.dump(data, out, indent=4, default=default_json_encoder)
        else:
            print_json(data)


@core_profile_session.command("parse-live", cls=Command)
@click.option("-c", "--count", type=click.INT, default=-1, help="Number of events to print. Omit to endless sniff.")
@click.option("--tid", type=click.INT, default=None, help="Thread ID to filter. Omit for all.")
@click.option("--show-tid/--no-show-tid", default=False, help="Whether to print thread id or not.")
@bsc_filter
@class_filter
@subclass_filter
@click.option("--process", default=None, help="Process ID / name to filter. Omit for all.")
def parse_live_profile_session(
    service_provider: LockdownClient, count, tid, show_tid, bsc, class_filters, subclass_filters, process
):
    """Print traces (syscalls, thread events, etc.) received from the device in real time."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print("Receiving time information")
        time_config = CoreProfileSessionTap.get_time_config(dvt)
        parser = PyKdebugParser()
        parser.filter_class = list(class_filters)
        if bsc:
            subclass_filters = [*list(subclass_filters), BSC_SUBCLASS]
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
        parser.color = user_requested_colored_output()

        with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            if show_tid:
                print("{:^32}|{:^11}|{:^33}|   Event".format("Time", "Thread", "Process"))
            else:
                print("{:^32}|{:^33}|   Event".format("Time", "Process"))

            for i, trace in enumerate(parser.formatted_traces(tap.get_kdbuf_stream())):
                print(trace, flush=True)
                if i == count:
                    break


def get_image_name(dsc_uuid_map, image_uuid, current_dsc_map):
    if not current_dsc_map:
        for dsc_mapping in dsc_uuid_map.values():
            if image_uuid in dsc_mapping:
                current_dsc_map.update(dsc_mapping)

    return current_dsc_map.get(image_uuid, image_uuid)


def format_callstack(callstack, dsc_uuid_map, current_dsc_map):
    lines = callstack.splitlines()
    for i, line in enumerate(lines[1:]):
        if ":" in line:
            uuid = line.split(":")[0].strip()
            lines[i + 1] = line.replace(uuid, get_image_name(dsc_uuid_map, uuid, current_dsc_map))
    return "\n".join(lines)


@core_profile_session.command("callstacks-live", cls=Command)
@click.option("-c", "--count", type=click.INT, default=-1, help="Number of events to print. Omit to endless sniff.")
@click.option("--process", default=None, help="Process to filter. Omit for all.")
@click.option("--tid", type=click.INT, default=None, help="Thread ID to filter. Omit for all.")
@click.option("--show-tid/--no-show-tid", default=False, help="Whether to print thread id or not.")
def callstacks_live_profile_session(service_provider: LockdownClient, count, process, tid, show_tid):
    """Print callstacks received from the device in real time."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print("Receiving time information")
        time_config = CoreProfileSessionTap.get_time_config(dvt)
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

        with open(os.path.join(pymobiledevice3.__path__[0], "resources", "dsc_uuid_map.json")) as fd:
            dsc_uuid_map = json.load(fd)

        current_dsc_map = {}
        with CoreProfileSessionTap(dvt, time_config) as tap:
            for i, callstack in enumerate(parser.formatted_callstacks(tap.get_kdbuf_stream())):
                print(format_callstack(callstack, dsc_uuid_map, current_dsc_map))
                if i == count:
                    break


@dvt.command("trace-codes", cls=Command)
def dvt_trace_codes(service_provider: LockdownClient):
    """Print KDebug trace codes."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        print_json({hex(k): v for k, v in device_info.trace_codes().items()})


@dvt.command("name-for-uid", cls=Command)
@click.argument("uid", type=click.INT)
def dvt_name_for_uid(service_provider: LockdownClient, uid):
    """Print the assiciated username for the given uid."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        print(device_info.name_for_uid(uid))


@dvt.command("name-for-gid", cls=Command)
@click.argument("gid", type=click.INT)
def dvt_name_for_gid(service_provider: LockdownClient, gid):
    """Print the assiciated group name for the given gid."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        device_info = DeviceInfo(dvt)
        print(device_info.name_for_gid(gid))


@dvt.command("oslog", cls=Command)
@click.option("--pid", type=click.INT)
def dvt_oslog(service_provider: LockdownClient, pid):
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
                timestamp = click.style(str(timestamp), bold=True)
                message_pid = click.style(str(message_pid), "magenta")
                subsystem = click.style(subsystem, "green")
                category = click.style(category, "green")
                image_name = click.style(image_name, "yellow")
                message_type = click.style(message_type, "cyan")

            print(
                f"[{timestamp}][{subsystem}][{category}][{message_pid}][{image_name}] "
                f"<{message_type}>: {formatted_message}"
            )


@dvt.command("energy", cls=Command)
@click.argument("pid-list", nargs=-1)
def dvt_energy(service_provider: LockdownClient, pid_list):
    """Monitor the energy consumption for given PIDs"""

    if len(pid_list) == 0:
        logger.error("pid_list must not be empty")
        return

    pid_list = [int(pid) for pid in pid_list]

    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, EnergyMonitor(dvt, pid_list) as energy_monitor:
        for telemetry in energy_monitor:
            logger.info(telemetry)


@dvt.command("notifications", cls=Command)
def dvt_notifications(service_provider: LockdownClient):
    """Monitor memory and app notifications"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, Notifications(dvt) as notifications:
        for notification in notifications:
            logger.info(notification)


@dvt.command("graphics", cls=Command)
def dvt_graphics(service_provider: LockdownClient):
    """Monitor graphics-related information"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, Graphics(dvt) as graphics:
        for stats in graphics:
            logger.info(stats)


@developer.group("fetch-symbols")
def fetch_symbols():
    """Download the DSC (and dyld) from the device"""
    pass


async def fetch_symbols_list_task(service_provider: LockdownServiceProvider) -> None:
    if Version(service_provider.product_version) < Version("17.0"):
        print_json(DtFetchSymbols(service_provider).list_files())
    else:
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            raise RSDRequiredError(service_provider.identifier)

        async with RemoteFetchSymbolsService(service_provider) as fetch_symbols:
            print_json([f.file_path for f in await fetch_symbols.get_dsc_file_list()])


@fetch_symbols.command("list", cls=Command)
def fetch_symbols_list(service_provider: LockdownServiceProvider) -> None:
    """list of files to be downloaded"""
    asyncio.run(fetch_symbols_list_task(service_provider), debug=True)


async def fetch_symbols_download_task(service_provider: LockdownServiceProvider, out: Optional[str]) -> None:
    should_create_device_support_layout = False
    if out is None:
        out = get_device_support_path(
            service_provider.product_type, service_provider.product_version, service_provider.product_build_version
        )
        should_create_device_support_layout = True

    logger.info(f"Downloading DSC into: {out}")

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    if Version(service_provider.product_version) < Version("17.0"):
        fetch_symbols = DtFetchSymbols(service_provider)
        files = fetch_symbols.list_files()

        downloaded_files = set()

        for i, file in enumerate(files):
            if file.startswith("/"):
                # trim root to allow relative download
                file = file[1:]
            file = out / file

            if file not in downloaded_files:
                # first time the file was seen in list, means we can safely remove any old copy if any
                file.unlink(missing_ok=True)

            downloaded_files.add(file)
            file.parent.mkdir(parents=True, exist_ok=True)
            with open(file, "ab") as f:
                # same file may appear twice, so we'll need to append data into it
                logger.info(f"writing to: {file}")
                fetch_symbols.get_file(i, f)
    else:
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            raise RSDRequiredError(service_provider.identifier)
        async with RemoteFetchSymbolsService(service_provider) as fetch_symbols:
            await fetch_symbols.download(out)

    if should_create_device_support_layout:
        create_device_support_layout(
            service_provider.product_type, service_provider.product_version, service_provider.product_build_version, out
        )


@fetch_symbols.command("download", cls=Command)
@click.argument("out", type=click.Path(dir_okay=True, file_okay=False), required=False)
def fetch_symbols_download(service_provider: LockdownServiceProvider, out: Optional[str]) -> None:
    """
    Fetches symbols from the given device and saves them into Xcode DeviceSupport directory.

    This command downloads symbol data. Optionally, the user can specify an output directory where the data will
    be stored. If no output directory is provided, the symbols will be downloaded into the Xcode directory directly
    (DeviceSupport).
    """
    asyncio.run(fetch_symbols_download_task(service_provider, out), debug=True)


@developer.group("simulate-location")
def simulate_location():
    """Simulate device location by given input"""
    pass


@simulate_location.command("clear", cls=Command)
def simulate_location_clear(service_provider: LockdownClient):
    """clear simulated location"""
    DtSimulateLocation(service_provider).clear()


@simulate_location.command("set", cls=Command)
@click.argument("latitude", type=click.FLOAT)
@click.argument("longitude", type=click.FLOAT)
def simulate_location_set(service_provider: LockdownClient, latitude, longitude):
    """
    set a simulated location.
    try:
        ... set -- 40.690008 -74.045843 for liberty island
    """
    DtSimulateLocation(service_provider).set(latitude, longitude)


@simulate_location.command("play", cls=Command)
@click.argument("filename", type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.argument("timing_randomness_range", type=click.INT)
@click.option("--disable-sleep", is_flag=True, default=False)
def simulate_location_play(service_provider: LockdownClient, filename, timing_randomness_range, disable_sleep):
    """play a .gpx file"""
    DtSimulateLocation(service_provider).play_gpx_file(filename, timing_randomness_range, disable_sleep=disable_sleep)


@developer.group("accessibility")
def accessibility():
    """Interact with accessibility-related features"""
    pass


@accessibility.command("run-audit", cls=Command)
@click.argument("test_types", nargs=-1)
def accessibility_run_audit(service_provider: LockdownServiceProvider, test_types):
    """runs accessibility audit tests"""
    param = list(test_types)
    audit_issues = AccessibilityAudit(service_provider).run_audit(param)
    print_json([audit_issue.json() for audit_issue in audit_issues], False)


@accessibility.command("supported-audit-types", cls=Command)
def accessibility_supported_audit_types(service_provider: LockdownServiceProvider):
    """lists supported accessibility audit test types"""
    print_json(AccessibilityAudit(service_provider).supported_audits_types())


@accessibility.command("capabilities", cls=Command)
def accessibility_capabilities(service_provider: LockdownClient):
    """display accessibility capabilities"""
    print_json(AccessibilityAudit(service_provider).capabilities)


@accessibility.group("settings")
def accessibility_settings():
    """accessibility settings."""
    pass


@accessibility_settings.command("show", cls=Command)
def accessibility_settings_show(service_provider: LockdownClient):
    """show current settings"""
    for setting in AccessibilityAudit(service_provider).settings:
        print(setting)


@accessibility_settings.command("set", cls=Command)
@click.argument("setting")
@click.argument("value")
def accessibility_settings_set(service_provider: LockdownClient, setting, value):
    """
    change current settings

    in order to list all available use the "show" command
    """
    service = AccessibilityAudit(service_provider)
    service.set_setting(setting, eval(value))
    OSUTILS.wait_return()


@accessibility_settings.command("reset", cls=Command)
def accessibility_settings_reset(service_provider: LockdownClient):
    """
    reset accessibility settings to default
    """
    service = AccessibilityAudit(service_provider)
    service.reset_settings()


@accessibility.command("shell", cls=Command)
def accessibility_shell(service_provider: LockdownClient):
    """start and ipython accessibility shell"""
    AccessibilityAudit(service_provider).shell()


@accessibility.command("notifications", cls=Command)
def accessibility_notifications(service_provider: LockdownClient):
    """show notifications"""

    service = AccessibilityAudit(service_provider)
    for event in service.iter_events():
        if event.name in (
            "hostAppStateChanged:",
            "hostInspectorCurrentElementChanged:",
        ):
            for focus_item in event.data:
                logger.info(focus_item)


@accessibility.command("list-items", cls=Command)
def accessibility_list_items(service_provider: LockdownClient):
    """List elements available in the currently shown menu."""

    elements = []
    with AccessibilityAudit(service_provider) as service:
        for element in service.iter_elements():
            elements.append(element.to_dict())
    print_json(elements)


@developer.group("condition")
def condition():
    """Force a predefined condition"""
    pass


@condition.command("list", cls=Command)
def condition_list(service_provider: LockdownServiceProvider) -> None:
    """list all available conditions"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print_json(ConditionInducer(dvt).list())


@condition.command("clear", cls=Command)
def condition_clear(service_provider: LockdownClient):
    """clear current condition"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        ConditionInducer(dvt).clear()


@condition.command("set", cls=Command)
@click.argument("profile_identifier")
def condition_set(service_provider: LockdownClient, profile_identifier):
    """set a specific condition"""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        ConditionInducer(dvt).set(profile_identifier)
        OSUTILS.wait_return()


@developer.command(cls=Command)
@click.argument("out", type=click.File("wb"))
def screenshot(service_provider: LockdownClient, out):
    """Take a screenshot in PNG format"""
    out.write(ScreenshotService(lockdown=service_provider).take_screenshot())


@developer.group("debugserver")
def debugserver():
    """Interact with debugserver"""
    pass


@debugserver.command("applist", cls=Command)
def debugserver_applist(service_provider: LockdownClient):
    """Get applist xml"""
    print_json(DebugServerAppList(service_provider).get())


@debugserver.command("start-server", cls=Command)
@click.argument("local_port", type=click.INT, required=False)
def debugserver_start_server(service_provider: LockdownClient, local_port: Optional[int] = None):
    """
    if local_port is provided, start a debugserver at remote listening on a given port locally.
    if local_port is not provided and iOS version >= 17.0 then just print the connect string

    Please note the connection must be done soon afterward using your own lldb client.
    This can be done using the following commands within lldb shell.
    """

    if Version(service_provider.product_version) < Version("17.0"):
        service_name = "com.apple.debugserver.DVTSecureSocketProxy"
    else:
        service_name = "com.apple.internal.dt.remote.debugproxy"

    if local_port is not None:
        print(DEBUGSERVER_CONNECTION_STEPS.format(host="127.0.0.1", port=local_port))
        print("Started port forwarding. Press Ctrl-C to close this shell when done")
        sys.stdout.flush()
        LockdownTcpForwarder(service_provider, local_port, service_name).start()
    elif Version(service_provider.product_version) >= Version("17.0"):
        if not isinstance(service_provider, RemoteServiceDiscoveryService):
            raise RSDRequiredError(service_provider.identifier)
        debugserver_port = service_provider.get_service_port(service_name)
        print(DEBUGSERVER_CONNECTION_STEPS.format(host=service_provider.service.address[0], port=debugserver_port))
    else:
        print("local_port is required for iOS < 17.0")


@debugserver.command("lldb", cls=RSDCommand)
@click.argument("xcodeproj_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("--configuration", default="Debug", help="Usually Release/Debug")
@click.option("--lldb-command", default="lldb")
@click.option("--launch", is_flag=True, default=False, help="Launch the app after connecting to lldb")
@click.option("breakpoints", "-b", "--break", multiple=True, help="Add multiple startup breakpoints")
@click.option("user_commands", "--command", "-c", multiple=True, help="Additional commands to run at startup")
def debugserver_lldb(
    service_provider: LockdownServiceProvider,
    xcodeproj_path: str,
    configuration: str,
    lldb_command: str,
    launch: bool,
    breakpoints: tuple[str],
    user_commands: tuple[str],
) -> None:
    """
    Automate lldb launch for a given xcodeproj.

    \b
    This will:
    - Build the given xcodeproj
    - Install it
    - Start a debugserver attached to it
    - Place breakpoints if given any
    - Launch the application if requested
    - Execute any additional commands if requested
    - Switch to lldb shell
    """
    if Version(service_provider.product_version) < Version("17.0"):
        logger.error("lldb is only supported on iOS >= 17.0")
        return

    commands = []
    xcodeproj_path = Path(xcodeproj_path)
    with local.cwd(xcodeproj_path.parent):
        logger.info(f"Building {xcodeproj_path} for {configuration} configuration")
        local["xcodebuild"]["-configuration", configuration, "build"]()
        local_app = next(iter(Path(f"build/{configuration}-iphoneos").glob("*.app")))
        logger.info(f"Using app: {local_app}")

        info_plist_path = local_app / "Info.plist"
        info_plist = plistlib.loads(info_plist_path.read_bytes())
        bundle_identifier = info_plist["CFBundleIdentifier"]
        logger.info(f"Bundle identifier: {bundle_identifier}")

        commands.append("platform select remote-ios")
        commands.append(f'target create "{local_app.absolute()}"')

        with InstallationProxyService(create_using_usbmux()) as installation_proxy:
            logger.info("Installing app")
            installation_proxy.install_from_local(local_app)
            remote_path = installation_proxy.get_apps(bundle_identifiers=[bundle_identifier])[bundle_identifier]["Path"]
            logger.info(f"Remote path: {remote_path}")

        commands.append(f'script lldb.target.module[0].SetPlatformFileSpec(lldb.SBFileSpec("{remote_path}"))')

        debugserver_port = service_provider.get_service_port("com.apple.internal.dt.remote.debugproxy")

        # Add connection and launch commands
        commands.append(f"process connect connect://[{service_provider.service.address[0]}]:{debugserver_port}")

        for bp in breakpoints:
            commands.append(f'breakpoint set -n "{bp}"')

        if launch:
            commands.append("process launch")

        # Add user commands
        commands += user_commands

        logger.info("Starting lldb with automated setup and connection")

        # Works only on unix-based systems, so keep these imports here
        import fcntl
        import pty
        import select as select_module
        import termios
        import tty

        master, slave = pty.openpty()

        process = None  # Initialize process variable for signal handler

        # Copy terminal size from the current terminal to PTY
        def resize_pty() -> None:
            """Update PTY size to match current terminal size"""
            size = struct.unpack(
                "HHHH", fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0))
            )
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", *size))
            # Send SIGWINCH to the child process to notify it of the resize
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGWINCH)

        # Initial resize
        resize_pty()

        # Set up signal handler for window resize
        def handle_sigwinch(signum, frame):
            resize_pty()

        old_sigwinch_handler = signal.signal(signal.SIGWINCH, handle_sigwinch)

        # Save original terminal settings
        old_tty = termios.tcgetattr(sys.stdin)

        try:
            # Set TERM environment variable to enable colors
            env = os.environ.copy()
            env["TERM"] = os.environ.get("TERM", "xterm-256color")

            process = subprocess.Popen([lldb_command], stdin=slave, stdout=slave, stderr=slave, env=env)
            os.close(slave)

            # Put terminal in raw mode for proper interaction
            tty.setraw(sys.stdin.fileno())
            # Send all commands through stdin
            for command in commands:
                os.write(master, (command + "\n").encode())

            # Now redirect stdin from the terminal to lldb so user can interact
            while True:
                rlist, _, _ = select_module.select([sys.stdin, master], [], [])

                if sys.stdin in rlist:
                    # User typed something
                    data = os.read(sys.stdin.fileno(), 1024)
                    if not data:
                        break
                    os.write(master, data)

                if master in rlist:
                    # lldb has output
                    try:
                        data = os.read(master, 1024)
                        if not data:
                            break
                        os.write(sys.stdout.fileno(), data)
                    except OSError:
                        break
        except (KeyboardInterrupt, OSError):
            pass
        finally:
            # Restore terminal settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
            # Restore original SIGWINCH handler
            signal.signal(signal.SIGWINCH, old_sigwinch_handler)
            os.close(master)
            if process is not None:
                process.terminate()
                process.wait()


@developer.group("arbitration")
def arbitration():
    """Mark/Unmark device as "in-use" """
    pass


@arbitration.command("version", cls=Command)
def version(service_provider: LockdownClient):
    """get arbitration version"""
    with DtDeviceArbitration(service_provider) as device_arbitration:
        print_json(device_arbitration.version)


@arbitration.command("check-in", cls=Command)
@click.argument("hostname")
@click.option("-f", "--force", default=False, is_flag=True)
def check_in(service_provider: LockdownClient, hostname, force):
    """owner check-in"""
    with DtDeviceArbitration(service_provider) as device_arbitration:
        try:
            device_arbitration.check_in(hostname, force=force)
            OSUTILS.wait_return()
        except DeviceAlreadyInUseError as e:
            logger.error(e.message)


@arbitration.command("check-out", cls=Command)
def check_out(service_provider: LockdownClient):
    """owner check-out"""
    with DtDeviceArbitration(service_provider) as device_arbitration:
        device_arbitration.check_out()


@dvt.command("har", cls=Command)
def dvt_har(service_provider: LockdownClient):
    """
    Enable har-logging

    For more information, please read:
        https://github.com/doronz88/harlogger?tab=readme-ov-file#enable-http-instrumentation-method
    """
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print("> Press Ctrl-C to abort")
        with ActivityTraceTap(dvt, enable_http_archive_logging=True) as tap:
            while True:
                tap.channel.receive_message()


@dvt.group("simulate-location")
def dvt_simulate_location():
    """Simulate device location by given input"""
    pass


@dvt_simulate_location.command("clear", cls=Command)
def dvt_simulate_location_clear(service_provider: LockdownClient):
    """Clear currently simulated location"""
    with DvtSecureSocketProxyService(service_provider) as dvt:
        LocationSimulation(dvt).clear()


@dvt_simulate_location.command("set", cls=Command)
@click.argument("latitude", type=click.FLOAT)
@click.argument("longitude", type=click.FLOAT)
def dvt_simulate_location_set(service_provider: LockdownClient, latitude, longitude):
    """
    Set a simulated location.
    For example:
        ... set -- 40.690008 -74.045843 for liberty island
    """
    with DvtSecureSocketProxyService(service_provider) as dvt:
        LocationSimulation(dvt).set(latitude, longitude)
        OSUTILS.wait_return()


@dvt_simulate_location.command("play", cls=Command)
@click.argument("filename", type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.argument("timing_randomness_range", type=click.INT, default=0)
@click.option("--disable-sleep", is_flag=True, default=False)
def dvt_simulate_location_play(
    service_provider: LockdownClient, filename: str, timing_randomness_range: int, disable_sleep: bool
) -> None:
    """Simulate inputs from a given .gpx file"""
    with DvtSecureSocketProxyService(service_provider) as dvt:
        LocationSimulation(dvt).play_gpx_file(
            filename, disable_sleep=disable_sleep, timing_randomness_range=timing_randomness_range
        )
        OSUTILS.wait_return()


@developer.group()
def core_device() -> None:
    """Access features exposed by the DeveloperDiskImage"""
    pass


async def core_device_list_directory_task(
    service_provider: RemoteServiceDiscoveryService, domain: str, path: str, identifier: str
) -> None:
    async with FileServiceService(service_provider, APPLE_DOMAIN_DICT[domain], identifier) as file_service:
        print_json(await file_service.retrieve_directory_list(path))


@core_device.command("list-directory", cls=RSDCommand)
@click.argument("domain", type=click.Choice(APPLE_DOMAIN_DICT.keys()))
@click.argument("path")
@click.option("--identifier", default="")
def core_device_list_directory(
    service_provider: RemoteServiceDiscoveryService, domain: str, path: str, identifier: str
) -> None:
    """List directory at given domain-path"""
    asyncio.run(core_device_list_directory_task(service_provider, domain, path, identifier))


async def core_device_read_file_task(
    service_provider: RemoteServiceDiscoveryService, domain: str, path: str, identifier: str, output: Optional[IO]
) -> None:
    async with FileServiceService(service_provider, APPLE_DOMAIN_DICT[domain], identifier) as file_service:
        buf = await file_service.retrieve_file(path)
        if output is not None:
            output.write(buf)
        else:
            print(try_decode(buf))


@core_device.command("read-file", cls=RSDCommand)
@click.argument("domain", type=click.Choice(APPLE_DOMAIN_DICT.keys()))
@click.argument("path")
@click.option("--identifier", default="")
@click.option("-o", "--output", type=click.File("wb"))
def core_device_read_file(
    service_provider: RemoteServiceDiscoveryService, domain: str, path: str, identifier: str, output: Optional[IO]
) -> None:
    """Read file from given domain-path"""
    asyncio.run(core_device_read_file_task(service_provider, domain, path, identifier, output))


async def core_device_propose_empty_file_task(
    service_provider: RemoteServiceDiscoveryService,
    domain: str,
    path: str,
    identifier: str,
    file_permissions: int,
    uid: int,
    gid: int,
    creation_time: int,
    last_modification_time: int,
) -> None:
    async with FileServiceService(service_provider, APPLE_DOMAIN_DICT[domain], identifier) as file_service:
        await file_service.propose_empty_file(path, file_permissions, uid, gid, creation_time, last_modification_time)


@core_device.command("propose-empty-file", cls=RSDCommand)
@click.argument("domain", type=click.Choice(APPLE_DOMAIN_DICT.keys()))
@click.argument("path")
@click.option("--identifier", default="")
@click.option("--file-permissions", type=click.INT, default=0o644)
@click.option("--uid", type=click.INT, default=501)
@click.option("--gid", type=click.INT, default=501)
@click.option("--creation-time", type=click.INT, default=time.time())
@click.option("--last-modification-time", type=click.INT, default=time.time())
def core_device_propose_empty_file(
    service_provider: RemoteServiceDiscoveryService,
    domain: str,
    path: str,
    identifier: str,
    file_permissions: int,
    uid: int,
    gid: int,
    creation_time: int,
    last_modification_time: int,
) -> None:
    """Write an empty file to given domain-path"""
    asyncio.run(
        core_device_propose_empty_file_task(
            service_provider,
            domain,
            path,
            identifier,
            file_permissions,
            uid,
            gid,
            creation_time,
            last_modification_time,
        )
    )


async def core_device_list_launch_application_task(
    service_provider: RemoteServiceDiscoveryService,
    bundle_identifier: str,
    argument: list[str],
    kill_existing: bool,
    suspended: bool,
    env: list[tuple[str, str]],
) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(
            await app_service.launch_application(bundle_identifier, argument, kill_existing, suspended, dict(env))
        )


@core_device.command("launch-application", cls=RSDCommand)
@click.argument("bundle_identifier")
@click.argument("argument", nargs=-1)
@click.option(
    "--kill-existing/--no-kill-existing", default=True, help="Whether to kill an existing instance of this process"
)
@click.option("--suspended", is_flag=True, help="Same as WaitForDebugger")
@click.option(
    "--env",
    multiple=True,
    type=click.Tuple((str, str)),
    help="Environment variables to pass to process given as a list of key value",
)
def core_device_launch_application(
    service_provider: RemoteServiceDiscoveryService,
    bundle_identifier: str,
    argument: tuple[str],
    kill_existing: bool,
    suspended: bool,
    env: list[tuple[str, str]],
) -> None:
    """Launch application"""
    asyncio.run(
        core_device_list_launch_application_task(
            service_provider, bundle_identifier, list(argument), kill_existing, suspended, env
        )
    )


async def core_device_list_processes_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.list_processes())


@core_device.command("list-processes", cls=RSDCommand)
def core_device_list_processes(service_provider: RemoteServiceDiscoveryService) -> None:
    """Get process list"""
    asyncio.run(core_device_list_processes_task(service_provider))


async def core_device_uninstall_app_task(
    service_provider: RemoteServiceDiscoveryService, bundle_identifier: str
) -> None:
    async with AppServiceService(service_provider) as app_service:
        await app_service.uninstall_app(bundle_identifier)


@core_device.command("uninstall", cls=RSDCommand)
@click.argument("bundle_identifier")
def core_device_uninstall_app(service_provider: RemoteServiceDiscoveryService, bundle_identifier: str) -> None:
    """Uninstall application"""
    asyncio.run(core_device_uninstall_app_task(service_provider, bundle_identifier))


async def core_device_send_signal_to_process_task(
    service_provider: RemoteServiceDiscoveryService, pid: int, signal: int
) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.send_signal_to_process(pid, signal))


@core_device.command("send-signal-to-process", cls=RSDCommand)
@click.argument("pid", type=click.INT)
@click.argument("signal", type=click.INT)
def core_device_send_signal_to_process(service_provider: RemoteServiceDiscoveryService, pid: int, signal: int) -> None:
    """Send signal to process"""
    asyncio.run(core_device_send_signal_to_process_task(service_provider, pid, signal))


async def core_device_get_device_info_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_device_info())


@core_device.command("get-device-info", cls=RSDCommand)
def core_device_get_device_info(service_provider: RemoteServiceDiscoveryService) -> None:
    """Get device information"""
    asyncio.run(core_device_get_device_info_task(service_provider))


async def core_device_get_display_info_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_display_info())


@core_device.command("get-display-info", cls=RSDCommand)
def core_device_get_display_info(service_provider: RemoteServiceDiscoveryService) -> None:
    """Get display information"""
    asyncio.run(core_device_get_display_info_task(service_provider))


async def core_device_query_mobilegestalt_task(service_provider: RemoteServiceDiscoveryService, key: list[str]) -> None:
    """Query MobileGestalt"""
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.query_mobilegestalt(key))


@core_device.command("query-mobilegestalt", cls=RSDCommand)
@click.argument("key", nargs=-1, type=click.STRING)
def core_device_query_mobilegestalt(service_provider: RemoteServiceDiscoveryService, key: tuple[str]) -> None:
    """Query MobileGestalt"""
    asyncio.run(core_device_query_mobilegestalt_task(service_provider, list(key)))


async def core_device_get_lockstate_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_lockstate())


@core_device.command("get-lockstate", cls=RSDCommand)
def core_device_get_lockstate(service_provider: RemoteServiceDiscoveryService) -> None:
    """Get lockstate"""
    asyncio.run(core_device_get_lockstate_task(service_provider))


async def core_device_list_apps_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.list_apps())


@core_device.command("list-apps", cls=RSDCommand)
def core_device_list_apps(service_provider: RemoteServiceDiscoveryService) -> None:
    """Get application list"""
    asyncio.run(core_device_list_apps_task(service_provider))


async def core_device_sysdiagnose_task(service_provider: RemoteServiceDiscoveryService, output: str) -> None:
    output = Path(output)
    async with DiagnosticsServiceService(service_provider) as service:
        response = await service.capture_sysdiagnose(False)
        logger.info(f"Operation response: {response}")
        if output.is_dir():
            output /= response.preferred_filename
        logger.info(f"Downloading sysdiagnose to: {output}")

        # get the file over lockdownd which is WAYYY faster
        lockdown = create_using_usbmux(service_provider.udid)
        with CrashReportsManager(lockdown) as crash_reports_manager:
            crash_reports_manager.afc.pull(
                posixpath.join(f"/DiagnosticLogs/sysdiagnose/{response.preferred_filename}"), output
            )


@core_device.command("sysdiagnose", cls=RSDCommand)
@click.argument("output", type=click.Path(dir_okay=True, file_okay=True, exists=True))
def core_device_sysdiagnose(service_provider: RemoteServiceDiscoveryService, output: str) -> None:
    """Execute sysdiagnose and fetch the output file"""
    asyncio.run(core_device_sysdiagnose_task(service_provider, output))
