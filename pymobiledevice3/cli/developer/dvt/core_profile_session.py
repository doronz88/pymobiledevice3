import importlib.resources
import json
import logging
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
    default_json_encoder,
    print_json,
    user_requested_colored_output,
)
from pymobiledevice3.exceptions import ExtractingStackshotError
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo

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
def live_profile_session(
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


@cli.command("save")
def save_profile_session(
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
    with (
        DvtSecureSocketProxyService(lockdown=service_provider) as dvt,
        CoreProfileSessionTap(dvt, {}, filters) as tap,
        out.open("wb") as out_file,
    ):
        tap.dump(out_file)


@cli.command("stackshot")
def stackshot(
    service_provider: ServiceProviderDep,
    out: Annotated[Optional[Path], typer.Option()] = None,
) -> None:
    """Dump stackshot information."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt, CoreProfileSessionTap(dvt, {}) as tap:
        try:
            data = tap.get_stackshot()
        except ExtractingStackshotError:
            logger.exception("Extracting stackshot failed")
            return

        if out is not None:
            out.write_text(json.dumps(data, indent=4, default=default_json_encoder))
        else:
            print_json(data)


@cli.command("parse-live")
def parse_live_profile_session(
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
) -> None:
    """Print traces (syscalls, thread events, etc.) received from the device in real time."""
    with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print("Receiving time information")
        time_config = CoreProfileSessionTap.get_time_config(dvt)
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
        parser.color = user_requested_colored_output()

        with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            if show_tid:
                print("{:^32}|{:^11}|{:^33}|   Event".format("Time", "Thread", "Process"))
            else:
                print("{:^32}|{:^33}|   Event".format("Time", "Process"))

            for trace in islice(parser.formatted_traces(tap.get_kdbuf_stream()), count):
                print(trace, flush=True)


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
def callstacks_live_profile_session(
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

        with importlib.resources.open_text(pymobiledevice3.resources, "dsc_uuid_map.json") as fd:
            dsc_uuid_map = json.load(fd)

        current_dsc_map = {}
        with CoreProfileSessionTap(dvt, time_config) as tap:
            for callstack in islice(parser.formatted_callstacks(tap.get_kdbuf_stream()), count):
                print(format_callstack(callstack, dsc_uuid_map, current_dsc_map))
