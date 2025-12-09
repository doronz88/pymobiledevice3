import contextlib
import json
import logging
import time
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, default_json_encoder, print_json
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="process",
    help="Process monitor options.",
    no_args_is_help=True,
)


@cli.command("monitor")
def sysmon_process_monitor(service_provider: ServiceProviderDep, threshold: float) -> None:
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


@cli.command("single")
def sysmon_process_single(
    service_provider: ServiceProviderDep,
    attributes: Annotated[
        Optional[list[str]],
        typer.Option(
            "--attributes",
            "-a",
            help="filter processes by given attribute value given as key=value. Can be specified multiple times.",
        ),
    ] = None,
) -> None:
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
                            filter_attr, filter_value = filter_attr.split("=", 1)
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


@cli.command("monitor-single")
def sysmon_process_monitor_single(
    service_provider: ServiceProviderDep,
    attributes: Annotated[
        Optional[list[str]],
        typer.Option(
            "--attributes",
            "-a",
            help="filter processes by attribute (key=value). Multiple filters on same attribute use OR logic, different attributes use AND.",
        ),
    ] = None,
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
) -> None:
    """Continuously monitor a single process with comprehensive metrics."""
    count = 0
    start_time = None

    # Parse attributes into grouped filters: same attribute uses OR, different attributes use AND
    parsed_filters: dict[str, list[str]] = {}
    if attributes:
        for raw in attributes:
            key, value = raw.split("=", 1)
            parsed_filters.setdefault(key, []).append(value)

    def matches_filters(proc: dict) -> bool:
        """Check if process matches all filter criteria."""
        if not parsed_filters:
            return True
        return all(str(proc.get(key)) in values for key, values in parsed_filters.items())

    with contextlib.ExitStack() as stack:
        output_file = stack.enter_context(open(output, "w")) if output else None

        dvt = stack.enter_context(DvtSecureSocketProxyService(lockdown=service_provider))
        sysmon = stack.enter_context(Sysmontap(dvt))

        for process_snapshot in sysmon.iter_processes():
            count += 1

            if count < 2:
                continue

            if start_time is None:
                start_time = time.time()

            if duration is not None:
                elapsed_ms = (time.time() - start_time) * 1000
                if elapsed_ms >= duration:
                    break

            for process in process_snapshot:
                if not matches_filters(process):
                    continue

                process["timestamp"] = datetime.now(timezone.utc).isoformat()

                if output_file:
                    json_output = json.dumps(process, default=default_json_encoder)
                    output_file.write(json_output + "\n")
                    output_file.flush()
                else:
                    print_json(process)

            if interval:
                time.sleep(interval / 1000.0)
