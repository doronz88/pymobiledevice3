import logging
from dataclasses import asdict
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.cli.developer.dvt.sysmon import process
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="sysmon",
    help="System monitor options.",
    no_args_is_help=True,
)
cli.add_typer(process.cli)


@cli.command("system")
@async_command
async def sysmon_system(
    service_provider: ServiceProviderDep,
    fields: Annotated[
        Optional[str],
        typer.Option(
            "--fields",
            "-f",
            help='field names separated by ",".',
        ),
    ] = None,
) -> None:
    """show current system stats."""

    split_fields = fields.split(",") if fields is not None else None

    async with DvtProvider(service_provider) as dvt:
        sysmontap = await Sysmontap.create(dvt)
        async with sysmontap as sysmon:
            system = None
            system_usage = None
            system_usage_seen = False  # Tracks if the first occurrence of SystemCPUUsage

            async for row in sysmon:
                if "System" in row and system is None:
                    system = sysmon.system_attributes_cls(*row["System"])

                if "SystemCPUUsage" in row:
                    if system_usage_seen:
                        system_usage = {
                            **row["SystemCPUUsage"],
                            "CPUCount": row["CPUCount"],
                            "EnabledCPUs": row["EnabledCPUs"],
                        }
                    else:  # Ignore the first occurrence because first occurrence always gives a incorrect value - 100 or 0
                        system_usage_seen = True

                if system and system_usage:
                    break

    assert system is not None and system_usage is not None  # for type checker

    attrs_dict = {**asdict(system), **system_usage}
    for name, value in attrs_dict.items():
        if (split_fields is None) or (name in fields):
            print(f"{name}: {value}")
