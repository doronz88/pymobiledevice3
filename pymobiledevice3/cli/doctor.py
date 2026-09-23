from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import async_command, print_json
from pymobiledevice3.doctor import DEVICE, HOST, run_checks

cli = InjectingTyper(
    name="doctor",
    help="Check what this host can reach a device with",
    no_args_is_help=False,
    invoke_without_command=True,
)


@cli.command("doctor")
@async_command
async def cli_doctor(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the checks as JSON, for pasting into a bug report."),
    ] = False,
) -> None:
    """Report which transports this host can use, and what to fix when it cannot.

    Inspects the host only -- no device has to be connected, since a device that never shows up is
    usually the thing being explained.
    """
    report = await run_checks()
    if json_output:
        print_json({
            "environment": report.environment,
            "checks": [
                {
                    "scope": scope,
                    "title": check.title,
                    "status": check.status.value,
                    "detail": check.detail,
                    "impact": check.impact,
                    "hint": check.hint,
                }
                for scope, checks in ((HOST, report.host), (DEVICE, report.device))
                for check in checks
            ],
        })
    else:
        typer.echo(repr(report))
    # Same verdict either way: a script reading the JSON must not pass on a broken host.
    if report.problems:
        raise typer.Exit(1)
