from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import async_command, print_json
from pymobiledevice3.doctor import run_checks

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
        print_json([
            {
                "title": check.title,
                "status": check.status.value,
                "detail": check.detail,
                "hint": check.hint,
            }
            for check in report.checks
        ])
        return
    typer.echo(repr(report))
    if report.problems:
        raise typer.Exit(1)
