from pathlib import Path
from textwrap import dedent
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep
from pymobiledevice3.cli.developer import (
    accessibility,
    arbitration,
    condition,
    core_device,
    debugserver,
    dvt,
    fetch_symbols,
    simulate_location,
)
from pymobiledevice3.services.remote_server import RemoteServer
from pymobiledevice3.services.screenshot import ScreenshotService

cli = InjectingTyper(
    name="developer",
    help=dedent("""\
        Developer tooling for iOS devices (requires Developer Mode + mounted DeveloperDiskImage).

        These commands require the DeveloperDiskImage.dmg to be mounted on the device prior
        to execution. You can achieve this using:

        pymobiledevice3 mounter mount

        Also, starting at iOS 17.0, a tunnel must be created to the device for the services
        to be accessible. Therefore, every CLI command is retried with a `--tunnel` option
        for implicitly accessing tunneld when necessary
    """),
    no_args_is_help=True,
)
cli.add_typer(dvt.cli)
cli.add_typer(fetch_symbols.cli)
cli.add_typer(simulate_location.cli)
cli.add_typer(accessibility.cli)
cli.add_typer(condition.cli)
cli.add_typer(debugserver.cli)
cli.add_typer(arbitration.cli)
cli.add_typer(core_device.cli)


@cli.command("shell")
def developer_shell(
    service_provider: ServiceProviderDep,
    service: str,
    remove_ssl_context: Annotated[bool, typer.Option("--remove-ssl-context", "-r")] = False,
) -> None:
    """Open an IPython shell connected to a developer service (for exploration/R&D)."""
    with RemoteServer(service_provider, service, remove_ssl_context) as service:
        service.shell()


@cli.command()
def screenshot(service_provider: ServiceProviderDep, out: Path) -> None:
    """Capture a PNG screenshot (Depcrecated API)."""
    out.write_bytes(ScreenshotService(lockdown=service_provider).take_screenshot())
