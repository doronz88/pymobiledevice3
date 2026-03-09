from pathlib import Path
from textwrap import dedent
from typing import Annotated

import typer
from pygments import formatters, highlight, lexers
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.cli.developer import (
    accessibility,
    arbitration,
    core_device,
    debugserver,
    dvt,
    fetch_symbols,
    simulate_location,
    wda,
)
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.energy_monitor import EnergyMonitor
from pymobiledevice3.services.dvt.instruments.graphics import Graphics
from pymobiledevice3.services.dvt.instruments.network_monitor import NetworkMonitor
from pymobiledevice3.services.dvt.instruments.notifications import Notifications
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.services.screenshot import ScreenshotService
from pymobiledevice3.utils import run_in_loop, start_ipython_shell

SHELL_USAGE = dedent("""\
    # Welcome to the DTX playground.
    # You are connected with:
    # - provider: DtxServiceProvider
    # - dtx: DTXConnection
    #
    # Quick wins:
    device_info = DeviceInfo(provider)
    await device_info.connect()
    procs = await device_info.proclist()
    print(procs[:3])
    #
    async with ProcessControl(provider):
        pid = await process_control.process_identifier_for_bundle_identifier("com.apple.Preferences")
        print(pid)
    #
    # Raw mode (dynamic service):
    svc = await dtx.open_channel("com.apple.instruments.server.services.deviceinfo")
    procs = await svc.invoke("runningProcesses")
    print(len(procs))
    #
    # Also preloaded:
    # ApplicationListing, Screenshot, NetworkMonitor, Notifications, Graphics, ConditionInducer, EnergyMonitor
""")

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
cli.add_typer(debugserver.cli)
cli.add_typer(arbitration.cli)
cli.add_typer(core_device.cli)
cli.add_typer(wda.cli)


@cli.command("shell")
def developer_shell(
    service_provider: ServiceProviderDep,
    service: str,
    remove_ssl_context: Annotated[bool, typer.Option("--remove-ssl-context", "-r")] = False,
) -> None:
    """Open an IPython shell connected to a developer service (for exploration/R&D)."""
    shell_provider_class = type(
        "ShellDtxProvider",
        (DtxServiceProvider,),
        {
            "SERVICE_NAME": service,
            "RSD_SERVICE_NAME": service,
            "OLD_SERVICE_NAME": service,
        },
    )
    provider = shell_provider_class(service_provider, strip_ssl=remove_ssl_context)
    run_in_loop(provider.connect())
    try:
        start_ipython_shell(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style="native")),
            user_ns={
                "provider": provider,
                "dtx": provider.dtx,
                "DeviceInfo": DeviceInfo,
                "ProcessControl": ProcessControl,
                "ApplicationListing": ApplicationListing,
                "Screenshot": Screenshot,
                "NetworkMonitor": NetworkMonitor,
                "Notifications": Notifications,
                "Graphics": Graphics,
                "ConditionInducer": ConditionInducer,
                "EnergyMonitor": EnergyMonitor,
            },
        )
    finally:
        run_in_loop(provider.close())


@cli.command()
@async_command
async def screenshot(service_provider: ServiceProviderDep, out: Path) -> None:
    """Capture a PNG screenshot (Depcrecated API)."""
    out.write_bytes(await ScreenshotService(lockdown=service_provider).take_screenshot())
