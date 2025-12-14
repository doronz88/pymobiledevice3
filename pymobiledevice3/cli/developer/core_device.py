import asyncio
import logging
import posixpath
import time
from pathlib import Path
from typing import IO, Annotated, Optional

import click
import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import RSDServiceProviderDep, print_json
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService
from pymobiledevice3.remote.core_device.diagnostics_service import DiagnosticsServiceService
from pymobiledevice3.remote.core_device.file_service import APPLE_DOMAIN_DICT, FileServiceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.crash_reports import CrashReportsManager
from pymobiledevice3.utils import try_decode

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="core-device",
    help="Access DeveloperDiskImage services (files, processes, app launch, diagnostics).",
    no_args_is_help=True,
)


async def core_device_list_directory_task(
    service_provider: RemoteServiceDiscoveryService, domain: str, path: str, identifier: str
) -> None:
    async with FileServiceService(service_provider, APPLE_DOMAIN_DICT[domain], identifier) as file_service:
        print_json(await file_service.retrieve_directory_list(path))


@cli.command("list-directory")
def core_device_list_directory(
    service_provider: RSDServiceProviderDep,
    domain: Annotated[
        str,
        typer.Argument(click_type=click.Choice(APPLE_DOMAIN_DICT)),
    ],
    path: str,
    identifier: Annotated[str, typer.Option()] = "",
) -> None:
    """List directory contents for a given domain/path."""
    asyncio.run(core_device_list_directory_task(service_provider, domain, path, identifier))


async def core_device_read_file_task(
    service_provider: RemoteServiceDiscoveryService,
    domain: str,
    path: str,
    identifier: str,
    output: Optional[IO],
) -> None:
    async with FileServiceService(service_provider, APPLE_DOMAIN_DICT[domain], identifier) as file_service:
        buf = await file_service.retrieve_file(path)
        if output is not None:
            output.write(buf)
        else:
            print(try_decode(buf))


@cli.command("read-file")
def core_device_read_file(
    service_provider: RSDServiceProviderDep,
    domain: Annotated[
        str,
        typer.Argument(click_type=click.Choice(APPLE_DOMAIN_DICT)),
    ],
    path: str,
    *,
    identifier: Annotated[str, typer.Option()] = "",
    output: Annotated[
        Path,
        typer.Option("--output", "-o"),
    ],
) -> None:
    """Read a file from a domain/path to stdout or --output."""
    with output.open("wb") as output_file:
        asyncio.run(core_device_read_file_task(service_provider, domain, path, identifier, output_file))


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


@cli.command("propose-empty-file")
def core_device_propose_empty_file(
    service_provider: RSDServiceProviderDep,
    domain: Annotated[
        str,
        typer.Argument(click_type=click.Choice(APPLE_DOMAIN_DICT)),
    ],
    path: str,
    identifier: Annotated[str, typer.Option()] = "",
    file_permissions: Annotated[int, typer.Option()] = 0o644,
    uid: Annotated[int, typer.Option()] = 501,
    gid: Annotated[int, typer.Option()] = 501,
    creation_time: Annotated[Optional[int], typer.Option()] = None,
    last_modification_time: Annotated[Optional[int], typer.Option()] = None,
) -> None:
    """Create an empty file at the given domain/path with custom permissions/owner/timestamps."""
    asyncio.run(
        core_device_propose_empty_file_task(
            service_provider,
            domain,
            path,
            identifier,
            file_permissions,
            uid,
            gid,
            creation_time if creation_time is not None else int(time.time()),
            last_modification_time if last_modification_time is not None else int(time.time()),
        )
    )


async def core_device_list_launch_application_task(
    service_provider: RemoteServiceDiscoveryService,
    bundle_identifier: str,
    argument: list[str],
    kill_existing: bool,
    suspended: bool,
    env: dict[str, str],
) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.launch_application(bundle_identifier, argument, kill_existing, suspended, env))


@cli.command("launch-application")
def core_device_launch_application(
    service_provider: RSDServiceProviderDep,
    bundle_identifier: str,
    argument: list[str],
    kill_existing: Annotated[
        bool,
        typer.Option(help="Whether to kill an existing instance of this process"),
    ] = True,
    suspended: Annotated[bool, typer.Option(help="Same as WaitForDebugger")] = False,
    env: Annotated[
        Optional[list[str]],
        typer.Option(
            help="Environment variable to pass to process given as key=value (can be specified multiple times)"
        ),
    ] = None,
) -> None:
    """Launch an app; optionally kill existing, wait for debugger, or set env vars."""
    asyncio.run(
        core_device_list_launch_application_task(
            service_provider,
            bundle_identifier,
            list(argument),
            kill_existing,
            suspended,
            dict(var.split("=", 1) for var in env or ()),
        )
    )


async def core_device_list_processes_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.list_processes())


@cli.command("list-processes")
def core_device_list_processes(service_provider: RSDServiceProviderDep) -> None:
    """List running processes via CoreDevice."""
    asyncio.run(core_device_list_processes_task(service_provider))


async def core_device_uninstall_app_task(
    service_provider: RemoteServiceDiscoveryService, bundle_identifier: str
) -> None:
    async with AppServiceService(service_provider) as app_service:
        await app_service.uninstall_app(bundle_identifier)


@cli.command("uninstall")
def core_device_uninstall_app(service_provider: RSDServiceProviderDep, bundle_identifier: str) -> None:
    """Uninstall an app by bundle identifier via CoreDevice."""
    asyncio.run(core_device_uninstall_app_task(service_provider, bundle_identifier))


async def core_device_send_signal_to_process_task(
    service_provider: RemoteServiceDiscoveryService, pid: int, signal: int
) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.send_signal_to_process(pid, signal))


@cli.command("send-signal-to-process")
def core_device_send_signal_to_process(service_provider: RSDServiceProviderDep, pid: int, signal: int) -> None:
    """Send signal to process"""
    asyncio.run(core_device_send_signal_to_process_task(service_provider, pid, signal))


async def core_device_get_device_info_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_device_info())


@cli.command("get-device-info")
def core_device_get_device_info(service_provider: RSDServiceProviderDep) -> None:
    """Get device information"""
    asyncio.run(core_device_get_device_info_task(service_provider))


async def core_device_get_display_info_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_display_info())


@cli.command("get-display-info")
def core_device_get_display_info(service_provider: RSDServiceProviderDep) -> None:
    """Get display information"""
    asyncio.run(core_device_get_display_info_task(service_provider))


async def core_device_query_mobilegestalt_task(service_provider: RemoteServiceDiscoveryService, key: list[str]) -> None:
    """Query MobileGestalt"""
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.query_mobilegestalt(key))


@cli.command("query-mobilegestalt")
def core_device_query_mobilegestalt(service_provider: RSDServiceProviderDep, key: list[str]) -> None:
    """Query MobileGestalt"""
    asyncio.run(core_device_query_mobilegestalt_task(service_provider, key))


async def core_device_get_lockstate_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with DeviceInfoService(service_provider) as app_service:
        print_json(await app_service.get_lockstate())


@cli.command("get-lockstate")
def core_device_get_lockstate(service_provider: RSDServiceProviderDep) -> None:
    """Get lockstate"""
    asyncio.run(core_device_get_lockstate_task(service_provider))


async def core_device_list_apps_task(service_provider: RemoteServiceDiscoveryService) -> None:
    async with AppServiceService(service_provider) as app_service:
        print_json(await app_service.list_apps())


@cli.command("list-apps")
def core_device_list_apps(service_provider: RSDServiceProviderDep) -> None:
    """Get application list"""
    asyncio.run(core_device_list_apps_task(service_provider))


async def core_device_sysdiagnose_task(service_provider: RemoteServiceDiscoveryService, output: Path) -> None:
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
                posixpath.join(f"/DiagnosticLogs/sysdiagnose/{response.preferred_filename}"), str(output)
            )


@cli.command("sysdiagnose")
def core_device_sysdiagnose(
    service_provider: RSDServiceProviderDep,
    output: Annotated[
        Path,
        typer.Argument(dir_okay=True, file_okay=True, exists=True),
    ],
) -> None:
    """Execute sysdiagnose and fetch the output file"""
    asyncio.run(core_device_sysdiagnose_task(service_provider, output))
