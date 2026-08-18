import dataclasses
from pathlib import Path
from typing import Annotated, Literal

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    RSDServiceProviderDep,
    ServiceProviderDep,
    WebDavBindPortOption,
    WebDavHostOption,
    WebDavMountOption,
    WebDavPathArgument,
    WebDavReadonlyOption,
    async_command,
    cli_loop,
    print_json,
    run_afc_webdav_cli,
)
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.install_coordination_proxy import InstallCoordinationProxyService
from pymobiledevice3.services.installation_proxy import InstallationProxyService

cli = InjectingTyper(
    name="apps",
    help="List, query, install, uninstall, and inspect apps on the device.",
    no_args_is_help=True,
)


@cli.command("list")
@async_command
async def apps_list(
    service_provider: ServiceProviderDep,
    app_type: Annotated[
        Literal["System", "User", "Hidden", "Any"],
        typer.Option(
            "--type",
            "-t",
            help="Filter by application type (System/User/Hidden/Any).",
        ),
    ] = "Any",
    calculate_sizes: Annotated[
        bool,
        typer.Option(help="Include app size information (slower)."),
    ] = False,
    show_placeholders: Annotated[
        bool,
        typer.Option(help="Include placeholder apps in the results."),
    ] = False,
) -> None:
    """List installed apps."""
    print_json(
        await InstallationProxyService(lockdown=service_provider).get_apps(
            application_type=app_type,
            calculate_sizes=calculate_sizes,
            show_placeholders=show_placeholders,
        )
    )


@cli.command("query")
@async_command
async def apps_query(
    service_provider: ServiceProviderDep,
    bundle_identifiers: list[str],
    calculate_sizes: Annotated[
        bool,
        typer.Option(help="Include app size information (slower)."),
    ] = False,
) -> None:
    """Return metadata for specific bundle identifiers."""
    print_json(
        await InstallationProxyService(lockdown=service_provider).get_apps(
            calculate_sizes=calculate_sizes, bundle_identifiers=bundle_identifiers
        )
    )


@cli.command("uninstall")
@async_command
async def uninstall(service_provider: ServiceProviderDep, bundle_id: str) -> None:
    """Uninstall an app by bundle identifier."""
    await InstallationProxyService(lockdown=service_provider).uninstall(bundle_id)


@cli.command("install")
@async_command
async def install(
    service_provider: ServiceProviderDep,
    package: Annotated[
        Path,
        typer.Argument(exists=True),
    ],
    developer: Annotated[
        bool,
        typer.Option(help="Install developer package"),
    ] = False,
) -> None:
    """Install a local .ipa/.app/.ipcc package."""
    await InstallationProxyService(lockdown=service_provider).install_from_local(package, developer=developer)


@cli.command("afc")
def afc(
    service_provider: ServiceProviderDep, bundle_id: str, documents: Annotated[bool, typer.Option()] = False
) -> None:
    """Open an AFC shell into the app container; pass --documents for Documents-only."""
    service = cli_loop.run_until_complete(
        HouseArrestService.create(lockdown=service_provider, bundle_id=bundle_id, documents_only=documents)
    )
    try:
        service.shell()
    finally:
        cli_loop.run_until_complete(service.close())


@cli.command("webdav")
@async_command
async def apps_webdav(
    service_provider: ServiceProviderDep,
    bundle_id: str,
    path: WebDavPathArgument = "/",
    documents: Annotated[bool, typer.Option()] = False,
    mount: WebDavMountOption = False,
    host: WebDavHostOption = "127.0.0.1",
    bind_port: WebDavBindPortOption = 0,
    readonly: WebDavReadonlyOption = False,
) -> None:
    """Serve an app container over WebDAV for local mounting; pass --documents for Documents-only."""
    async with await HouseArrestService.create(
        lockdown=service_provider, bundle_id=bundle_id, documents_only=documents
    ) as service:
        label = f"pmd-{service_provider.udid or 'device'}-{bundle_id}"
        await run_afc_webdav_cli(
            service, path=path, mount=mount, host=host, bind_port=bind_port, readonly=readonly, label=label
        )


@cli.command("pull")
@async_command
async def pull(
    service_provider: ServiceProviderDep,
    bundle_id: str,
    remote_file: str,
    local_file: Path,
    documents: Annotated[bool, typer.Option()] = False,
) -> None:
    """Pull a file from an app container to a local path."""
    async with await HouseArrestService.create(
        lockdown=service_provider, bundle_id=bundle_id, documents_only=documents
    ) as service:
        await service.pull(remote_file, str(local_file))


@cli.command("push")
@async_command
async def push(
    service_provider: ServiceProviderDep,
    bundle_id: str,
    local_file: Path,
    remote_file: str,
    documents: Annotated[bool, typer.Option()] = False,
) -> None:
    """Push a local file into an app container."""
    async with await HouseArrestService.create(
        lockdown=service_provider, bundle_id=bundle_id, documents_only=documents
    ) as service:
        await service.push(str(local_file), remote_file)


@cli.command("rm")
@async_command
async def rm(
    service_provider: ServiceProviderDep,
    bundle_id: str,
    remote_file: str,
    documents: Annotated[bool, typer.Option()] = False,
) -> None:
    """Delete a file from an app container."""
    async with await HouseArrestService.create(
        lockdown=service_provider, bundle_id=bundle_id, documents_only=documents
    ) as service:
        await service.rm(remote_file)


@cli.command("install-record")
@async_command
async def install_record(service_provider: RSDServiceProviderDep, bundle_id: str) -> None:
    """Query an app's LaunchServices install record via installcoordination_proxy."""
    async with InstallCoordinationProxyService(service_provider) as service:
        print_json(dataclasses.asdict(await service.query(bundle_id)))
