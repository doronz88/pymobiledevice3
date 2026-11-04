import dataclasses
from pathlib import Path
from typing import Annotated, Literal

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    RSDServiceProviderDep,
    ServiceProviderDep,
    ShellHostToolsOption,
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
from pymobiledevice3.services.streaming_zip_conduit import StreamingZipConduitService

cli = InjectingTyper(
    name="apps",
    help="List, query, install, uninstall, and inspect apps on the device.",
    no_args_is_help=True,
)

BundleIdArgument = Annotated[str, typer.Argument(help="Bundle identifier of the app (e.g. com.apple.mobilesafari).")]
DocumentsOption = Annotated[
    bool, typer.Option(help="Expose only the app's Documents folder instead of its whole container.")
]


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
    bundle_identifiers: Annotated[list[str], typer.Argument(help="One or more bundle identifiers.")],
    calculate_sizes: Annotated[
        bool,
        typer.Option(help="Include app size information (slower)."),
    ] = False,
) -> None:
    """Print the installation metadata of the given apps."""
    print_json(
        await InstallationProxyService(lockdown=service_provider).get_apps(
            calculate_sizes=calculate_sizes, bundle_identifiers=bundle_identifiers
        )
    )


@cli.command("uninstall")
@async_command
async def uninstall(service_provider: ServiceProviderDep, bundle_id: BundleIdArgument) -> None:
    """Uninstall an app and delete its data."""
    await InstallationProxyService(lockdown=service_provider).uninstall(bundle_id)


@cli.command("install")
@async_command
async def install(
    service_provider: ServiceProviderDep,
    package: Annotated[
        Path,
        typer.Argument(
            exists=True, help="App to install: an .ipa file, an .app directory, or an .ipcc carrier bundle."
        ),
    ],
    developer: Annotated[
        bool,
        typer.Option(help="Install as a developer package (PackageType=Developer)."),
    ] = False,
    streaming: Annotated[
        bool,
        typer.Option(
            help="Stream the app through streaming_zip_conduit, as Xcode does: the device extracts it "
            "while it arrives instead of unpacking an uploaded .ipa. Not for .ipcc packages."
        ),
    ] = False,
) -> None:
    """Install an app (.ipa/.app) or carrier bundle (.ipcc) from this computer."""
    if not streaming:
        await InstallationProxyService(lockdown=service_provider).install_from_local(package, developer=developer)
        return
    if package.suffix == ".ipcc":
        raise typer.BadParameter("--streaming cannot install .ipcc packages")
    async with StreamingZipConduitService(service_provider) as conduit:
        await conduit.install(package, developer=developer)


@cli.command("afc")
def afc(
    service_provider: ServiceProviderDep,
    bundle_id: BundleIdArgument,
    documents: DocumentsOption = False,
    tool: ShellHostToolsOption = None,
) -> None:
    """Open an interactive file shell inside an app's container."""
    service = cli_loop.run_until_complete(
        HouseArrestService.create(lockdown=service_provider, bundle_id=bundle_id, documents_only=documents)
    )
    try:
        service.shell(host_tools=tool or [])
    finally:
        cli_loop.run_until_complete(service.close())


@cli.command("webdav")
@async_command
async def apps_webdav(
    service_provider: ServiceProviderDep,
    bundle_id: BundleIdArgument,
    path: WebDavPathArgument = "/",
    documents: DocumentsOption = False,
    mount: WebDavMountOption = False,
    host: WebDavHostOption = "127.0.0.1",
    bind_port: WebDavBindPortOption = 0,
    readonly: WebDavReadonlyOption = False,
) -> None:
    """Serve an app's container over WebDAV for local mounting (e.g. in Finder); runs until Ctrl+C."""
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
    bundle_id: BundleIdArgument,
    remote_file: Annotated[str, typer.Argument(help="File or directory inside the app container.")],
    local_file: Annotated[Path, typer.Argument(help="Local destination path.")],
    documents: DocumentsOption = False,
) -> None:
    """Download a file or directory (recursively) from an app's container."""
    async with await HouseArrestService.create(
        lockdown=service_provider, bundle_id=bundle_id, documents_only=documents
    ) as service:
        await service.pull(remote_file, str(local_file))


@cli.command("push")
@async_command
async def push(
    service_provider: ServiceProviderDep,
    bundle_id: BundleIdArgument,
    local_file: Annotated[Path, typer.Argument(help="Local file or directory to upload.")],
    remote_file: Annotated[str, typer.Argument(help="Destination inside the app container (may be a directory).")],
    documents: DocumentsOption = False,
) -> None:
    """Upload a local file or directory (recursively) into an app's container, overwriting files."""
    async with await HouseArrestService.create(
        lockdown=service_provider, bundle_id=bundle_id, documents_only=documents
    ) as service:
        await service.push(str(local_file), remote_file)


@cli.command("rm")
@async_command
async def rm(
    service_provider: ServiceProviderDep,
    bundle_id: BundleIdArgument,
    remote_file: Annotated[str, typer.Argument(help="File or directory inside the app container.")],
    documents: DocumentsOption = False,
) -> None:
    """Delete a file or a whole directory tree from an app's container (no confirmation)."""
    async with await HouseArrestService.create(
        lockdown=service_provider, bundle_id=bundle_id, documents_only=documents
    ) as service:
        await service.rm(remote_file)


@cli.command("install-record")
@async_command
async def install_record(service_provider: RSDServiceProviderDep, bundle_id: BundleIdArgument) -> None:
    """Print an app's LaunchServices install record (iOS 17+, via installcoordination_proxy)."""
    async with InstallCoordinationProxyService(service_provider) as service:
        print_json(dataclasses.asdict(await service.query(bundle_id)))
