from pathlib import Path
from typing import Annotated, Literal

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService

cli = InjectingTyper(
    name="apps",
    help="Manage installed applications",
    no_args_is_help=True,
)


@cli.command("list")
def apps_list(
    service_provider: ServiceProviderDep,
    app_type: Annotated[
        Literal["System", "User", "Hidden", "Any"],
        typer.Option(
            "--type",
            "-t",
            help="include only applications of given type",
        ),
    ] = "Any",
    calculate_sizes: Annotated[bool, typer.Option()] = False,
) -> None:
    """list installed apps"""
    print_json(
        InstallationProxyService(lockdown=service_provider).get_apps(
            application_type=app_type, calculate_sizes=calculate_sizes
        )
    )


@cli.command("query")
def apps_query(
    service_provider: ServiceProviderDep,
    bundle_identifiers: list[str],
    calculate_sizes: Annotated[bool, typer.Option()] = False,
) -> None:
    """query installed apps"""
    print_json(
        InstallationProxyService(lockdown=service_provider).get_apps(
            calculate_sizes=calculate_sizes, bundle_identifiers=bundle_identifiers
        )
    )


@cli.command("uninstall")
def uninstall(service_provider: ServiceProviderDep, bundle_id: str) -> None:
    """uninstall app by given bundle_id"""
    InstallationProxyService(lockdown=service_provider).uninstall(bundle_id)


@cli.command("install")
def install(
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
    """install given .ipa/.app/.ipcc"""
    InstallationProxyService(lockdown=service_provider).install_from_local(package, developer=developer)


@cli.command("afc")
def afc(
    service_provider: ServiceProviderDep, bundle_id: str, documents: Annotated[bool, typer.Option()] = False
) -> None:
    """open an AFC shell for given bundle_id, assuming its profile is installed"""
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id, documents_only=documents).shell()


@cli.command("pull")
def pull(service_provider: ServiceProviderDep, bundle_id: str, remote_file: Path, local_file: Path) -> None:
    """pull remote file from specified bundle_id"""
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id).pull(str(remote_file), str(local_file))


@cli.command("push")
def push(service_provider: ServiceProviderDep, bundle_id: str, local_file: Path, remote_file: Path) -> None:
    """push local file into specified bundle_id"""
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id).push(str(local_file), str(remote_file))


@cli.command("rm")
def rm(service_provider: ServiceProviderDep, bundle_id: str, remote_file: Path) -> None:
    """remove remote file from specified bundle_id"""
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id).rm(str(remote_file))
