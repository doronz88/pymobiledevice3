import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService


@click.group()
def cli() -> None:
    pass


@cli.group()
def apps() -> None:
    """Manage installed applications"""
    pass


@apps.command("list", cls=Command)
@click.option(
    "app_type",
    "-t",
    "--type",
    type=click.Choice(["System", "User", "Hidden", "Any"]),
    default="Any",
    help="include only applications of given type",
)
@click.option("--calculate-sizes/--no-calculate-size", default=False)
def apps_list(service_provider: LockdownServiceProvider, app_type: str, calculate_sizes: bool) -> None:
    """list installed apps"""
    print_json(
        InstallationProxyService(lockdown=service_provider).get_apps(
            application_type=app_type, calculate_sizes=calculate_sizes
        )
    )


@apps.command("query", cls=Command)
@click.argument("bundle_identifiers", nargs=-1)
@click.option("--calculate-sizes/--no-calculate-size", default=False)
def apps_query(service_provider: LockdownServiceProvider, bundle_identifiers: list[str], calculate_sizes: bool) -> None:
    """query installed apps"""
    print_json(
        InstallationProxyService(lockdown=service_provider).get_apps(
            calculate_sizes=calculate_sizes, bundle_identifiers=bundle_identifiers
        )
    )


@apps.command("uninstall", cls=Command)
@click.argument("bundle_id")
def uninstall(service_provider: LockdownClient, bundle_id):
    """uninstall app by given bundle_id"""
    InstallationProxyService(lockdown=service_provider).uninstall(bundle_id)


@apps.command("install", cls=Command)
@click.option("--developer", is_flag=True, help="Install developer package")
@click.argument("package", type=click.Path(exists=True))
def install(service_provider: LockdownServiceProvider, package: str, developer: bool) -> None:
    """install given .ipa/.app/.ipcc"""
    InstallationProxyService(lockdown=service_provider).install_from_local(package, developer=developer)


@apps.command("afc", cls=Command)
@click.option("--documents", is_flag=True)
@click.argument("bundle_id")
def afc(service_provider: LockdownClient, bundle_id: str, documents: bool):
    """open an AFC shell for given bundle_id, assuming its profile is installed"""
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id, documents_only=documents).shell()


@apps.command("pull", cls=Command)
@click.argument("bundle_id")
@click.argument("remote_file", type=click.Path(exists=False))
@click.argument("local_file", type=click.Path(exists=False))
def pull(service_provider: LockdownClient, bundle_id: str, remote_file: str, local_file: str):
    """pull remote file from specified bundle_id"""
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id).pull(remote_file, local_file)


@apps.command("push", cls=Command)
@click.argument("bundle_id")
@click.argument("local_file", type=click.Path(exists=False))
@click.argument("remote_file", type=click.Path(exists=False))
def push(service_provider: LockdownClient, bundle_id: str, local_file: str, remote_file: str):
    """push local file into specified bundle_id"""
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id).push(local_file, remote_file)


@apps.command("rm", cls=Command)
@click.argument("bundle_id")
@click.argument("remote_file", type=click.Path(exists=False))
def rm(service_provider: LockdownClient, bundle_id: str, remote_file: str):
    """remove remote file from specified bundle_id"""
    HouseArrestService(lockdown=service_provider, bundle_id=bundle_id).rm(remote_file)
