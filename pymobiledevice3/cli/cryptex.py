import dataclasses
import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import RSDServiceProviderDep, async_command, print_json
from pymobiledevice3.exceptions import AlreadyMountedError
from pymobiledevice3.services.cryptexd import XCODE_DDI_RESTORE_DIR, CryptexdService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="cryptex",
    help="Manage cryptexes via cryptexd (iOS 17+, requires an RSD tunnel).",
    no_args_is_help=True,
)

NonceDomainOption = Annotated[
    Optional[int],
    typer.Option("--nonce-domain", help="Nonce domain index (defaults to the cryptex domain)."),
]
NonceDomainHandleOption = Annotated[
    Optional[int],
    typer.Option("--nonce-domain-handle", help="Nonce domain handle, as an alternative to --nonce-domain."),
]


@cli.command("list")
@async_command
async def cryptex_list(service_provider: RSDServiceProviderDep) -> None:
    """List installed cryptexes (a mounted personalized DDI appears as com.apple.MobileAsset.DDI)."""
    cryptexd = CryptexdService(service_provider)
    print_json([dataclasses.asdict(cryptex) for cryptex in await cryptexd.copy_installed()])


@cli.command("auto-install")
@async_command
async def cryptex_auto_install(
    service_provider: RSDServiceProviderDep,
    restore_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--restore-dir",
            exists=True,
            file_okay=False,
            dir_okay=True,
            help="Unpacked DDI Restore directory holding the Cryptex1 assets, e.g. Xcode's own "
            f"({XCODE_DDI_RESTORE_DIR}). Defaults to downloading and caching the DDI.",
        ),
    ] = None,
) -> None:
    """Personalize and install the DeveloperDiskImage cryptex, using only cryptexd."""
    cryptexd = CryptexdService(service_provider)
    try:
        installed = await cryptexd.auto_install_ddi(restore_dir)
    except FileNotFoundError as e:
        raise typer.BadParameter(str(e)) from e
    except AlreadyMountedError as e:
        logger.error(f"DeveloperDiskImage cryptex already installed ({e}); uninstall it first")
        raise typer.Exit(1) from e
    logger.info(f"Installed {installed.identifier} {installed.version}")


@cli.command("personalization-identifiers")
@async_command
async def cryptex_personalization_identifiers(service_provider: RSDServiceProviderDep) -> None:
    """Read the AppleImage4 chip instance used to personalize a cryptex."""
    cryptexd = CryptexdService(service_provider)
    print_json(await cryptexd.read_personalization_identifiers())


@cli.command("nonce")
@async_command
async def cryptex_nonce(
    service_provider: RSDServiceProviderDep,
    nonce_domain: NonceDomainOption = None,
    nonce_domain_handle: NonceDomainHandleOption = None,
) -> None:
    """Read the nonce for a nonce domain."""
    cryptexd = CryptexdService(service_provider)
    try:
        print_json(await cryptexd.get_nonce(nonce_domain, nonce_domain_handle))
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e


@cli.command("roll-nonce")
@async_command
async def cryptex_roll_nonce(
    service_provider: RSDServiceProviderDep,
    nonce_domain: NonceDomainOption = None,
    nonce_domain_handle: NonceDomainHandleOption = None,
) -> None:
    """Roll a nonce domain's nonce (invalidates a personalized DDI; it must be re-mounted)."""
    cryptexd = CryptexdService(service_provider)
    try:
        await cryptexd.roll_nonce(nonce_domain, nonce_domain_handle)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e
    logger.info("Nonce rolled")


@cli.command("uninstall")
@async_command
async def cryptex_uninstall(
    service_provider: RSDServiceProviderDep,
    identifier: str,
    version: Annotated[Optional[str], typer.Option("--version")] = None,
) -> None:
    """Uninstall an installed cryptex by its identifier."""
    cryptexd = CryptexdService(service_provider)
    await cryptexd.uninstall(identifier, version)
    logger.info(f"Uninstalled {identifier}")
