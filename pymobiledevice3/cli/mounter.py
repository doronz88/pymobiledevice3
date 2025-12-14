import asyncio
import logging
from functools import update_wrapper
from pathlib import Path
from typing import Annotated, Optional
from urllib.error import URLError

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.exceptions import (
    AlreadyMountedError,
    DeveloperDiskImageNotFoundError,
    NotMountedError,
    UnsupportedCommandError,
)
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.mobile_image_mounter import (
    DeveloperDiskImageMounter,
    MobileImageMounterService,
    PersonalizedImageMounter,
    auto_mount,
)

logger = logging.getLogger(__name__)


def catch_errors(func):
    def catch_function(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AlreadyMountedError:
            logger.error("Given image was already mounted")
        except UnsupportedCommandError:
            logger.error("Your iOS version doesn't support this command")

    return update_wrapper(catch_function, func)


cli = InjectingTyper(
    name="mounter",
    help="Mount/Umount DeveloperDiskImage or query related info",
    no_args_is_help=True,
)


@cli.command("list")
def mounter_list(service_provider: ServiceProviderDep) -> None:
    """list all mounted images"""
    output = []

    images = MobileImageMounterService(lockdown=service_provider).copy_devices()
    for image in images:
        image_signature = image.get("ImageSignature")
        if image_signature is not None:
            image["ImageSignature"] = image_signature.hex()
        output.append(image)

    print_json(output)


@cli.command("lookup")
def mounter_lookup(service_provider: ServiceProviderDep, image_type: str) -> None:
    """lookup mounter image type"""
    try:
        signature = MobileImageMounterService(lockdown=service_provider).lookup_image(image_type)
        print_json(signature)
    except NotMountedError:
        logger.error(f"Disk image of type: {image_type} is not mounted")


@cli.command("umount-developer")
@catch_errors
def mounter_umount_developer(service_provider: ServiceProviderDep) -> None:
    """unmount Developer image"""
    try:
        DeveloperDiskImageMounter(lockdown=service_provider).umount()
        logger.info("Developer image unmounted successfully")
    except NotMountedError:
        logger.error("Developer image isn't currently mounted")


@cli.command("umount-personalized")
@catch_errors
def mounter_umount_personalized(service_provider: ServiceProviderDep) -> None:
    """unmount Personalized image"""
    try:
        PersonalizedImageMounter(lockdown=service_provider).umount()
        logger.info("Personalized image unmounted successfully")
    except NotMountedError:
        logger.error("Personalized image isn't currently mounted")


@cli.command("mount-developer")
@catch_errors
def mounter_mount_developer(
    service_provider: ServiceProviderDep,
    image: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ],
    signature: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ],
) -> None:
    """mount developer image"""
    DeveloperDiskImageMounter(lockdown=service_provider).mount(image, signature)
    logger.info("Developer image mounted successfully")


async def mounter_mount_personalized_task(
    service_provider: LockdownServiceProvider, image: str, trust_cache: str, build_manifest: str
) -> None:
    await PersonalizedImageMounter(lockdown=service_provider).mount(
        Path(image), Path(build_manifest), Path(trust_cache)
    )
    logger.info("Personalized image mounted successfully")


@cli.command("mount-personalized")
@catch_errors
def mounter_mount_personalized(
    service_provider: ServiceProviderDep,
    image: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ],
    trust_cache: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ],
    build_manifest: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ],
) -> None:
    """mount personalized image"""
    asyncio.run(
        mounter_mount_personalized_task(service_provider, str(image), str(trust_cache), str(build_manifest)), debug=True
    )


async def mounter_auto_mount_task(service_provider: LockdownServiceProvider, xcode: str, version: str) -> None:
    try:
        await auto_mount(service_provider, xcode=xcode, version=version)
        logger.info("DeveloperDiskImage mounted successfully")
    except URLError:
        logger.warning("failed to query DeveloperDiskImage versions")
    except DeveloperDiskImageNotFoundError:
        logger.error("Unable to find the correct DeveloperDiskImage")
    except AlreadyMountedError:
        logger.error("DeveloperDiskImage already mounted")
    except PermissionError as e:
        logger.error(
            f"DeveloperDiskImage could not be saved to Xcode default path ({e.filename}). "
            f"Please make sure your user has the necessary permissions"
        )


@cli.command("auto-mount")
def mounter_auto_mount(
    service_provider: ServiceProviderDep,
    xcode: Annotated[
        Optional[Path],
        typer.Option(
            "--xcode",
            "-x",
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="Xcode application path used to figure out automatically the DeveloperDiskImage path",
        ),
    ] = None,
    version: Annotated[
        Optional[str],
        typer.Option(help="Use a different DeveloperDiskImage version from the one retrieved by lockdownconnection"),
    ] = None,
) -> None:
    """auto-detect correct DeveloperDiskImage and mount it"""
    asyncio.run(mounter_auto_mount_task(service_provider, str(xcode), version), debug=True)


@cli.command("query-developer-mode-status")
def mounter_query_developer_mode_status(service_provider: ServiceProviderDep) -> None:
    """Query developer mode status"""
    print_json(MobileImageMounterService(lockdown=service_provider).query_developer_mode_status())


@cli.command("query-nonce")
def mounter_query_nonce(service_provider: ServiceProviderDep, image_type: Annotated[str, typer.Option()]) -> None:
    """Query nonce"""
    print_json(MobileImageMounterService(lockdown=service_provider).query_nonce(image_type))


@cli.command("query-personalization-identifiers")
def mounter_query_personalization_identifiers(service_provider: ServiceProviderDep) -> None:
    """Query personalization identifiers"""
    print_json(MobileImageMounterService(lockdown=service_provider).query_personalization_identifiers())


@cli.command("query-personalization-manifest")
def mounter_query_personalization_manifest(service_provider: ServiceProviderDep) -> None:
    """Query personalization manifest"""
    result = []
    mounter = MobileImageMounterService(lockdown=service_provider)
    for device in mounter.copy_devices():
        result.append(mounter.query_personalization_manifest(device["PersonalizedImageType"], device["ImageSignature"]))
    print_json(result)


@cli.command("roll-personalization-nonce")
def mounter_roll_personalization_nonce(service_provider: ServiceProviderDep) -> None:
    MobileImageMounterService(lockdown=service_provider).roll_personalization_nonce()


@cli.command("roll-cryptex-nonce")
def mounter_roll_cryptex_nonce(service_provider: ServiceProviderDep) -> None:
    """Roll cryptex nonce (will reboot)"""
    MobileImageMounterService(lockdown=service_provider).roll_cryptex_nonce()
