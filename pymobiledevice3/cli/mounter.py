import logging
from functools import update_wrapper
from pathlib import Path
from typing import Annotated, Any, Callable, Optional
from urllib.error import URLError

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.exceptions import (
    AlreadyMountedError,
    DeveloperDiskImageNotFoundError,
    NotMountedError,
    UnsupportedCommandError,
)
from pymobiledevice3.services.mobile_image_mounter import (
    DeveloperDiskImageMounter,
    MobileImageMounterService,
    PersonalizedDdi,
    PersonalizedImageMounter,
    auto_mount,
    uses_personalized_image,
)

logger = logging.getLogger(__name__)

#: How to remove an iOS 17+ DeveloperDiskImage. Which one applies depends on the front-end that put
#: it there: `cryptex list` shows the DDI only when it was installed as a cryptex.
PERSONALIZED_DDI_REMOVAL_HINT = (
    "remove it first with `cryptex uninstall com.apple.MobileAsset.DDI` (if `cryptex list` shows it) "
    "or `mounter umount-personalized`"
)


def catch_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    def catch_function(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except AlreadyMountedError as e:
            logger.error("Given image was already mounted")
            raise typer.Exit(1) from e
        except UnsupportedCommandError as e:
            logger.error("Your iOS version doesn't support this command")
            raise typer.Exit(1) from e

    return update_wrapper(catch_function, func)


cli = InjectingTyper(
    name="mounter",
    help="Mount/Umount DeveloperDiskImage or query related info",
    no_args_is_help=True,
)


@cli.command("list")
@async_command
async def mounter_list(service_provider: ServiceProviderDep) -> None:
    """list all mounted images"""
    output: list[dict[str, Any]] = []

    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        images = await mounter.list_images()
    for image in images:
        image_signature = image.get("ImageSignature")
        if image_signature is not None:
            image["ImageSignature"] = image_signature.hex()
        output.append(image)

    print_json(output)


@cli.command("lookup")
@async_command
async def mounter_lookup(service_provider: ServiceProviderDep, image_type: str) -> None:
    """lookup mounter image type"""
    try:
        async with MobileImageMounterService(lockdown=service_provider) as mounter:
            signature = await mounter.lookup_image(image_type)
        print_json(signature)
    except NotMountedError:
        logger.error(f"Disk image of type: {image_type} is not mounted")


@cli.command("umount-developer")
@catch_errors
@async_command
async def mounter_umount_developer(service_provider: ServiceProviderDep) -> None:
    """unmount Developer image"""
    try:
        async with DeveloperDiskImageMounter(lockdown=service_provider) as mounter:
            await mounter.umount()
        logger.info("Developer image unmounted successfully")
    except NotMountedError:
        logger.error("Developer image isn't currently mounted")


@cli.command("umount-personalized")
@catch_errors
@async_command
async def mounter_umount_personalized(service_provider: ServiceProviderDep) -> None:
    """unmount Personalized image"""
    try:
        async with PersonalizedImageMounter(lockdown=service_provider) as mounter:
            await mounter.umount()
        logger.info("Personalized image unmounted successfully")
    except NotMountedError:
        logger.error("Personalized image isn't currently mounted")


@cli.command("mount-developer")
@catch_errors
@async_command
async def mounter_mount_developer(
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
    async with DeveloperDiskImageMounter(lockdown=service_provider) as mounter:
        await mounter.mount(image, signature)
    logger.info("Developer image mounted successfully")


@cli.command("mount-personalized")
@catch_errors
@async_command
async def mounter_mount_personalized(
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
    async with PersonalizedImageMounter(lockdown=service_provider) as mounter:
        await mounter.mount(Path(image), Path(build_manifest), Path(trust_cache))
    logger.info("Personalized image mounted successfully")


@cli.command("auto-mount")
@async_command
async def mounter_auto_mount(
    service_provider: ServiceProviderDep,
    xcode: Annotated[
        Optional[Path],
        typer.Option(
            "--xcode",
            "-x",
            exists=True,
            file_okay=False,
            dir_okay=True,
            help="Xcode application path used to figure out automatically the DeveloperDiskImage path",
        ),
    ] = None,
    version: Annotated[
        Optional[str],
        typer.Option(help="Use a different DeveloperDiskImage version from the one retrieved by lockdownconnection"),
    ] = None,
    image: Annotated[
        Optional[PersonalizedDdi],
        typer.Option(
            "--image",
            help="iOS 17+ only: force this DeveloperDiskImage instead of choosing one by iOS version "
            "(cryptex from iOS 27, personalized-dmg below it)",
        ),
    ] = None,
) -> None:
    """auto-detect correct DeveloperDiskImage and mount it

    Exits non-zero when no image could be mounted. An image that is already mounted is what was
    asked for, so that succeeds -- scripts can run this unconditionally before developer commands.
    """
    if image is not None and not uses_personalized_image(service_provider):
        logger.error(f"--image {image.value} needs iOS 17 or later")
        raise typer.Exit(1)
    try:
        await auto_mount(
            service_provider, xcode=str(xcode) if xcode is not None else None, version=version, image=image
        )
        logger.info("DeveloperDiskImage mounted successfully")
    except AlreadyMountedError:
        if uses_personalized_image(service_provider):
            logger.info(f"DeveloperDiskImage already mounted; to replace it, {PERSONALIZED_DDI_REMOVAL_HINT}")
        else:
            logger.info("DeveloperDiskImage already mounted; to replace it, run `mounter umount-developer` first")
    except URLError as e:
        logger.error("failed to query DeveloperDiskImage versions")
        raise typer.Exit(1) from e
    except DeveloperDiskImageNotFoundError as e:
        logger.error("Unable to find the correct DeveloperDiskImage")
        raise typer.Exit(1) from e
    except PermissionError as e:
        logger.error(
            f"DeveloperDiskImage could not be saved to Xcode default path ({e.filename}). "
            f"Please make sure your user has the necessary permissions"
        )
        raise typer.Exit(1) from e


@cli.command("query-developer-mode-status")
@async_command
async def mounter_query_developer_mode_status(service_provider: ServiceProviderDep) -> None:
    """Query developer mode status"""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        print_json(await mounter.query_developer_mode_status())


@cli.command("query-nonce")
@async_command
async def mounter_query_nonce(
    service_provider: ServiceProviderDep, image_type: Annotated[Optional[str], typer.Option()] = None
) -> None:
    """Query nonce"""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        print_json(await mounter.query_nonce(image_type))


@cli.command("query-personalization-identifiers")
@async_command
async def mounter_query_personalization_identifiers(service_provider: ServiceProviderDep) -> None:
    """Query personalization identifiers"""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        print_json(await mounter.query_personalization_identifiers())


@cli.command("query-personalization-manifest")
@async_command
async def mounter_query_personalization_manifest(service_provider: ServiceProviderDep) -> None:
    """Query personalization manifest"""
    result: list[bytes] = []
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        for device in await mounter.copy_devices():
            result.append(
                await mounter.query_personalization_manifest(device["PersonalizedImageType"], device["ImageSignature"])
            )
    print_json(result)


@cli.command("roll-personalization-nonce")
@async_command
async def mounter_roll_personalization_nonce(service_provider: ServiceProviderDep) -> None:
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        await mounter.roll_personalization_nonce()


@cli.command("roll-cryptex-nonce")
@async_command
async def mounter_roll_cryptex_nonce(service_provider: ServiceProviderDep) -> None:
    """Roll cryptex nonce (will reboot)"""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        await mounter.roll_cryptex_nonce()
