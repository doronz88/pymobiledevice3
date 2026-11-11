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
    NoSuchBuildIdentityError,
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
    help="Mount, unmount and inspect the DeveloperDiskImage (DDI) needed by developer commands.",
    no_args_is_help=True,
)


@cli.command("list")
@async_command
async def mounter_list(service_provider: ServiceProviderDep) -> None:
    """List the disk images currently mounted on the device."""
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
async def mounter_lookup(
    service_provider: ServiceProviderDep,
    image_type: Annotated[
        str, typer.Argument(help="Image type to look up: `Developer` (iOS < 17) or `Personalized` (iOS 17+).")
    ],
) -> None:
    """Print the signature of the mounted image of the given type, if one is mounted."""
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
    """Unmount the classic DeveloperDiskImage (iOS < 17)."""
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
    """Unmount the personalized DeveloperDiskImage (iOS 17+).

    A DDI installed as a cryptex (see `cryptex list`) is removed with
    `cryptex uninstall com.apple.MobileAsset.DDI` instead.
    """
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
            help="DeveloperDiskImage.dmg file.",
        ),
    ],
    signature: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="Matching DeveloperDiskImage.dmg.signature file.",
        ),
    ],
) -> None:
    """Mount a classic DeveloperDiskImage from local files (iOS < 17).

    Requires Developer Mode on iOS 16. Most users want `auto-mount` instead.
    """
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
            help="Personalized image file (Image.dmg).",
        ),
    ],
    trust_cache: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="Trust cache shipped with the image (e.g. Image.trustcache).",
        ),
    ],
    build_manifest: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="BuildManifest.plist shipped with the image.",
        ),
    ],
) -> None:
    """Mount a personalized DeveloperDiskImage from local files (iOS 17+).

    Reuses a personalization ticket already stored on the device, otherwise requests
    one from Apple's signing server (needs Internet). Requires Developer Mode.
    Most users want `auto-mount` instead.
    """
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
            help="iOS < 17 only: Xcode.app to take the DeveloperDiskImage from (default: /Applications/Xcode.app, "
            "falling back to a download cache in the home folder).",
        ),
    ] = None,
    version: Annotated[
        Optional[str],
        typer.Option(
            help="iOS < 17 only: DeveloperDiskImage version (major.minor) to use instead of the device's iOS version."
        ),
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
    """Download (if needed) and mount the right DeveloperDiskImage for the device.

    Picks the image by iOS version and downloads it when it is not available locally;
    iOS 17+ images are personalized for the device through Apple's signing server
    (needs Internet). Requires Developer Mode.

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
    except NoSuchBuildIdentityError as e:
        # Only the PersonalizedDMG is matched by board; the cryptex fits any device
        logger.error(
            f"{e} The personalized-dmg image does not support this device; "
            "use the cryptex one instead (`--image cryptex`, the default from iOS 27)."
        )
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
    """Print whether Developer Mode is enabled, as reported by the image mounter."""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        print_json(await mounter.query_developer_mode_status())


@cli.command("query-nonce")
@async_command
async def mounter_query_nonce(
    service_provider: ServiceProviderDep,
    image_type: Annotated[
        Optional[str],
        typer.Option(
            help="Personalized image type to query the nonce for (e.g. `DeveloperDiskImage`); "
            "omitted or unrecognized, the device returns its default nonce."
        ),
    ] = None,
) -> None:
    """Print the personalization nonce used to sign images for this device."""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        print_json(await mounter.query_nonce(image_type))


@cli.command("query-personalization-identifiers")
@async_command
async def mounter_query_personalization_identifiers(service_provider: ServiceProviderDep) -> None:
    """Print the identifiers used to personalize images for this device (board ID, chip ID, ...)."""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        print_json(await mounter.query_personalization_identifiers())


@cli.command("query-personalization-manifest")
@async_command
async def mounter_query_personalization_manifest(service_provider: ServiceProviderDep) -> None:
    """Print the personalization manifest (IM4M) of each mounted personalized image."""
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
    """Ask the device to generate a new personalization nonce."""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        await mounter.roll_personalization_nonce()


@cli.command("roll-cryptex-nonce")
@async_command
async def mounter_roll_cryptex_nonce(service_provider: ServiceProviderDep) -> None:
    """Ask the device to generate a new cryptex nonce (the device reboots)."""
    async with MobileImageMounterService(lockdown=service_provider) as mounter:
        await mounter.roll_cryptex_nonce()
