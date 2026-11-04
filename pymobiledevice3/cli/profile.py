import logging
import plistlib
import tempfile
from pathlib import Path
from typing import Annotated, Literal, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.ca import create_keybag_file
from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.mobile_activation import MobileActivationService
from pymobiledevice3.services.mobile_config import MobileConfigService, WallpaperScreen

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="profile",
    help="Install and remove configuration profiles, supervise the device, and other MDM-style management.",
    no_args_is_help=True,
)


@cli.command("list")
@async_command
async def profile_list(service_provider: ServiceProviderDep) -> None:
    """Print the installed configuration profiles."""
    print_json(await MobileConfigService(lockdown=service_provider).get_profile_list())


@cli.command("install")
@async_command
async def profile_install(
    service_provider: ServiceProviderDep,
    profiles: Annotated[list[Path], typer.Argument(help="Configuration profile files (.mobileconfig).")],
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="Supervision identity (PEM with the supervisor certificate and private key) to install "
            "silently; without it the user must approve the profile on the device.",
        ),
    ] = None,
) -> None:
    """Install configuration profiles (.mobileconfig).

    Without --keybag the device asks the user to approve each profile; with a
    supervision identity (supervised devices) it is installed silently.
    """
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f"installing {profile}")
        if keybag is not None:
            await service.install_profile_silent(Path(keybag), profile.read_bytes())
        else:
            await service.install_profile(profile.read_bytes())


@cli.command("cloud-configuration")
@async_command
async def profile_cloud_configuration(
    service_provider: ServiceProviderDep,
    config: Annotated[
        Optional[Path], typer.Argument(help="Cloud configuration plist to apply; omit to print the current one.")
    ] = None,
) -> None:
    """Print the device's cloud (supervision/DEP) configuration, or apply one from a plist."""
    if not config:
        print_json(await MobileConfigService(lockdown=service_provider).get_cloud_configuration())
    else:
        with config.open("rb") as config_file:
            config_json = plistlib.load(config_file)
        logger.info(f"applying cloud configuration {config_json}")
        await MobileConfigService(lockdown=service_provider).set_cloud_configuration(config_json)
        logger.info("applied cloud configuration")


@cli.command("download-cloud-configuration")
@async_command
async def profile_download_cloud_configuration(
    service_provider: ServiceProviderDep,
    username: Annotated[
        Optional[str],
        typer.Option(help="MDM enrollment username."),
    ] = None,
    password: Annotated[
        Optional[str],
        typer.Option(help="MDM enrollment password."),
    ] = None,
) -> None:
    """Ask the device to download and apply its DEP cloud configuration (needs Internet on the device)."""
    async with MobileConfigService(lockdown=service_provider) as service:
        logger.info("downloading and applying DEP cloud configuration")
        await service.download_and_apply_cloud_configuration(username=username, password=password)
        logger.info("downloaded and applied DEP cloud configuration")


@cli.command("store")
@async_command
async def profile_store(
    service_provider: ServiceProviderDep,
    profiles: Annotated[list[Path], typer.Argument(help="Configuration profile files (.mobileconfig).")],
) -> None:
    """Store profiles on the device for installation after setup, without installing them now."""
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f"storing {profile.name}")
        await service.store_profile(profile.read_bytes())


@cli.command("remove")
@async_command
async def profile_remove(
    service_provider: ServiceProviderDep,
    name: Annotated[str, typer.Argument(help="Profile identifier, as listed under ProfileMetadata by `profile list`.")],
) -> None:
    """Remove an installed configuration profile by its identifier."""
    await MobileConfigService(lockdown=service_provider).remove_profile(name)


@cli.command("set-wifi-power")
@async_command
async def profile_set_wifi_power(
    service_provider: ServiceProviderDep,
    state: Annotated[Literal["on", "off"], typer.Argument(help="Turn Wi-Fi on or off.")] = "off",
) -> None:
    """Turn the device's Wi-Fi radio on or off (defaults to off)."""
    await MobileConfigService(lockdown=service_provider).set_wifi_power_state(state == "on")


@cli.command("erase-device")
@async_command
async def profile_erase_device(
    service_provider: ServiceProviderDep,
    preserve_data_plan: Annotated[
        bool,
        typer.Option(help="Keep the eSIM / cellular data plan across the erase."),
    ] = True,
    disallow_proximity_setup: Annotated[
        bool,
        typer.Option(help="Prevent setting up the erased device from a nearby device (Quick Start)."),
    ] = False,
) -> None:
    """Erase all content and settings from the device. DESTRUCTIVE.

    Wipes the device back to factory state (like Settings > General > Transfer
    or Reset > Erase All Content and Settings). There is no confirmation.
    """
    logger.info(
        f"Erasing device with preserve_data_plan: {preserve_data_plan}, "
        f"disallow_proximity_setup: {disallow_proximity_setup}"
    )
    await MobileConfigService(lockdown=service_provider).erase_device(preserve_data_plan, disallow_proximity_setup)
    logger.info("Erased device")


@cli.command("create-keybag")
def profile_create_keybag(
    keybag: Annotated[
        Path,
        typer.Argument(
            exists=False,
            file_okay=True,
            dir_okay=False,
            help="File to write the new identity (PEM private key + certificate) to.",
        ),
    ],
    organization: Annotated[str, typer.Argument(help="Organization name for the certificate's Common Name.")],
) -> None:
    """Create a supervision identity (keybag) for `supervise` and silent profile installs.

    Runs locally; no device needed.
    """
    create_keybag_file(keybag, organization)


@cli.command("supervise")
@async_command
async def profile_supervise(
    service_provider: ServiceProviderDep,
    organization: Annotated[str, typer.Argument(help="Organization name shown on the device as the supervisor.")],
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="Supervision identity to register (see `create-keybag`). If omitted, a throwaway one is "
            "generated, so later supervised-only commands cannot be used.",
        ),
    ] = None,
) -> None:
    """Supervise the device under your organization.

    Activates the device first if it is not activated yet, then writes a
    supervised cloud configuration that registers the supervision identity.
    """
    if await MobileActivationService(service_provider).state() == "Unactivated":
        logger.info("Activating device")
        await MobileActivationService(service_provider).activate()
        logger.info("Device has been successfully activated")
    logger.info("Supervising device")
    if keybag is None:
        with tempfile.TemporaryDirectory() as temp_dir:
            keybag = Path(temp_dir) / "keybag"
            create_keybag_file(keybag, organization)
            await MobileConfigService(lockdown=service_provider).supervise(organization, keybag)
    else:
        await MobileConfigService(lockdown=service_provider).supervise(organization, Path(keybag))

    logger.info("Device has been successfully supervised")


@cli.command("install-wifi-profile")
@async_command
async def profile_install_wifi_profile(
    service_provider: ServiceProviderDep,
    encryption_type: Annotated[str, typer.Argument(help="Network security type (e.g. WPA, WEP, None).")],
    ssid: Annotated[str, typer.Argument(help="Network name (SSID).")],
    password: Annotated[str, typer.Argument(help="Network password.")],
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="Supervision identity (PEM with the supervisor certificate and private key) to install "
            "silently; without it the user must approve the profile on the device.",
        ),
    ] = None,
) -> None:
    """Install a Wi-Fi profile so the device joins the given network automatically."""
    if keybag is not None:
        keybag = Path(keybag)
    await MobileConfigService(lockdown=service_provider).install_wifi_profile(
        encryption_type=encryption_type, ssid=ssid, password=password, keybag_file=keybag
    )


@cli.command("install-http-proxy")
@async_command
async def profile_install_http_proxy(
    service_provider: ServiceProviderDep,
    server: Annotated[str, typer.Argument(help="Proxy server host name or address.")],
    port: Annotated[
        int,
        typer.Argument(min=1, max=0xFFFF, help="Proxy server port."),
    ],
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="Supervision identity (PEM with the supervisor certificate and private key) to install "
            "silently; without it the user must approve the profile on the device.",
        ),
    ] = None,
) -> None:
    """Install a profile that routes the device's HTTP traffic through a global proxy."""
    if keybag is not None:
        keybag = Path(keybag)
    await MobileConfigService(lockdown=service_provider).install_http_proxy(server, port, keybag_file=keybag)


@cli.command("remove-http-proxy")
@async_command
async def profile_remove_http_proxy(service_provider: ServiceProviderDep) -> None:
    """Remove the HTTP proxy profile installed by `install-http-proxy`."""
    await MobileConfigService(lockdown=service_provider).remove_http_proxy()


@cli.command("install-restrictions-profile")
@async_command
async def profile_install_restrictions_profile(
    service_provider: ServiceProviderDep,
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
            help="Supervision identity (PEM with the supervisor certificate and private key) to install "
            "silently; without it the user must approve the profile on the device.",
        ),
    ] = None,
    enforced_software_update_delay: Annotated[
        int,
        typer.Option(min=0, max=90, help="Days to delay software updates from showing up (0-90)."),
    ] = 0,
) -> None:
    """Install a restrictions profile, e.g. to delay software (OTA) updates."""
    if keybag is not None:
        keybag = Path(keybag)
    await MobileConfigService(lockdown=service_provider).install_restrictions_profile(
        enforced_software_update_delay=enforced_software_update_delay, keybag_file=keybag
    )


KeybagOption = Annotated[
    Path,
    typer.Option(
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Supervision identity (PEM with the supervisor certificate and private key).",
    ),
]


@cli.command("request-unlock-token")
@async_command
async def profile_request_unlock_token(
    service_provider: ServiceProviderDep,
    keybag: KeybagOption,
    output: Annotated[Path, typer.Argument(dir_okay=False, help="File to write the raw unlock token to.")],
) -> None:
    """
    Save the passcode unlock token (supervised devices only).

    The device must have no passcode set. The token can later be passed to `clear-passcode`.
    """
    async with MobileConfigService(lockdown=service_provider) as service:
        await service.escalate(keybag)
        token = await service.request_unlock_token()
    output.touch(mode=0o600, exist_ok=True)
    output.chmod(0o600)
    output.write_bytes(token)
    logger.info(f"wrote a {len(token)}-byte unlock token to {output}")


@cli.command("clear-passcode")
@async_command
async def profile_clear_passcode(
    service_provider: ServiceProviderDep,
    keybag: KeybagOption,
    token: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=False, help="Unlock token saved by request-unlock-token."),
    ],
) -> None:
    """
    Remove the device passcode using a saved unlock token (supervised devices only).

    The device then drops this host's pairing; re-pair without a prompt using
    `lockdown pair-supervised`.
    """
    async with MobileConfigService(lockdown=service_provider) as service:
        await service.escalate(keybag)
        await service.clear_passcode(token.read_bytes())
    logger.info(
        "cleared the passcode; the device dropped this host's pairing (re-pair with `lockdown pair-supervised`)"
    )


@cli.command("clear-restrictions-password")
@async_command
async def profile_clear_restrictions_password(service_provider: ServiceProviderDep, keybag: KeybagOption) -> None:
    """
    Clear the Screen Time passcode (supervised devices only).

    iOS 27.2 rejects it device-side (its sandbox blocks the Screen Time agent lookup).
    """
    async with MobileConfigService(lockdown=service_provider) as service:
        await service.escalate(keybag)
        await service.clear_restrictions_password()
    logger.info("cleared the Screen Time passcode")


@cli.command("security-info")
@async_command
async def profile_security_info(service_provider: ServiceProviderDep, keybag: KeybagOption) -> None:
    """
    Show the device's security status (supervised devices only).

    PasscodePresent reliably tells whether a passcode is set, unlike lockdown's
    PasswordProtected.
    """
    async with MobileConfigService(lockdown=service_provider) as service:
        await service.escalate(keybag)
        print_json(await service.get_security_info())


@cli.command("set-wallpaper")
@async_command
async def profile_set_wallpaper(
    service_provider: ServiceProviderDep,
    keybag: KeybagOption,
    image: Annotated[Path, typer.Argument(exists=True, file_okay=True, dir_okay=False, help="JPEG or PNG image.")],
    screen: Annotated[
        Literal["lock", "home", "both"],
        typer.Option(help="Screen(s) to apply the wallpaper to; iOS 16+ may apply it to both regardless."),
    ] = "home",
) -> None:
    """Set the wallpaper (supervised devices only)."""
    async with MobileConfigService(lockdown=service_provider) as service:
        await service.escalate(keybag)
        await service.set_wallpaper(image.read_bytes(), WallpaperScreen[screen.upper()])
    logger.info("set the wallpaper")
