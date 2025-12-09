import logging
import plistlib
import tempfile
from pathlib import Path
from typing import Annotated, Literal, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.ca import create_keybag_file
from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.services.mobile_activation import MobileActivationService
from pymobiledevice3.services.mobile_config import MobileConfigService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="profile",
    help="Manage installed profiles or install SSL certificates",
    no_args_is_help=True,
)


@cli.command("list")
def profile_list(service_provider: ServiceProviderDep) -> None:
    """List installed profiles"""
    print_json(MobileConfigService(lockdown=service_provider).get_profile_list())


@cli.command("install")
def profile_install(
    service_provider: ServiceProviderDep,
    profiles: list[Path],
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
) -> None:
    """
    Install given profiles

    If given a keybag, use that to install the profile silently
    """
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f"installing {profile}")
        if keybag is not None:
            service.install_profile_silent(Path(keybag), profile.read_bytes())
        else:
            service.install_profile(profile.read_bytes())


@cli.command("cloud-configuration")
def profile_cloud_configuration(service_provider: ServiceProviderDep, config: Optional[Path] = None) -> None:
    """Get/Set cloud configuration"""
    if not config:
        print_json(MobileConfigService(lockdown=service_provider).get_cloud_configuration())
    else:
        with config.open("rb") as config_file:
            config_json = plistlib.load(config_file)
        logger.info(f"applying cloud configuration {config_json}")
        MobileConfigService(lockdown=service_provider).set_cloud_configuration(config_json)
        logger.info("applied cloud configuration")


@cli.command("store")
def profile_store(service_provider: ServiceProviderDep, profiles: list[Path]) -> None:
    """Store a profile"""
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f"storing {profile.name}")
        service.store_profile(profile.read_bytes())


@cli.command("remove")
def profile_remove(service_provider: ServiceProviderDep, name: str) -> None:
    """Remove a profile by its name"""
    MobileConfigService(lockdown=service_provider).remove_profile(name)


@cli.command("set-wifi-power")
def profile_set_wifi_power(service_provider: ServiceProviderDep, state: Literal["on", "off"] = "off") -> None:
    """change Wi-Fi power state"""
    MobileConfigService(lockdown=service_provider).set_wifi_power_state(state == "on")


@cli.command("erase-device")
def profile_erase_device(
    service_provider: ServiceProviderDep,
    preserve_data_plan: Annotated[
        bool,
        typer.Option(help="Preserves eSIM / data plan after erase"),
    ] = True,
    disallow_proximity_setup: Annotated[
        bool,
        typer.Option(help="Disallows setup of the erased device from nearby devices"),
    ] = False,
) -> None:
    """Erase device"""
    logger.info(
        f"Erasing device with preserve_data_plan: {preserve_data_plan}, "
        f"disallow_proximity_setup: {disallow_proximity_setup}"
    )
    MobileConfigService(lockdown=service_provider).erase_device(preserve_data_plan, disallow_proximity_setup)
    logger.info("Erased device")


@cli.command("create-keybag")
def profile_create_keybag(
    keybag: Annotated[
        Path,
        typer.Argument(
            exists=False,
            file_okay=True,
            dir_okay=False,
        ),
    ],
    organization: str,
) -> None:
    """Create keybag storing certificate and private key"""
    create_keybag_file(keybag, organization)


@cli.command("supervise")
def profile_supervise(
    service_provider: ServiceProviderDep,
    organization: str,
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
) -> None:
    """Supervise device"""
    if MobileActivationService(service_provider).state == "Unactivated":
        logger.info("Activating device")
        MobileActivationService(service_provider).activate()
        logger.info("Device has been successfully activated")
    logger.info("Supervising device")
    if keybag is None:
        with tempfile.TemporaryDirectory() as temp_dir:
            keybag = Path(temp_dir) / "keybag"
            create_keybag_file(keybag, organization)
            MobileConfigService(lockdown=service_provider).supervise(organization, keybag)
    else:
        MobileConfigService(lockdown=service_provider).supervise(organization, Path(keybag))

    logger.info("Device has been successfully supervised")


@cli.command("install-wifi-profile")
def profile_install_wifi_profile(
    service_provider: ServiceProviderDep,
    encryption_type: str,
    ssid: str,
    password: str,
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
) -> None:
    """
    Install Wi-Fi profile

    This will enable the device to auto-connect to given network
    """
    if keybag is not None:
        keybag = Path(keybag)
    MobileConfigService(lockdown=service_provider).install_wifi_profile(
        encryption_type=encryption_type, ssid=ssid, password=password, keybag_file=keybag
    )


@cli.command("install-http-proxy")
def profile_install_http_proxy(
    service_provider: ServiceProviderDep,
    server: str,
    port: Annotated[
        int,
        typer.Argument(min=1, max=0xFFFF),
    ],
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
) -> None:
    """Install HTTP Proxy profile"""
    if keybag is not None:
        keybag = Path(keybag)
    MobileConfigService(lockdown=service_provider).install_http_proxy(server, port, keybag_file=keybag)


@cli.command("remove-http-proxy")
def profile_remove_http_proxy(service_provider: ServiceProviderDep) -> None:
    """Remove HTTP Proxy profile that was previously installed using pymobiledevice3"""
    MobileConfigService(lockdown=service_provider).remove_http_proxy()


@cli.command("install-restrictions-profile")
def profile_install_restrictions_profile(
    service_provider: ServiceProviderDep,
    keybag: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
    enforced_software_update_delay: Annotated[
        int,
        typer.Option(min=0, max=90),
    ] = 0,
) -> None:
    """Install restrictions profile (can be used for delayed OTA)"""
    if keybag is not None:
        keybag = Path(keybag)
    MobileConfigService(lockdown=service_provider).install_restrictions_profile(
        enforced_software_update_delay=enforced_software_update_delay, keybag_file=keybag
    )
