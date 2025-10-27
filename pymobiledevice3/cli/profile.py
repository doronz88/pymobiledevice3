import logging
import plistlib
import tempfile
from pathlib import Path
from typing import IO, Optional

import click

from pymobiledevice3.ca import create_keybag_file
from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.mobile_activation import MobileActivationService
from pymobiledevice3.services.mobile_config import MobileConfigService

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group("profile")
def profile_group() -> None:
    """Managed installed profiles or install SSL certificates"""
    pass


@profile_group.command("list", cls=Command)
def profile_list(service_provider: LockdownClient):
    """List installed profiles"""
    print_json(MobileConfigService(lockdown=service_provider).get_profile_list())


@profile_group.command("install", cls=Command)
@click.option("--keybag", type=click.Path(file_okay=True, dir_okay=False, exists=True))
@click.argument("profiles", nargs=-1, type=click.File("rb"))
def profile_install(service_provider: LockdownServiceProvider, keybag: Optional[str], profiles: list[IO]) -> None:
    """
    Install given profiles

    If given a keybag, use that to install the profile silently
    """
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f"installing {profile.name}")
        if keybag is not None:
            service.install_profile_silent(Path(keybag), profile.read())
        else:
            service.install_profile(profile.read())


@profile_group.command("cloud-configuration", cls=Command)
@click.argument("config", type=click.File("rb"), required=False)
def profile_cloud_configuration(service_provider: LockdownServiceProvider, config: Optional[IO]) -> None:
    """Get/Set cloud configuration"""
    if not config:
        print_json(MobileConfigService(lockdown=service_provider).get_cloud_configuration())
    else:
        config_json = plistlib.load(config)
        logger.info(f"applying cloud configuration {config_json}")
        MobileConfigService(lockdown=service_provider).set_cloud_configuration(config_json)
        logger.info("applied cloud configuration")


@profile_group.command("store", cls=Command)
@click.argument("profiles", nargs=-1, type=click.File("rb"))
def profile_store(service_provider: LockdownServiceProvider, profiles: list[IO]) -> None:
    """Store a profile"""
    service = MobileConfigService(lockdown=service_provider)
    for profile in profiles:
        logger.info(f"storing {profile.name}")
        service.store_profile(profile.read())


@profile_group.command("remove", cls=Command)
@click.argument("name")
def profile_remove(service_provider: LockdownServiceProvider, name: str) -> None:
    """Remove a profile by its name"""
    MobileConfigService(lockdown=service_provider).remove_profile(name)


@profile_group.command("set-wifi-power", cls=Command)
@click.argument("state", type=click.Choice(["on", "off"]), required=False)
def profile_set_wifi_power(service_provider: LockdownServiceProvider, state: str) -> None:
    """change Wi-Fi power state"""
    MobileConfigService(lockdown=service_provider).set_wifi_power_state(state == "on")


@profile_group.command("erase-device", cls=Command)
@click.option(
    "--preserve-data-plan/--no-preserve-data-plan", default=True, help="Preserves eSIM / data plan after erase"
)
@click.option(
    "--disallow-proximity-setup/--no-disallow-proximity-setup",
    default=False,
    help="Disallows to setup the erased device from nearby devices",
)
def profile_erase_device(
    service_provider: LockdownServiceProvider, preserve_data_plan: bool, disallow_proximity_setup: bool
) -> None:
    """Erase device"""
    logger.info(
        f"Erasing device with preserve_data_plan: {preserve_data_plan}, "
        f"disallow_proximity_setup: {disallow_proximity_setup}"
    )
    MobileConfigService(lockdown=service_provider).erase_device(preserve_data_plan, disallow_proximity_setup)
    logger.info("Erased device")


@profile_group.command("create-keybag")
@click.argument("keybag", type=click.Path(file_okay=True, dir_okay=False, exists=False))
@click.argument("organization")
def profile_create_keybag(keybag: str, organization: str) -> None:
    """Create keybag storing certificate and private key"""
    create_keybag_file(Path(keybag), organization)


@profile_group.command("supervise", cls=Command)
@click.argument("organization")
@click.option("--keybag", type=click.Path(file_okay=True, dir_okay=False, exists=True))
def profile_supervise(service_provider: LockdownServiceProvider, organization: str, keybag: Optional[str]) -> None:
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


@profile_group.command("install-wifi-profile", cls=Command)
@click.argument("encryption_type")
@click.argument("ssid")
@click.argument("password")
@click.option("--keybag", type=click.Path(file_okay=True, dir_okay=False, exists=True))
def profile_install_wifi_profile(
    service_provider: LockdownServiceProvider, encryption_type: str, ssid: str, password: str, keybag: Optional[str]
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


@profile_group.command("install-http-proxy", cls=Command)
@click.argument("server")
@click.argument("port", type=click.IntRange(1, 65535))
@click.option("--keybag", type=click.Path(file_okay=True, dir_okay=False, exists=True))
def profile_install_http_proxy(
    service_provider: LockdownServiceProvider, server: str, port: int, keybag: Optional[str]
) -> None:
    """Install HTTP Proxy profile"""
    if keybag is not None:
        keybag = Path(keybag)
    MobileConfigService(lockdown=service_provider).install_http_proxy(server, port, keybag_file=keybag)


@profile_group.command("remove-http-proxy", cls=Command)
def profile_remove_http_proxy(service_provider: LockdownServiceProvider) -> None:
    """Remove HTTP Proxy profile that was previously installed using pymobiledevice3"""
    MobileConfigService(lockdown=service_provider).remove_http_proxy()


@profile_group.command("install-restrictions-profile", cls=Command)
@click.option("--keybag", type=click.Path(file_okay=True, dir_okay=False, exists=True))
@click.option("--enforced-software-update-delay", type=click.IntRange(0, 90), default=0)
def profile_install_restrictions_profile(
    service_provider: LockdownServiceProvider, keybag: Optional[str], enforced_software_update_delay: int
) -> None:
    """Install restrictions profile (can be used for delayed OTA)"""
    if keybag is not None:
        keybag = Path(keybag)
    MobileConfigService(lockdown=service_provider).install_restrictions_profile(
        enforced_software_update_delay=enforced_software_update_delay, keybag_file=keybag
    )
