import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobile_activation import MobileActivationService


@click.group()
def cli() -> None:
    pass


@cli.group()
def activation() -> None:
    """Perform iCloud activation/deactivation or query the current state"""
    pass


@activation.command(cls=Command)
def state(service_provider: LockdownClient):
    """Get current activation state"""
    print(MobileActivationService(service_provider).state)


@activation.command(cls=Command)
@click.option("--now", is_flag=True, help="do not wait for next nonce cycle")
def activate(service_provider: LockdownClient, now):
    """Activate device"""
    activation_service = MobileActivationService(service_provider)
    if not now:
        activation_service.wait_for_activation_session()
    activation_service.activate()


@activation.command(cls=Command)
def deactivate(service_provider: LockdownClient):
    """Deactivate device"""
    MobileActivationService(service_provider).deactivate()


@activation.command(cls=Command)
def itunes(service_provider: LockdownClient):
    """Tell the device that it has been connected to iTunes (useful for < iOS 4)"""
    service_provider.set_value(True, key="iTunesHasConnected")
