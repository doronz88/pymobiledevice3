import logging

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.resources.firmware_notifications import get_notifications
from pymobiledevice3.services.notification_proxy import NotificationProxyService

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group()
def notification() -> None:
    """Post/Observe notifications"""
    pass


@notification.command(cls=Command)
@click.argument("names", nargs=-1)
@click.option("--insecure", is_flag=True, help="use the insecure relay meant for untrusted clients instead")
def post(service_provider: LockdownClient, names, insecure):
    """API for notify_post()."""
    service = NotificationProxyService(lockdown=service_provider, insecure=insecure)
    for name in names:
        service.notify_post(name)


@notification.command(cls=Command)
@click.argument("names", nargs=-1)
@click.option("--insecure", is_flag=True, help="use the insecure relay meant for untrusted clients instead")
def observe(service_provider: LockdownClient, names, insecure):
    """API for notify_register_dispatch()."""
    service = NotificationProxyService(lockdown=service_provider, insecure=insecure)
    for name in names:
        service.notify_register_dispatch(name)

    for event in service.receive_notification():
        logger.info(event)


@notification.command("observe-all", cls=Command)
@click.option("--insecure", is_flag=True, help="use the insecure relay meant for untrusted clients instead")
def observe_all(service_provider: LockdownClient, insecure):
    """attempt to observe all builtin firmware notifications."""
    service = NotificationProxyService(lockdown=service_provider, insecure=insecure)
    for notification in get_notifications():
        service.notify_register_dispatch(notification)

    for event in service.receive_notification():
        logger.info(event)
