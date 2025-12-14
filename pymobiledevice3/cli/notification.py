import logging
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep
from pymobiledevice3.resources.firmware_notifications import get_notifications
from pymobiledevice3.services.notification_proxy import NotificationProxyService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="notifications",
    help="Post or observe Darwin notifications via notification_proxy.",
    no_args_is_help=True,
)


@cli.command()
def post(
    service_provider: ServiceProviderDep,
    names: list[str],
    insecure: Annotated[
        bool,
        typer.Option(help="Use the insecure relay meant for untrusted clients instead of the trusted channel."),
    ],
) -> None:
    """Post one or more Darwin notifications (notify_post)."""
    service = NotificationProxyService(lockdown=service_provider, insecure=insecure)
    for name in names:
        service.notify_post(name)


@cli.command()
def observe(
    service_provider: ServiceProviderDep,
    names: list[str],
    insecure: Annotated[
        bool,
        typer.Option(help="Use the insecure relay meant for untrusted clients instead of the trusted channel."),
    ],
) -> None:
    """Subscribe and stream notifications (notify_register_dispatch)."""
    service = NotificationProxyService(lockdown=service_provider, insecure=insecure)
    for name in names:
        service.notify_register_dispatch(name)

    for event in service.receive_notification():
        logger.info(event)


@cli.command("observe-all")
def observe_all(
    service_provider: ServiceProviderDep,
    insecure: Annotated[
        bool,
        typer.Option(help="Use the insecure relay meant for untrusted clients instead of the trusted channel."),
    ],
) -> None:
    """Subscribe to all known firmware notifications and stream events."""
    service = NotificationProxyService(lockdown=service_provider, insecure=insecure)
    for notification in get_notifications():
        service.notify_register_dispatch(notification)

    for event in service.receive_notification():
        logger.info(event)
