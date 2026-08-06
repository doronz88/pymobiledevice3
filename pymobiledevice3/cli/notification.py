import logging
from contextlib import AsyncExitStack
from typing import Annotated, Union

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.resources.firmware_notifications import get_notifications
from pymobiledevice3.services.notification_proxy import NotificationProxyService, RemoteNotificationProxyService

logger = logging.getLogger(__name__)


RemoteXpcOption = Annotated[
    bool,
    typer.Option(
        "--remotexpc",
        help=(
            "Talk to the notification proxy directly over RemoteXPC instead of tunnelling the "
            "lockdown service through its shim. Requires an RSD tunnel (--rsd/--tunnel/--userspace)."
        ),
    ),
]
InsecureOption = Annotated[
    bool,
    typer.Option(help="Use the insecure relay meant for untrusted clients instead of the trusted channel."),
]


async def _open_service(
    stack: AsyncExitStack, service_provider: LockdownServiceProvider, insecure: bool, remotexpc: bool
) -> Union[NotificationProxyService, RemoteNotificationProxyService]:
    """Open either the lockdown notification proxy or its RemoteXPC counterpart."""
    if not remotexpc:
        return NotificationProxyService(lockdown=service_provider, insecure=insecure)
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        raise typer.BadParameter("--remotexpc requires an RSD tunnel (--rsd/--tunnel/--userspace)")
    return await stack.enter_async_context(RemoteNotificationProxyService(service_provider, insecure=insecure))


cli = InjectingTyper(
    name="notification",
    help="Post or observe Darwin notifications via notification_proxy.",
    no_args_is_help=True,
)


@cli.command()
@async_command
async def post(
    service_provider: ServiceProviderDep,
    names: list[str],
    insecure: InsecureOption = False,
    remotexpc: RemoteXpcOption = False,
) -> None:
    """Post one or more Darwin notifications (notify_post)."""
    async with AsyncExitStack() as stack:
        service = await _open_service(stack, service_provider, insecure, remotexpc)
        for name in names:
            await service.notify_post(name)


@cli.command()
@async_command
async def observe(
    service_provider: ServiceProviderDep,
    names: list[str],
    insecure: InsecureOption = False,
    remotexpc: RemoteXpcOption = False,
) -> None:
    """Subscribe and stream notifications (notify_register_dispatch)."""
    async with AsyncExitStack() as stack:
        service = await _open_service(stack, service_provider, insecure, remotexpc)
        for name in names:
            await service.notify_register_dispatch(name)

        async for event in service.receive_notification():
            logger.info(event)


@cli.command("observe-all")
@async_command
async def observe_all(
    service_provider: ServiceProviderDep,
    insecure: InsecureOption = False,
    remotexpc: RemoteXpcOption = False,
) -> None:
    """Subscribe to all known firmware notifications and stream events."""
    async with AsyncExitStack() as stack:
        service = await _open_service(stack, service_provider, insecure, remotexpc)
        for notification in get_notifications():
            await service.notify_register_dispatch(notification)

        async for event in service.receive_notification():
            logger.info(event)
