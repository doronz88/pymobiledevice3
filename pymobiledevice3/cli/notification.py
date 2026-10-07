import asyncio
import logging
from contextlib import AsyncExitStack
from typing import Annotated, Union

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    RSDServiceProviderDep,
    ServiceProviderDep,
    async_command,
    print_json,
    print_json_line,
)
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
            print_json_line(event)


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
            print_json_line(event)


@cli.command("get-state")
@async_command
async def get_state(service_provider: RSDServiceProviderDep, names: list[str]) -> None:
    """Read the 64-bit state of one or more Darwin notifications (notify_get_state). iOS 27.2+."""
    async with RemoteNotificationProxyService(service_provider) as service:
        print_json({name: await service.notify_get_state(name) for name in names})


@cli.command("set-state")
@async_command
async def set_state(
    service_provider: RSDServiceProviderDep,
    name: str,
    state: int,
    post: Annotated[bool, typer.Option(help="Also post the notification, so observers pick the new state up.")] = True,
) -> None:
    """Set the 64-bit state of a Darwin notification (notify_set_state) and hold it. iOS 27.2+.

    The device keeps the state only while this command runs, and resets it to 0 afterwards.
    """
    async with RemoteNotificationProxyService(service_provider) as service:
        await service.notify_set_state(name, state)
        if post:
            await service.notify_post(name)
        print("> Hit Ctrl+C to release the state")
        await asyncio.Event().wait()
