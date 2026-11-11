import asyncio
import logging
from contextlib import AsyncExitStack
from enum import Enum
from typing import Annotated, Any, Optional

import typer
from packaging.version import Version
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    OutputFormat,
    OutputFormatOption,
    ServiceProviderDep,
    async_command,
    print_json,
    print_json_line,
)
from pymobiledevice3.cli.developer.accessibility import settings
from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit, Direction
from pymobiledevice3.services.notification_proxy import RemoteNotificationProxyService

logger = logging.getLogger(__name__)


#: SpringBoard keeps this notification's state at 1 while the device is locked
LOCKSTATE_NOTIFICATION = "com.apple.springboard.lockstate"
#: From here the notification proxy can read a notification's state
NOTIFICATION_STATE_MIN_VERSION = Version("27.2")


async def _is_device_locked(service_provider: LockdownServiceProvider) -> Optional[bool]:
    """
    Whether SpringBoard reports the device locked; None where that cannot be read.

    The state is only readable over RemoteXPC, so a lockdown connection opens a tunnel for it.
    """
    try:
        if Version(service_provider.product_version) < NOTIFICATION_STATE_MIN_VERSION:
            return None
        return await asyncio.wait_for(_read_lock_state(service_provider), timeout=15.0)
    except (PyMobileDevice3Exception, asyncio.TimeoutError, OSError):
        return None


async def _read_lock_state(service_provider: LockdownServiceProvider) -> bool:
    async with AsyncExitStack() as stack:
        if isinstance(service_provider, RemoteServiceDiscoveryService):
            rsd = service_provider
        else:
            rsd = await stack.enter_async_context(PreferredRsdTunnel(serial=service_provider.udid, autopair=False))
        service = await stack.enter_async_context(RemoteNotificationProxyService(rsd))
        return bool(await service.notify_get_state(LOCKSTATE_NOTIFICATION))


async def _no_focus_reason(service_provider: LockdownServiceProvider) -> str:
    """Explain why the device reported no focused element: it does not while it is locked."""
    locked = await _is_device_locked(service_provider)
    if locked:
        return "The device is locked, so it reports no accessibility elements; unlock it and try again."
    if locked is None:
        return "The device reported no focused element; make sure it is unlocked and showing an app."
    return "The device reported no focused element."


class FocusDirection(str, Enum):
    FIRST = "first"
    NEXT = "next"
    PREVIOUS = "previous"
    LAST = "last"

    def to_direction(self) -> Direction:
        return Direction[self.value.capitalize()]


cli = InjectingTyper(
    name="accessibility",
    help="Run accessibility audits, inspect on-screen elements and change accessibility settings.",
    no_args_is_help=True,
)
cli.add_typer(settings.cli)


@cli.command("run-audit")
@async_command
async def accessibility_run_audit(
    service_provider: ServiceProviderDep,
    test_types: Annotated[
        list[str], typer.Argument(help="One or more audit types to run (see `supported-audit-types`).")
    ],
) -> None:
    """Run accessibility audits on the foreground app and print the issues found as JSON."""
    audit_issues = await AccessibilityAudit(service_provider).run_audit(test_types)
    print_json([audit_issue.json() for audit_issue in audit_issues], False)


@cli.command("supported-audit-types")
@async_command
async def accessibility_supported_audit_types(service_provider: ServiceProviderDep) -> None:
    """List the accessibility audit types this device supports."""
    print_json(await AccessibilityAudit(service_provider).supported_audits_types())


@cli.command("capabilities")
@async_command
async def accessibility_capabilities(service_provider: ServiceProviderDep) -> None:
    """Print the device's accessibility inspector capabilities as JSON."""
    print_json(await AccessibilityAudit(service_provider).capabilities())


@cli.command("shell")
def accessibility_shell(service_provider: ServiceProviderDep) -> None:
    """Open an IPython shell connected to the accessibility audit service (for R&D)."""
    AccessibilityAudit(service_provider).shell()


@cli.command("notifications")
@async_command
async def accessibility_notifications(
    service_provider: ServiceProviderDep, output_format: OutputFormatOption = OutputFormat.TEXT
) -> None:
    """Stream accessibility focus and app-state changes as they happen, until interrupted (Ctrl+C)."""
    service = AccessibilityAudit(service_provider)
    async for event in service.iter_events():
        if event.name in (
            "hostAppStateChanged:",
            "hostInspectorCurrentElementChanged:",
        ):
            for focus_item in event.data:
                if output_format is OutputFormat.JSON:
                    print_json_line(focus_item.to_dict())
                else:
                    print(focus_item, flush=True)


@cli.command("list-items")
@async_command
async def accessibility_list_items(service_provider: ServiceProviderDep) -> None:
    """List the accessibility elements of the foreground app by moving the inspector focus through them."""
    elements: list[dict[str, Any]] = []
    async with AccessibilityAudit(service_provider) as service:
        try:
            async for element in service.iter_elements():
                elements.append(element.to_dict())
        except TimeoutError:
            # A locked device accepts the focus moves but reports no element
            logger.error(await _no_focus_reason(service_provider))
            raise typer.Exit(1) from None
    print_json(elements)


@cli.command("element-attributes")
@async_command
async def accessibility_element_attributes(
    service_provider: ServiceProviderDep,
    attributes: Annotated[
        Optional[list[str]],
        typer.Argument(help="Attribute names to read (default: Label, Identifier, Value)."),
    ] = None,
    direction: Annotated[
        FocusDirection,
        typer.Option(help="How to move the inspector focus before reading the newly focused element."),
    ] = FocusDirection.NEXT,
) -> None:
    """Move the accessibility inspector focus and read attributes (label, identifier, value, ...) of the focused element."""
    if not attributes:
        attributes = ["Label", "Identifier", "Value"]
    async with AccessibilityAudit(service_provider) as service:
        try:
            focus = await service.move_focus_and_wait(direction.to_direction())
        except TimeoutError:
            logger.error(f"The focus did not move ({direction.value}); it may already be on that element.")
            raise typer.Exit(1) from None
        element = focus.element
        if element is None:
            logger.error("The focused item does not identify an element.")
            raise typer.Exit(1)
        result = focus.to_dict()
        result["attributes"] = await service.element_attributes(element.identifier, attributes)
    print_json(result)
