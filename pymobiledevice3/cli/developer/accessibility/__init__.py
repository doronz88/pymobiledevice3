import logging

from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.cli.developer.accessibility import settings
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="accessibility",
    help="Interact with accessibility-related features",
    no_args_is_help=True,
)
cli.add_typer(settings.cli)


@cli.command("run-audit")
def accessibility_run_audit(service_provider: ServiceProviderDep, test_types: list[str]) -> None:
    """runs accessibility audit tests"""
    audit_issues = AccessibilityAudit(service_provider).run_audit(test_types)
    print_json([audit_issue.json() for audit_issue in audit_issues], False)


@cli.command("supported-audit-types")
def accessibility_supported_audit_types(service_provider: ServiceProviderDep) -> None:
    """lists supported accessibility audit test types"""
    print_json(AccessibilityAudit(service_provider).supported_audits_types())


@cli.command("capabilities")
def accessibility_capabilities(service_provider: ServiceProviderDep) -> None:
    """display accessibility capabilities"""
    print_json(AccessibilityAudit(service_provider).capabilities)


@cli.command("shell")
def accessibility_shell(service_provider: ServiceProviderDep) -> None:
    """start and ipython accessibility shell"""
    AccessibilityAudit(service_provider).shell()


@cli.command("notifications")
def accessibility_notifications(service_provider: ServiceProviderDep) -> None:
    """show notifications"""
    service = AccessibilityAudit(service_provider)
    for event in service.iter_events():
        if event.name in (
            "hostAppStateChanged:",
            "hostInspectorCurrentElementChanged:",
        ):
            for focus_item in event.data:
                logger.info(focus_item)


@cli.command("list-items")
def accessibility_list_items(service_provider: ServiceProviderDep) -> None:
    """List elements available in the currently shown menu."""
    elements = []
    with AccessibilityAudit(service_provider) as service:
        for element in service.iter_elements():
            elements.append(element.to_dict())
    print_json(elements)
