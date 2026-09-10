import asyncio
import datetime
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError, WebInspectorNotEnabledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services import webinspector
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.services.webinspector import (
    SAFARI,
    Application,
    AutomationAvailability,
    Page,
    WebinspectorService,
    WirTypes,
    make_target_id,
)


@asynccontextmanager
async def webinspector_service(lockdown: LockdownClient) -> AsyncGenerator[WebinspectorService, None]:
    inspector = WebinspectorService(lockdown=lockdown)
    try:
        try:
            await inspector.connect()
        except WebInspectorNotEnabledError:
            pytest.xfail("Web Inspector is disabled on the device")
        async with inspector:
            yield inspector
    finally:
        await inspector.close()


async def testp_opening_app(lockdown: LockdownClient) -> None:
    async with webinspector_service(lockdown) as inspector:
        safari = await inspector.open_app(SAFARI)
        pages = await inspector.get_open_pages()
        # Might take a while to update.
        if safari.name not in pages:
            await inspector.flush_input(1)
        pages = await inspector.get_open_pages()
        assert safari.name in pages
        assert pages[safari.name]


def test_javascript_page_listing_keeps_its_title() -> None:
    """A JSContext debuggable is listed with a title but no URL - there is no document behind it."""
    page = Page.from_page_dictionary({
        "WIRTitleKey": "JSContext",
        "WIRTypeKey": "WIRTypeJavaScript",
        "WIRPageIdentifierKey": 1,
        "WIROverrideNameKey": "",
    })
    assert page.type_ == WirTypes.JAVASCRIPT
    assert page.web_title == "JSContext"
    assert page.web_url == ""
    assert page.web_connection_id == ""


def test_javascript_page_listing_reports_the_debugger_holding_it() -> None:
    """The device names the connection debugging a JSContext exactly as it does for a web page
    (observed on iOS 26.6.1: the key appears while a session is attached, and only then)."""
    page = Page.from_page_dictionary({
        "WIRTitleKey": "JSContext",
        "WIRTypeKey": "WIRTypeJavaScript",
        "WIRPageIdentifierKey": 7,
        "WIRConnectionIdentifierKey": "D0F5501A-3182-492B-AE82-F0F323B02C28",
        "WIROverrideNameKey": "",
    })
    assert page.web_connection_id == "D0F5501A-3182-492B-AE82-F0F323B02C28"


def test_application_listing_keeps_its_icon() -> None:
    """The device sends each process's icon as PNG bytes (a generic one for processes without an
    icon of their own); the landing page shows it."""
    application = Application.from_application_dictionary({
        "WIRApplicationIdentifierKey": "PID:26846",
        "WIRApplicationBundleIdentifierKey": "com.apple.mobilesafari",
        "WIRApplicationNameKey": "Safari",
        "WIRAutomationAvailabilityKey": "WIRAutomationAvailabilityAvailable",
        "WIRIsApplicationActiveKey": 2,
        "WIRIsApplicationProxyKey": False,
        "WIRIsApplicationReadyKey": True,
        "WIRApplicationIconKey": b"\x89PNG\r\n\x1a\nicon",
    })
    assert application.icon == b"\x89PNG\r\n\x1a\nicon"


async def test_missing_automation_availability_is_unknown() -> None:
    """iOS 12 Safari sends no WIRAutomationAvailabilityKey, neither in the application dictionary nor
    in _rpc_reportCurrentState. Indexing it directly made `webinspector cdp` exit with a KeyError
    before serving (seen on an iPhone 5s, iOS 12.5.8)."""
    application = Application.from_application_dictionary({
        "WIRApplicationIdentifierKey": "PID:196",
        "WIRApplicationBundleIdentifierKey": "com.apple.mobilesafari",
        "WIRApplicationNameKey": "Safari",
        "WIRIsApplicationActiveKey": 1,
        "WIRIsApplicationProxyKey": False,
        "WIRIsApplicationReadyKey": True,
    })
    assert application.availability == AutomationAvailability.UNKNOWN

    inspector = WebinspectorService(lockdown=cast(Any, object()))
    await inspector._handle_report_current_state({})
    assert inspector.state == AutomationAvailability.UNKNOWN.value


def test_web_page_listing_reports_the_debugger_holding_it() -> None:
    """WebKit serves one inspector session per page, and the listing names the connection that has
    it. Without that, a page held by another debugger looked exactly like a device not answering."""
    held = Page.from_page_dictionary({
        "WIRPageIdentifierKey": 1,
        "WIRTypeKey": "WIRTypeWebPage",
        "WIRTitleKey": "Example Domain",
        "WIRURLKey": "https://example.com/",
        "WIRConnectionIdentifierKey": "98FC0F20-4680-4E8D-A3C9-AB19296BCE96",
    })
    assert held.web_connection_id == "98FC0F20-4680-4E8D-A3C9-AB19296BCE96"

    # The key is absent altogether while nobody is debugging the page.
    free = Page.from_page_dictionary({
        "WIRPageIdentifierKey": 1,
        "WIRTypeKey": "WIRTypeWebPage",
        "WIRTitleKey": "Example Domain",
        "WIRURLKey": "https://example.com/",
    })
    assert free.web_connection_id == ""


def _web_page_listing(app_id: str, pages: dict[str, str]) -> dict[str, Any]:
    return {
        "WIRApplicationIdentifierKey": app_id,
        "WIRListingKey": {
            page_id: {
                "WIRPageIdentifierKey": int(page_id),
                "WIRTypeKey": "WIRTypeWeb",
                "WIRTitleKey": title,
                "WIRURLKey": f"https://example.com/{title}",
            }
            for page_id, title in pages.items()
        },
    }


async def test_listing_drops_pages_that_closed() -> None:
    """A listing is the application's complete set of pages: one missing from it has closed.
    Merging without dropping those kept every tab ever opened in the listing forever."""
    inspector = WebinspectorService(lockdown=cast(Any, object()))
    await inspector._handle_application_sent_listing(_web_page_listing("PID:1", {"1": "kept", "2": "closed"}))
    kept = inspector.application_pages["PID:1"]["1"]

    await inspector._handle_application_sent_listing(_web_page_listing("PID:1", {"1": "renamed", "3": "opened"}))

    assert set(inspector.application_pages["PID:1"]) == {"1", "3"}
    # A page that survives is updated in place - sessions hold references to it
    assert inspector.application_pages["PID:1"]["1"] is kept
    assert kept.web_title == "renamed"


async def test_forwarded_events_are_queued_per_session() -> None:
    """Events carry no id, so a consumer cannot recognize its own by content. `webinspectord` tags
    each with the session it was forwarded to, and they are queued per session - otherwise two
    concurrent debugger sessions consume each other's events."""
    inspector = WebinspectorService.__new__(WebinspectorService)
    inspector.wir_events = {}
    inspector.wir_message_results = {}
    for session_id in ("A", "B"):
        await inspector._handle_application_sent_data({
            "WIRApplicationIdentifierKey": "PID:1",
            "WIRDestinationKey": session_id,
            "WIRMessageDataKey": json.dumps({"method": "Console.messageAdded", "params": {"of": session_id}}).encode(),
        })

    for session_id in ("A", "B"):
        assert [event["params"]["of"] for event in inspector.session_events(session_id)] == [session_id]


def test_find_page_id_distinguishes_same_page_of_different_applications() -> None:
    """Page identifiers are per application - every JSContext debuggable is page 1 of its own
    process - so the identifier the CDP bridge hands out qualifies them with the application."""
    inspector = WebinspectorService.__new__(WebinspectorService)
    listing = {"WIRTitleKey": "JSContext", "WIRTypeKey": "WIRTypeJavaScript", "WIRPageIdentifierKey": 1}
    inspector.application_pages = {app_id: {"1": Page.from_page_dictionary(listing)} for app_id in ("PID:1", "PID:2")}
    inspector.connected_application = cast(Any, {app_id: app_id for app_id in ("PID:1", "PID:2")})

    for app_id in ("PID:1", "PID:2"):
        application, page = inspector.find_page_id(make_target_id(app_id, "1"))
        assert application == app_id
        assert page.id_ == 1

    with pytest.raises(KeyError):
        inspector.find_page_id(make_target_id("PID:3", "1"))


async def testp_reattaching_immediately_after_a_session_succeeds(lockdown: LockdownClient) -> None:
    """webinspectord admits a new session only about ten seconds after the previous one started,
    and until then never completes the TLS handshake - a hair past our handshake timeout. Every
    reattach that came too soon (a restarted CDP bridge, an automation session opened once
    inspection was done) therefore failed, and was reported as Web Inspector being disabled."""
    async with webinspector_service(lockdown):
        pass

    # No delay: this is the reattach that used to abort.
    reattached = WebinspectorService(lockdown=lockdown)
    await reattached.connect()
    try:
        assert reattached.connection_id
    finally:
        await reattached.close()


class _ProbeableLockdown:
    """A lockdown stand-in whose liveness probe answers or fails on demand."""

    def __init__(self, answers: bool) -> None:
        self.answers = answers

    async def get_date(self) -> datetime.datetime:
        if not self.answers:
            raise ConnectionTerminatedError
        return datetime.datetime.now()


def _refusing_inspector(
    monkeypatch: pytest.MonkeyPatch, lockdown: _ProbeableLockdown, refusals: int
) -> tuple[WebinspectorService, list[int]]:
    """A service whose handshake webinspectord refuses `refusals` times, with its attempt log."""
    attempts: list[int] = []

    async def connect(self: Any) -> None:
        attempts.append(len(attempts))
        if len(attempts) <= refusals:
            raise ConnectionTerminatedError

    async def handshake_step(*args: Any) -> None:
        return None

    monkeypatch.setattr(LockdownService, "connect", connect)
    monkeypatch.setattr(webinspector, "HANDSHAKE_RETRY_INTERVAL", 0)
    inspector = WebinspectorService(lockdown=cast(Any, lockdown))
    monkeypatch.setattr(inspector, "_report_identifier", handshake_step)
    monkeypatch.setattr(inspector, "_recv_message", handshake_step)
    monkeypatch.setattr(inspector, "_handle_recv", handshake_step)
    return inspector, attempts


@asynccontextmanager
async def _never_disabled() -> AsyncGenerator[Any, None]:
    """The disabled-notification watcher of a device that never posts one."""
    task = asyncio.create_task(asyncio.Event().wait())
    try:
        yield task
    finally:
        task.cancel()


async def test_a_refused_handshake_is_retried_until_webinspectord_serves_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """webinspectord refuses a session it will not serve yet - the gate on consecutive sessions,
    or a device that is still booting - exactly as a device with Web Inspector disabled does. Both
    transient refusals clear within seconds, so the handshake is retried rather than reported."""
    inspector, attempts = _refusing_inspector(monkeypatch, _ProbeableLockdown(answers=True), refusals=2)
    async with _never_disabled() as disabled_task:
        await inspector._handshake(disabled_task)
    assert len(attempts) == 3


async def test_a_refusal_that_outlives_the_deadline_reports_web_inspector_as_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The device is there and keeps refusing: that is Web Inspector being off."""
    monkeypatch.setattr(webinspector, "HANDSHAKE_RETRY_TIMEOUT", 0)
    inspector, attempts = _refusing_inspector(monkeypatch, _ProbeableLockdown(answers=True), refusals=1)
    async with _never_disabled() as disabled_task:
        with pytest.raises(WebInspectorNotEnabledError) as raised:
            await inspector._handshake(disabled_task)
    assert isinstance(raised.value.__cause__, ConnectionTerminatedError)
    assert len(attempts) == 1


async def test_a_disconnect_during_the_handshake_is_not_reported_as_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A device that goes away mid-handshake (a reboot, a cable pull) terminates the connection
    just like one refusing the session does - but reporting it as disabled stops the callers that
    would otherwise retry the disconnect (the CDP bridge under `--reconnect`)."""
    inspector, attempts = _refusing_inspector(monkeypatch, _ProbeableLockdown(answers=False), refusals=1)
    async with _never_disabled() as disabled_task:
        with pytest.raises(ConnectionTerminatedError):
            await inspector._handshake(disabled_task)
    assert len(attempts) == 1
