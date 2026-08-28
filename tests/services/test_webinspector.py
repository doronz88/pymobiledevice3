import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import WebInspectorNotEnabledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.webinspector import SAFARI, Page, WebinspectorService, WirTypes, make_target_id


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
    inspector = WebinspectorService.__new__(WebinspectorService)
    inspector.application_pages = {}
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
