"""Attaching to debuggables before they run: Target.setAutoAttach(waitForDebuggerOnStart).

Everything here runs without a device: the inspector service is wired to a fake webinspectord
connection that records what the bridge sends it, and the messages webinspectord would relay
from an app are fed straight into the service's receive handlers in their wire format.
"""

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, Optional, cast

import httpx
import pytest

from pymobiledevice3.services.web_protocol import cdp_browser
from pymobiledevice3.services.web_protocol.cdp_browser import (
    HELD_TARGETS,
    CdpBrowser,
    HeldTargets,
    adopt_held_target,
    iter_inspectable,
)
from pymobiledevice3.services.web_protocol.cdp_server import app, targets_html
from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import Application, AutomationAvailability, Page, WebinspectorService

APP_ID = "PID:42"
CANDIDATE_SESSION = "9D0D3D1E-2C5B-4B69-8E4F-2A6A0B8E1C11"
TIMEOUT = 5


class FakeWebinspectord:
    """The service connection a WebinspectorService talks over, recording every plist sent."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send_plist(self, plist: dict[str, Any]) -> None:
        self.sent.append(plist)

    def selectors(self) -> list[str]:
        return [message["__selector"] for message in self.sent]

    def arguments(self, selector: str) -> list[dict[str, Any]]:
        return [message["__argument"] for message in self.sent if message["__selector"] == selector]

    def socket_data(self) -> list[dict[str, Any]]:
        """The inspector-protocol messages forwarded to debuggables, decoded."""
        return [json.loads(argument["WIRSocketDataKey"]) for argument in self.arguments("_rpc_forwardSocketData:")]


class FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send_json(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    def events(self, method: str) -> list[dict[str, Any]]:
        return [message for message in self.sent if message.get("method") == method]


async def eventually(condition: Any, timeout: float = TIMEOUT) -> None:
    """Wait for `condition()` to hold; the bridge's target tasks run in the background."""
    deadline = asyncio.get_event_loop().time() + timeout
    while not condition():
        if asyncio.get_event_loop().time() >= deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.01)


def application_connected(app_id: str = APP_ID) -> dict[str, Any]:
    return {
        "__selector": "_rpc_applicationConnected:",
        "__argument": {
            "WIRApplicationIdentifierKey": app_id,
            "WIRApplicationBundleIdentifierKey": "com.example.app",
            "WIRApplicationNameKey": "Example",
            "WIRAutomationAvailabilityKey": "WIRAutomationAvailabilityNotAvailable",
            "WIRIsApplicationActiveKey": 1,
            "WIRIsApplicationProxyKey": False,
            "WIRIsApplicationReadyKey": True,
        },
    }


def jscontext_listing(page_id: int, app_id: str = APP_ID) -> dict[str, Any]:
    return {
        "__selector": "_rpc_applicationSentListing:",
        "__argument": {
            "WIRApplicationIdentifierKey": app_id,
            "WIRListingKey": {
                str(page_id): {
                    "WIRPageIdentifierKey": page_id,
                    "WIRTypeKey": "WIRTypeJavaScript",
                    "WIRTitleKey": "JSContext",
                    "WIROverrideNameKey": "",
                }
            },
        },
    }


def web_page_listing(page_id: int, app_id: str = APP_ID) -> dict[str, Any]:
    return {
        "__selector": "_rpc_applicationSentListing:",
        "__argument": {
            "WIRApplicationIdentifierKey": app_id,
            "WIRListingKey": {
                str(page_id): {
                    "WIRPageIdentifierKey": page_id,
                    "WIRTypeKey": "WIRTypeWebPage",
                    "WIRTitleKey": "Example",
                    "WIRURLKey": "https://example.com/",
                }
            },
        },
    }


def automatic_inspection_candidate(page_id: int, app_id: str = APP_ID) -> dict[str, Any]:
    return {
        "__selector": "_rpc_reportAutomaticInspectionCandidate:",
        "__argument": {
            "WIRApplicationIdentifierKey": app_id,
            "WIRPageIdentifierKey": page_id,
            "WIRAutomaticInspectionSessionIdentifierKey": CANDIDATE_SESSION,
        },
    }


def application_sent_data(session_id: str, message: dict[str, Any], app_id: str = APP_ID) -> dict[str, Any]:
    return {
        "__selector": "_rpc_applicationSentData:",
        "__argument": {
            "WIRApplicationIdentifierKey": app_id,
            "WIRDestinationKey": session_id,
            "WIRMessageDataKey": json.dumps(message).encode(),
        },
    }


@asynccontextmanager
async def offline_browser(
    pause_on_start: bool = False,
) -> AsyncGenerator[tuple[CdpBrowser, FakeWebinspectord, FakeWebSocket], None]:
    inspector = WebinspectorService(lockdown=cast(Any, object()))
    connection = FakeWebinspectord()
    inspector._service = cast(Any, connection)
    websocket = FakeWebSocket()
    browser = CdpBrowser(inspector, cast(Any, websocket), pause_on_start=pause_on_start)
    await inspector._handle_recv(application_connected())
    connection.sent.clear()
    try:
        yield browser, connection, websocket
    finally:
        await browser.close()


async def enable_auto_attach(browser: CdpBrowser, wait_for_debugger: bool = True) -> None:
    await browser._handle({
        "id": 1,
        "method": "Target.setAutoAttach",
        "params": {"autoAttach": True, "waitForDebuggerOnStart": wait_for_debugger, "flatten": True},
    })


async def announce_jscontext(browser: CdpBrowser, page_id: int) -> None:
    """What webinspectord relays when an app creates an inspectable JSContext while automatic
    inspection is on: the app pushes its listing, then the candidate is reported."""
    await browser.inspector._handle_recv(jscontext_listing(page_id))
    await browser.inspector._handle_recv(automatic_inspection_candidate(page_id))


async def attached_session(websocket: FakeWebSocket) -> str:
    await eventually(lambda: websocket.events("Target.attachedToTarget"))
    return websocket.events("Target.attachedToTarget")[-1]["params"]["sessionId"]


async def test_wait_for_debugger_on_start_enables_automatic_inspection_on_the_device() -> None:
    """Only a debugger that asked webinspectord for automatic inspection is offered new contexts."""
    async with offline_browser() as (browser, connection, _):
        await enable_auto_attach(browser)

        configurations = connection.arguments("_rpc_forwardAutomaticInspectionConfiguration:")
        assert [c["WIRAutomaticInspectionEnabledKey"] for c in configurations] == [True]


async def test_auto_attach_without_waiting_leaves_automatic_inspection_off() -> None:
    async with offline_browser() as (browser, connection, _):
        await enable_auto_attach(browser, wait_for_debugger=False)

        assert "_rpc_forwardAutomaticInspectionConfiguration:" not in connection.selectors()


async def test_a_new_jscontext_is_attached_before_it_runs() -> None:
    """The candidate is accepted with a socket setup, and the client is told the target waits."""
    async with offline_browser() as (browser, connection, websocket):
        await enable_auto_attach(browser)
        await announce_jscontext(browser, page_id=1)

        session_id = await attached_session(websocket)
        setups = connection.arguments("_rpc_forwardSocketSetup:")
        assert [(s["WIRApplicationIdentifierKey"], s["WIRPageIdentifierKey"]) for s in setups] == [(APP_ID, 1)]
        assert setups[0]["WIRAutomaticallyPause"] is False
        attached = websocket.events("Target.attachedToTarget")[0]["params"]
        assert attached["waitingForDebugger"] is True
        assert attached["targetInfo"]["type"] == "node"
        assert session_id
        assert "_rpc_forwardAutomaticInspectionRejection:" not in connection.selectors()


async def test_a_jscontext_whose_listing_lands_first_is_still_attached_as_waiting() -> None:
    """The device pushes the listing a few milliseconds before it reports the candidate. Reacting
    to the listing alone attached the context as already running, so the candidate only opened a
    second session on it and the application was never released."""
    async with offline_browser() as (browser, connection, websocket):
        await enable_auto_attach(browser)
        await browser.inspector._handle_recv(jscontext_listing(page_id=1))
        # Let the listing consumer act on the push before the candidate is even received.
        for _ in range(20):
            await asyncio.sleep(0)
        await browser.inspector._handle_recv(automatic_inspection_candidate(page_id=1))

        await attached_session(websocket)
        await asyncio.sleep(0.05)
        setups = connection.arguments("_rpc_forwardSocketSetup:")
        assert [s["WIRPageIdentifierKey"] for s in setups] == [1]
        attached = websocket.events("Target.attachedToTarget")
        assert [a["params"]["waitingForDebugger"] for a in attached] == [True]
        assert "_rpc_forwardAutomaticInspectionRejection:" not in connection.selectors()


async def test_a_jscontext_that_is_never_offered_is_attached_after_the_grace_period(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not every JSContext in a pushed listing comes with a candidate (one made inspectable
    before automatic inspection reached its process, say). Hold off for the candidate briefly,
    then attach it as a running target."""
    monkeypatch.setattr(cdp_browser, "CANDIDATE_GRACE", 0.05)
    async with offline_browser() as (browser, connection, websocket):
        await enable_auto_attach(browser)

        await browser.inspector._handle_recv(jscontext_listing(page_id=1))

        await asyncio.sleep(0.02)
        assert "_rpc_forwardSocketSetup:" not in connection.selectors()
        await asyncio.sleep(0.05)
        await browser._sync_targets()
        session_id = await attached_session(websocket)
        assert websocket.events("Target.attachedToTarget")[0]["params"]["waitingForDebugger"] is False
        assert session_id


async def test_run_if_waiting_for_debugger_releases_the_jscontext() -> None:
    """WebKit holds the context until the frontend reports itself initialized; that is what
    Runtime.runIfWaitingForDebugger means to a Chrome client."""
    async with offline_browser() as (browser, connection, websocket):
        await enable_auto_attach(browser)
        await announce_jscontext(browser, page_id=1)
        session_id = await attached_session(websocket)
        assert "Inspector.initialized" not in [m["method"] for m in connection.socket_data()]

        await browser._handle({"id": 7, "sessionId": session_id, "method": "Runtime.runIfWaitingForDebugger"})

        await eventually(lambda: "Inspector.initialized" in [m["method"] for m in connection.socket_data()])
        await eventually(lambda: any(m.get("id") == 7 for m in websocket.sent))
        assert "result" in next(m for m in websocket.sent if m.get("id") == 7)


async def test_pause_mode_leaves_debuggables_that_already_existed_running() -> None:
    """Safari's automatic pause applies to contexts created while it is on; a context that was
    already running when the client attached is not stopped in its tracks."""
    async with offline_browser(pause_on_start=True) as (browser, connection, websocket):
        await browser.inspector._handle_recv(jscontext_listing(page_id=1))
        await enable_auto_attach(browser)
        session_id = await attached_session(websocket)

        await browser._handle({"id": 5, "sessionId": session_id, "method": "Debugger.enable", "params": {}})

        await eventually(
            lambda: "Debugger.setPauseOnDebuggerStatements" in [m["method"] for m in connection.socket_data()]
        )
        assert "Debugger.pause" not in [m["method"] for m in connection.socket_data()]


async def test_a_candidate_nobody_waits_for_is_rejected() -> None:
    """An unanswered candidate stalls the app for ten seconds; decline it right away instead."""
    inspector = WebinspectorService(lockdown=cast(Any, object()))
    connection = FakeWebinspectord()
    inspector._service = cast(Any, connection)
    await inspector._handle_recv(application_connected())

    await inspector._handle_recv(automatic_inspection_candidate(page_id=1))

    rejections = connection.arguments("_rpc_forwardAutomaticInspectionRejection:")
    assert len(rejections) == 1
    assert rejections[0]["WIRApplicationIdentifierKey"] == APP_ID
    assert rejections[0]["WIRPageIdentifierKey"] == 1
    assert rejections[0]["WIRAutomaticInspectionSessionIdentifierKey"] == CANDIDATE_SESSION


async def test_a_candidate_that_cannot_be_attached_is_rejected() -> None:
    """A candidate whose page never made it into the listing cannot be set up; decline it."""
    async with offline_browser() as (browser, connection, _):
        await enable_auto_attach(browser)

        await browser.inspector._handle_recv(automatic_inspection_candidate(page_id=5))

        await eventually(lambda: connection.arguments("_rpc_forwardAutomaticInspectionRejection:"))
        assert "_rpc_forwardSocketSetup:" not in connection.selectors()


async def test_closing_the_browser_releases_and_switches_automatic_inspection_off() -> None:
    """A held context must not outlive the debugger that held it, and webinspectord must stop
    offering candidates to a connection that no longer takes them."""
    async with offline_browser() as (browser, connection, websocket):
        await enable_auto_attach(browser)
        await announce_jscontext(browser, page_id=1)
        await attached_session(websocket)

        await browser.close()

        assert "Inspector.initialized" in [m["method"] for m in connection.socket_data()]
        configurations = connection.arguments("_rpc_forwardAutomaticInspectionConfiguration:")
        assert [c["WIRAutomaticInspectionEnabledKey"] for c in configurations] == [True, False]


async def test_a_pushed_listing_attaches_a_new_page_without_waiting_for_the_poll() -> None:
    """webinspectord relays an app's listing the moment a page appears; auto-attach acts on that
    push rather than on the next periodic refresh. A page cannot be held before it runs, so the
    client is told it is not waiting."""
    async with offline_browser() as (browser, connection, websocket):
        await enable_auto_attach(browser)

        await browser.inspector._handle_recv(web_page_listing(page_id=3))

        await eventually(lambda: connection.arguments("_rpc_forwardSocketSetup:"))
        setup = connection.arguments("_rpc_forwardSocketSetup:")[0]
        assert setup["WIRPageIdentifierKey"] == 3
        # The page answers its socket setup by announcing its inspection target.
        await browser.inspector._handle_recv(
            application_sent_data(
                setup["WIRSenderKey"],
                {"method": "Target.targetCreated", "params": {"targetInfo": {"targetId": "page-3-1", "type": "page"}}},
            )
        )
        session_id = await attached_session(websocket)
        attached = websocket.events("Target.attachedToTarget")[0]["params"]
        assert attached["waitingForDebugger"] is False
        assert attached["targetInfo"]["type"] == "page"
        assert session_id


@asynccontextmanager
async def offline_holder() -> AsyncGenerator[tuple[HeldTargets, FakeWebinspectord], None]:
    """The bridge-level acceptor `--pause-new-targets` runs: it takes every candidate itself."""
    HELD_TARGETS.clear()
    inspector = WebinspectorService(lockdown=cast(Any, object()))
    connection = FakeWebinspectord()
    inspector._service = cast(Any, connection)
    await inspector._handle_recv(application_connected())
    holder = HeldTargets(inspector)
    await holder.start()
    try:
        yield holder, connection
    finally:
        await holder.stop()
        HELD_TARGETS.clear()


async def test_the_pause_flag_holds_a_new_jscontext_paused_on_its_first_statement() -> None:
    """Like Safari with both Develop-menu options on: the bridge accepts the candidate itself,
    initializes the session so WebKit pauses the context on its first statement, and keeps the
    session for whichever frontend opens it later."""
    async with offline_holder() as (holder, connection):
        assert [
            c["WIRAutomaticInspectionEnabledKey"]
            for c in connection.arguments("_rpc_forwardAutomaticInspectionConfiguration:")
        ] == [True]
        await holder.inspector._handle_recv(jscontext_listing(page_id=1))
        await holder.inspector._handle_recv(automatic_inspection_candidate(page_id=1))

        page_id = f"{APP_ID}:1"
        await eventually(lambda: page_id in HELD_TARGETS)
        await eventually(lambda: "Inspector.initialized" in [m["method"] for m in connection.socket_data()])
        assert connection.arguments("_rpc_forwardSocketSetup:")[0]["WIRAutomaticallyPause"] is True
        methods = [m["method"] for m in connection.socket_data()]
        assert methods.index("Debugger.enable") < methods.index("Inspector.initialized")
        assert "_rpc_forwardAutomaticInspectionRejection:" not in connection.selectors()

        target = adopt_held_target(page_id)
        assert target is not None
        assert adopt_held_target(page_id) is None
        await target.close()


async def test_a_held_target_is_dropped_when_its_context_goes_away() -> None:
    async with offline_holder() as (holder, connection):
        await holder.inspector._handle_recv(jscontext_listing(page_id=1))
        await holder.inspector._handle_recv(automatic_inspection_candidate(page_id=1))
        page_id = f"{APP_ID}:1"
        await eventually(lambda: page_id in HELD_TARGETS)

        await holder.inspector._handle_recv({
            "__selector": "_rpc_applicationSentListing:",
            "__argument": {"WIRApplicationIdentifierKey": APP_ID, "WIRListingKey": {}},
        })

        await eventually(lambda: page_id not in HELD_TARGETS)
        # The session is torn down right after it is dropped from the registry, on the holder's
        # own task - give it its turn rather than assert on the same tick.
        await eventually(lambda: "_rpc_forwardDidClose:" in connection.selectors())


async def test_stopping_the_holder_releases_and_switches_automatic_inspection_off() -> None:
    async with offline_holder() as (holder, connection):
        await holder.inspector._handle_recv(jscontext_listing(page_id=1))
        await holder.inspector._handle_recv(automatic_inspection_candidate(page_id=1))
        await eventually(lambda: f"{APP_ID}:1" in HELD_TARGETS)

        await holder.stop()

        assert "_rpc_forwardDidClose:" in connection.selectors()
        assert HELD_TARGETS == {}
        configurations = connection.arguments("_rpc_forwardAutomaticInspectionConfiguration:")
        assert [c["WIRAutomaticInspectionEnabledKey"] for c in configurations] == [True, False]


async def test_a_candidate_the_holder_cannot_attach_is_rejected() -> None:
    async with offline_holder() as (holder, connection):
        await holder.inspector._handle_recv(automatic_inspection_candidate(page_id=9))

        await eventually(lambda: connection.arguments("_rpc_forwardAutomaticInspectionRejection:"))
        assert "_rpc_forwardSocketSetup:" not in connection.selectors()


def _offline_jscontext_target(connection: FakeWebinspectord) -> CdpTarget:
    inspector = WebinspectorService(lockdown=cast(Any, object()))
    inspector._service = cast(Any, connection)
    page = Page.from_page_dictionary({
        "WIRPageIdentifierKey": 1,
        "WIRTypeKey": "WIRTypeJavaScript",
        "WIRTitleKey": "JSContext",
        "WIROverrideNameKey": "",
    })
    application = Application(
        APP_ID, "com.example.app", 42, "Example", AutomationAvailability.NOT_AVAILABLE, 1, False, True
    )
    return CdpTarget(SessionProtocol(inspector, "HELD", application, page, method_prefix=""), f"jscontext:{APP_ID}:1")


async def _next_output(target: CdpTarget) -> dict[str, Any]:
    return await asyncio.wait_for(target.receive(), TIMEOUT)


async def test_a_frontend_adopting_a_held_target_sees_its_pause_after_enabling_the_debugger() -> None:
    """The context paused while nobody was looking. A frontend that opens it later enables the
    debugger as usual; WebKit answers that the domain is already on (the bridge enabled it), which
    is turned into a success, and the scripts and the pause the frontend missed follow - the order
    a fresh backend would have produced."""
    connection = FakeWebinspectord()
    target = _offline_jscontext_target(connection)
    try:
        target.start_holding()
        events = target.protocol.inspector.session_events("HELD")
        events.append({"method": "Debugger.scriptParsed", "params": {"scriptId": "2", "url": ""}})
        events.append({"method": "Debugger.paused", "params": {"reason": "PauseOnNextStatement", "callFrames": []}})
        await eventually(lambda: len(target.held_events) == 2)

        target.adopt()
        await target.send({"id": 3, "method": "Debugger.enable", "params": {}})
        await eventually(lambda: any(m["method"] == "Debugger.enable" for m in connection.socket_data()))
        wire_id = next(m["id"] for m in connection.socket_data() if m["method"] == "Debugger.enable")
        target.protocol.inspector.wir_message_results[wire_id] = {
            "id": wire_id,
            "error": {"code": -32000, "message": "Debugger domain already enabled"},
        }

        assert await _next_output(target) == {"id": 3, "result": {}}
        assert (await _next_output(target))["method"] == "Debugger.scriptParsed"
        assert (await _next_output(target))["method"] == "Debugger.paused"
    finally:
        await target.close()


async def test_error_data_reaches_the_frontend_as_a_string() -> None:
    """WebKit's error responses carry `data` as a list of error objects; Chrome's protocol
    types it as a string. WebStorm's reader threw "Expected a string but was BEGIN_ARRAY" on
    every such response - one per domain a JSContext lacks - and lost the session's pauses."""
    connection = FakeWebinspectord()
    target = _offline_jscontext_target(connection)
    try:
        await target.send({"id": 4, "method": "Page.enable", "params": {}})
        await eventually(lambda: connection.socket_data())
        wire_id = connection.socket_data()[0]["id"]
        target.protocol.inspector.wir_message_results[wire_id] = {
            "id": wire_id,
            "error": {
                "code": -32601,
                "message": "'Page' domain was not found",
                "data": [{"code": -32601, "message": "'Page' domain was not found"}],
            },
        }

        reply = await _next_output(target)

        assert reply["id"] == 4
        assert reply["error"]["code"] == -32601
        assert reply["error"]["message"] == "'Page' domain was not found"
        assert isinstance(reply["error"]["data"], str)
    finally:
        await target.close()


async def test_skip_all_pauses_is_translated_to_what_webkit_has() -> None:
    """WebStorm sends Debugger.setSkipAllPauses on attach; WebKit has no such method. Its
    meaning is covered by deactivating breakpoints and debugger statements, so translate it
    instead of handing the editor an error for its first debugger request."""
    connection = FakeWebinspectord()
    target = _offline_jscontext_target(connection)
    try:
        await target.send({"id": 4, "method": "Debugger.setSkipAllPauses", "params": {"skip": True}})

        assert await _next_output(target) == {"id": 4, "result": {}}
        await eventually(lambda: len(connection.socket_data()) == 2)
        assert [(m["method"], m["params"]) for m in connection.socket_data()] == [
            ("Debugger.setBreakpointsActive", {"active": False}),
            ("Debugger.setPauseOnDebuggerStatements", {"enabled": False}),
        ]
    finally:
        await target.close()


async def test_a_url_less_jscontext_script_gets_a_synthetic_url() -> None:
    """A JSContext's own scripts carry no URL. Give each a stable synthetic one so an editor can
    address it (and set a breakpoint on it)."""
    connection = FakeWebinspectord()
    target = _offline_jscontext_target(connection)
    try:
        await target._debugger_script_parsed({
            "method": "Debugger.scriptParsed",
            "params": {"scriptId": "7", "url": "", "startLine": 0},
        })
        assert (await _next_output(target))["params"]["url"] == "jscontext:///7.js"
    finally:
        await target.close()


async def test_a_url_breakpoint_on_a_jscontext_binds_by_location() -> None:
    """An editor sets a breakpoint by URL; that never binds on a URL-less JSContext script. The
    bridge turns it into a scriptId-location breakpoint - the only kind that binds - and answers
    in the shape setBreakpointByUrl callers expect."""
    connection = FakeWebinspectord()
    target = _offline_jscontext_target(connection)
    try:
        await target._debugger_script_parsed({
            "method": "Debugger.scriptParsed",
            "params": {"scriptId": "7", "url": "", "startLine": 0},
        })
        await _next_output(target)

        await target.send({
            "id": 40,
            "method": "Debugger.setBreakpointByUrl",
            "params": {"lineNumber": 2, "url": "jscontext:///7.js"},
        })
        await eventually(lambda: any(m.get("method") == "Debugger.setBreakpoint" for m in connection.socket_data()))
        sent = next(m for m in connection.socket_data() if m.get("method") == "Debugger.setBreakpoint")
        assert sent["params"]["location"] == {"scriptId": "7", "lineNumber": 2}
        # The device answers; the frontend gets a setBreakpointByUrl-shaped reply.
        wire_id = sent["id"]
        target.protocol.inspector.wir_message_results[wire_id] = {
            "id": wire_id,
            "result": {
                "breakpointId": "7:2:0",
                "actualLocation": {"scriptId": "7", "lineNumber": 2, "columnNumber": 2},
            },
        }
        reply = await _next_output(target)
        assert reply["id"] == 40
        assert reply["result"]["breakpointId"] == "7:2:0"
        assert reply["result"]["locations"] == [{"scriptId": "7", "lineNumber": 2, "columnNumber": 2}]
    finally:
        await target.close()


async def test_a_breakpoint_hit_is_reported_as_other_with_hit_breakpoints() -> None:
    """A source-breakpoint hit is reason "other" with hitBreakpoints in V8/Chrome. WebKit calls
    it "Breakpoint"; forwarding it as "instrumentation" (Chrome's reason for DOM/event breakpoints)
    made editors discard the pause, so a breakpoint set on a JSContext line was reached but never
    surfaced."""
    connection = FakeWebinspectord()
    target = _offline_jscontext_target(connection)
    try:
        await target._debugger_paused({
            "method": "Debugger.paused",
            "params": {"reason": "Breakpoint", "data": {"breakpointId": "2:1:0"}, "callFrames": []},
        })

        paused = (await _next_output(target))["params"]
        assert paused["reason"] == "other"
        assert paused["hitBreakpoints"] == ["2:1:0"]
    finally:
        await target.close()


async def test_a_debugger_statement_is_reported_as_other_like_v8() -> None:
    """V8 reports a `debugger;` statement as reason "other", and editors hold that. WebKit calls
    it "DebuggerStatement"; forwarding it as "debugCommand" (Chrome's reason for a client-issued
    Debugger.pause) made WebStorm resume on its own, so `debugger` never stopped it on a
    JSContext, while node - reporting "other" - did stop."""
    connection = FakeWebinspectord()
    target = _offline_jscontext_target(connection)
    try:
        await target._debugger_paused({
            "method": "Debugger.paused",
            "params": {"reason": "DebuggerStatement", "callFrames": []},
        })

        assert (await _next_output(target))["params"]["reason"] == "other"
    finally:
        await target.close()


async def test_a_pause_on_the_next_statement_is_reported_as_a_plain_pause() -> None:
    """WebKit's PauseOnNextStatement is what Chrome reports as "other" (its own pause button).
    Reported as "instrumentation", Chrome's frontend takes it for one of its instrumentation
    breakpoints, looks for the breakpoint data that is not there, and drops the pause on the
    floor: the Sources panel stays at "Not paused" while the context sits stopped."""
    connection = FakeWebinspectord()
    target = _offline_jscontext_target(connection)
    try:
        await target._debugger_paused({
            "method": "Debugger.paused",
            "params": {"reason": "PauseOnNextStatement", "callFrames": []},
        })

        assert (await _next_output(target))["params"]["reason"] == "other"
    finally:
        await target.close()


async def test_the_browser_endpoint_adopts_a_held_jscontext_instead_of_attaching() -> None:
    """With the flag on, the bridge already holds every new context; a client auto-attaching
    gets that session (already released and paused) rather than a second socket setup."""
    async with offline_browser(pause_on_start=True) as (browser, connection, websocket):
        await enable_auto_attach(browser)
        held = _offline_jscontext_target(FakeWebinspectord())
        held.start_holding()
        HELD_TARGETS[f"{APP_ID}:1"] = held
        try:
            await browser.inspector._handle_recv(jscontext_listing(page_id=1))

            session_id = await attached_session(websocket)
            assert websocket.events("Target.attachedToTarget")[0]["params"]["waitingForDebugger"] is False
            assert "_rpc_forwardSocketSetup:" not in connection.selectors()
            assert HELD_TARGETS == {}
            assert session_id
        finally:
            HELD_TARGETS.clear()


async def test_with_the_pause_flag_the_browser_leaves_candidates_to_the_holder() -> None:
    async with offline_browser(pause_on_start=True) as (browser, connection, _):
        await enable_auto_attach(browser)

        await announce_jscontext(browser, page_id=1)

        await asyncio.sleep(0.05)
        assert "_rpc_forwardSocketSetup:" not in connection.selectors()
        # Nobody held it (no holder in this test), so the service declined it on the spot.
        assert connection.arguments("_rpc_forwardAutomaticInspectionRejection:")


def _listed_inspector(connection: FakeWebinspectord) -> WebinspectorService:
    inspector = WebinspectorService(lockdown=cast(Any, object()))
    inspector._service = cast(Any, connection)
    inspector.connected_application = {
        APP_ID: Application(
            APP_ID, "com.example.app", 42, "Example", AutomationAvailability.NOT_AVAILABLE, 1, False, True
        )
    }
    inspector.application_pages = {
        APP_ID: {
            "1": Page.from_page_dictionary({
                "WIRPageIdentifierKey": 1,
                "WIRTypeKey": "WIRTypeJavaScript",
                "WIRTitleKey": "JSContext",
                "WIROverrideNameKey": "",
            })
        }
    }
    return inspector


def test_landing_page_marks_held_targets_paused() -> None:
    inspector = _listed_inspector(FakeWebinspectord())
    HELD_TARGETS[f"{APP_ID}:1"] = cast(Any, object())
    try:
        html = targets_html(inspector, "127.0.0.1:9222")
        assert "paused" in html
        # The link itself stays as it was: the context's label, nothing else, is its text; its
        # process is named by the header it is listed under.
        assert '<span class="name">Example</span>' in html
        assert '<a href="/devtools/js_app.html?ws=127.0.0.1:9222/devtools/page/PID:42:1">JSContext #1</a>' in html
    finally:
        HELD_TARGETS.clear()


@asynccontextmanager
async def bridge_client(
    monkeypatch: pytest.MonkeyPatch, pause_new_targets: bool = False
) -> AsyncGenerator[tuple[httpx.AsyncClient, FakeWebinspectord], None]:
    """The bridge's HTTP surface over a fake device connection."""
    connection = FakeWebinspectord()
    inspector = _listed_inspector(connection)

    async def connect() -> None:
        pass

    monkeypatch.setattr(inspector, "connect", connect)
    app.state.inspector = inspector
    app.state.pause_new_targets = pause_new_targets
    try:
        # Not a parenthesized `with`: that is 3.10+ syntax and the repository runs on 3.9.
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(app.router.lifespan_context(app))
            client = await stack.enter_async_context(
                httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://bridge")
            )
            yield client, connection
    finally:
        HELD_TARGETS.clear()


async def test_the_landing_page_toggle_starts_and_stops_holding_new_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pause-on-launch can be switched from the landing page: on enables automatic inspection
    on the device (the bridge starts taking candidates), off stops it and lets held targets go."""
    async with bridge_client(monkeypatch) as (client, connection):
        assert (await client.get("/pause-new-targets")).json() == {"enabled": False}

        assert (await client.post("/pause-new-targets", json={"enabled": True})).json() == {"enabled": True}
        assert (await client.get("/pause-new-targets")).json() == {"enabled": True}
        assert (await client.post("/pause-new-targets", json={"enabled": False})).json() == {"enabled": False}

        configurations = connection.arguments("_rpc_forwardAutomaticInspectionConfiguration:")
        assert [c["WIRAutomaticInspectionEnabledKey"] for c in configurations] == [True, False]


async def test_the_flag_sets_the_toggles_initial_state(monkeypatch: pytest.MonkeyPatch) -> None:
    async with bridge_client(monkeypatch, pause_new_targets=True) as (client, connection):
        assert (await client.get("/pause-new-targets")).json() == {"enabled": True}
        assert 'id="pause-new-targets" checked' in (await client.get("/")).text
        configurations = connection.arguments("_rpc_forwardAutomaticInspectionConfiguration:")
        assert [c["WIRAutomaticInspectionEnabledKey"] for c in configurations] == [True]


async def test_a_jscontext_is_listed_with_a_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """A JSContext has no document, and an empty url broke WebStorm: it builds its Node-style
    target from the url field and fails on "" with "Malformed URL". Name the context instead."""
    async with bridge_client(monkeypatch) as (client, _):
        listed = (await client.get("/json/list")).json()[0]
        api = (await client.get("/api/targets")).json()["targets"][0]

        assert listed["url"] == "jscontext://com.example.app/42/1"
        assert api["url"] == "jscontext://com.example.app/42/1"
        assert api["webSocketDebuggerUrl"] == "ws://bridge/devtools/page/PID:42:1"


async def test_the_landing_page_offers_an_attach_config_per_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """Instead of hand-writing a launch.json with a pid and page number, each target on the
    landing page comes with the VS Code configuration that attaches to exactly it."""
    async with bridge_client(monkeypatch) as (client, _):
        html = (await client.get("/")).text

        assert '"websocketAddress": "ws://bridge/devtools/page/PID:42:1"' in html
        assert '"type": "node"' in html
        assert "Attach to Node.js/Chrome" in html


def test_targets_are_listed_in_order() -> None:
    """The device reports a process's contexts in whatever order it holds them (3, 1, 4, 2, 5);
    the bridge lists applications by name and each one's targets by number."""
    inspector = _listed_inspector(FakeWebinspectord())
    inspector.connected_application["PID:7"] = Application(
        "PID:7", "com.apple.mobilesafari", 7, "Safari", AutomationAvailability.NOT_AVAILABLE, 1, False, True
    )
    inspector.application_pages = {
        "PID:7": {
            "12": Page.from_page_dictionary({
                "WIRPageIdentifierKey": 12,
                "WIRTypeKey": "WIRTypeWebPage",
                "WIRTitleKey": "b",
                "WIRURLKey": "https://b/",
            }),
            "2": Page.from_page_dictionary({
                "WIRPageIdentifierKey": 2,
                "WIRTypeKey": "WIRTypeWebPage",
                "WIRTitleKey": "a",
                "WIRURLKey": "https://a/",
            }),
        },
        APP_ID: {
            str(n): Page.from_page_dictionary({
                "WIRPageIdentifierKey": n,
                "WIRTypeKey": "WIRTypeJavaScript",
                "WIRTitleKey": "JSContext",
            })
            for n in (3, 1, 10, 2)
        },
    }

    listed = [target_id for target_id, _, _ in iter_inspectable(inspector)]

    assert listed == ["PID:42:1", "PID:42:2", "PID:42:3", "PID:42:10", "PID:7:2", "PID:7:12"]


def test_each_attach_snippet_has_a_copy_button() -> None:
    """Like a GitHub code snippet: one click puts the configuration on the clipboard."""
    inspector = _listed_inspector(FakeWebinspectord())

    html = targets_html(inspector, "127.0.0.1:9222")

    assert html.count('<button type="button" class="copy"') == 1
    assert html.index('class="copy"') < html.index("<pre>")


def test_a_page_target_gets_a_chrome_attach_config() -> None:
    inspector = _listed_inspector(FakeWebinspectord())
    inspector.application_pages[APP_ID]["2"] = Page.from_page_dictionary({
        "WIRPageIdentifierKey": 2,
        "WIRTypeKey": "WIRTypeWebPage",
        "WIRTitleKey": "Example",
        "WIRURLKey": "https://example.com/path?q=1",
    })

    html = targets_html(inspector, "127.0.0.1:9222")

    assert '"type": "chrome"' in html
    assert '"urlFilter": "https://example.com/path?q=1"' in html
    assert '"port": 9222' in html


async def test_the_landing_page_api_reports_held_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    async with bridge_client(monkeypatch) as (client, _):
        HELD_TARGETS[f"{APP_ID}:1"] = cast(Any, object())

        listing = (await client.get("/api/targets")).json()

        assert listing["pause_new_targets"] is False
        assert [(t["id"], t["type"], t["paused"]) for t in listing["targets"]] == [(f"{APP_ID}:1", "node", True)]
        assert listing["targets"][0]["devtoolsFrontendUrl"].startswith("/devtools/js_app.html?ws=")


def _offline_page_target(
    connection: FakeWebinspectord, target_id: str = "page-1", pause_on_start: bool = False
) -> CdpTarget:
    inspector = WebinspectorService(lockdown=cast(Any, object()))
    inspector._service = cast(Any, connection)
    page = Page.from_page_dictionary({
        "WIRPageIdentifierKey": 1,
        "WIRTypeKey": "WIRTypeWebPage",
        "WIRTitleKey": "Example",
        "WIRURLKey": "https://example.com/",
    })
    application = Application(
        APP_ID, "com.example.app", 42, "Example", AutomationAvailability.NOT_AVAILABLE, 1, False, True
    )
    target = CdpTarget(SessionProtocol(inspector, "SESSION", application, page, method_prefix=""), target_id)
    target.pause_on_start = pause_on_start
    # The frontend had enabled the debugger; a target that takes over gets it replayed.
    target._setup_messages["Debugger.enable"] = {}
    return target


def _target_created(target_id: str, **extra: Any) -> dict[str, Any]:
    return {
        "method": "Target.targetCreated",
        "params": {"targetInfo": {"targetId": target_id, "type": "page", **extra}},
    }


def _inner_methods(connection: FakeWebinspectord) -> list[tuple[str, Optional[str]]]:
    """(method, targetId) of every message sent, unwrapping Target.sendMessageToTarget."""
    methods: list[tuple[str, Optional[str]]] = []
    for message in connection.socket_data():
        if message["method"] == "Target.sendMessageToTarget":
            methods.append((json.loads(message["params"]["message"])["method"], message["params"]["targetId"]))
        else:
            methods.append((message["method"], message.get("params", {}).get("targetId")))
    return methods


async def test_holding_navigations_asks_webkit_to_pause_new_targets() -> None:
    """WebKit's Target.setPauseOnStart holds the page target a cross-site navigation creates
    until it is resumed - the one creation-time hold WebKit offers for pages."""
    connection = FakeWebinspectord()
    target = _offline_page_target(connection)
    try:
        await target.hold_new_targets()

        assert connection.socket_data()[-1] == {
            "id": connection.socket_data()[-1]["id"],
            "method": "Target.setPauseOnStart",
            "params": {"pauseOnStart": True},
        }
    finally:
        await target.close()


async def test_a_paused_provisional_target_is_set_up_and_then_resumed() -> None:
    """The point of holding it: the frontend's debugger state reaches the new process before its
    first script runs. Setup goes first, then the resume."""
    connection = FakeWebinspectord()
    target = _offline_page_target(connection)
    try:
        await target._target_created(_target_created("page-2", isProvisional=True, isPaused=True))

        assert _inner_methods(connection) == [("Debugger.enable", "page-2"), ("Target.resume", "page-2")]
    finally:
        await target.close()


async def test_a_paused_provisional_target_is_paused_on_its_first_statement_in_pause_mode() -> None:
    connection = FakeWebinspectord()
    target = _offline_page_target(connection, pause_on_start=True)
    try:
        await target._target_created(_target_created("page-2", isProvisional=True, isPaused=True))

        assert _inner_methods(connection) == [
            ("Debugger.enable", "page-2"),
            ("Debugger.pause", "page-2"),
            ("Target.resume", "page-2"),
        ]
    finally:
        await target.close()


async def test_a_target_that_is_not_paused_is_not_resumed() -> None:
    connection = FakeWebinspectord()
    target = _offline_page_target(connection)
    try:
        await target._target_created(_target_created("page-2"))

        assert _inner_methods(connection) == [("Debugger.enable", "page-2")]
    finally:
        await target.close()


async def test_pause_mode_pauses_a_page_once_its_debugger_is_enabled() -> None:
    """A page cannot be held at creation, so the closest to Safari's automatic pause is stopping
    it on its next statement as soon as the client's debugger is on."""
    connection = FakeWebinspectord()
    target = _offline_page_target(connection, pause_on_start=True)
    try:
        await target.send({"id": 3, "method": "Debugger.enable", "params": {}})

        await eventually(lambda: ("Debugger.pause", "page-1") in _inner_methods(connection))
        methods = [method for method, _ in _inner_methods(connection)]
        assert methods.index("Debugger.enable") < methods.index("Debugger.pause")
    finally:
        await target.close()
