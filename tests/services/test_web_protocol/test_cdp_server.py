import asyncio
import base64
import itertools
import json
import logging
import socket
import threading
import time
import urllib.request
import uuid
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager, suppress
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional, cast
from urllib.parse import urlsplit

import httpx
import pytest
import uvicorn
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, CloseConnection, Ping, TextMessage
from wsproto.events import Request as WsRequest

from pymobiledevice3.exceptions import WebInspectorNotEnabledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.web_protocol.cdp_browser import PAGE_LOCKS, PAGE_TAKEOVERS
from pymobiledevice3.services.web_protocol.cdp_server import (
    DEVTOOLS_FRONTEND_HOST,
    DEVTOOLS_FRONTEND_REV,
    _fetch,
    _frontend_base,
    app,
    bridge_version,
    targets_html,
)
from pymobiledevice3.services.web_protocol.cdp_target import (
    JS_CONTEXT_EXECUTION_ID,
    REPLY_WAKE_INTERVAL,
    CdpTarget,
)
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import SAFARI, Application, AutomationAvailability, Page, WebinspectorService
from tests.services.test_web_protocol.golden_flow import load_fixture, replay_flat_session, replay_page_session
from tests.services.test_web_protocol.protocol_inventory import load_spec, validate_editor_event

TIMEOUT = 30


@asynccontextmanager
async def cdp_server(lockdown: LockdownClient) -> AsyncGenerator[tuple[int, WebinspectorService], None]:
    """Run the CDP server against the device and yield (port, inspector)."""
    inspector = WebinspectorService(lockdown=lockdown)
    try:
        await inspector.connect()
    except WebInspectorNotEnabledError:
        pytest.xfail("Web Inspector is disabled on the device")
    app.state.inspector = inspector
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, ws="wsproto"))
    serve_task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            assert not serve_task.done()
            await asyncio.sleep(0.1)
        yield server.servers[0].sockets[0].getsockname()[1], inspector
    finally:
        # force_exit skips uvicorn's graceful wait so a wedged debugger session can't hang the test
        server.should_exit = True
        server.force_exit = True
        await asyncio.wait_for(serve_task, TIMEOUT)
        await inspector.close()


@asynccontextmanager
async def cdp_server_with_safari_page(
    lockdown: LockdownClient,
) -> AsyncGenerator[tuple[int, list[dict[str, Any]]], None]:
    """Run the CDP server against the device and yield (port, listed Safari targets)."""
    async with cdp_server(lockdown) as (port, inspector):
        await inspector.open_app(SAFARI)
        targets = []
        for _ in range(TIMEOUT):
            targets = [target for target in await http_get_json(port, "/json/list") if target["type"] == "page"]
            if targets:
                break
            await asyncio.sleep(1)
        assert targets, "no inspectable Safari page was listed"
        yield port, targets


async def http_get_json(port: int, path: str) -> Any:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        response = await reader.read()
    finally:
        writer.close()
        await writer.wait_closed()
    headers, _, body = response.partition(b"\r\n\r\n")
    assert headers.split(b" ", 2)[1] == b"200"
    return json.loads(body)


class CdpWebsocketClient:
    def __init__(self, port: int, page_id: str) -> None:
        self.port = port
        self.page_id = page_id
        self.ws = WSConnection(ConnectionType.CLIENT)
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.seen_events: set[str] = set()

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writer.write(
            self.ws.send(WsRequest(host=f"127.0.0.1:{self.port}", target=f"/devtools/page/{self.page_id}"))
        )
        await self.writer.drain()
        assert isinstance(await self._next_event(), AcceptConnection)

    async def close(self) -> None:
        assert self.writer is not None
        self.writer.close()
        await self.writer.wait_closed()

    async def send(self, message: dict[str, Any]) -> None:
        assert self.writer is not None
        self.writer.write(self.ws.send(TextMessage(data=json.dumps(message))))
        await self.writer.drain()

    async def receive(self) -> dict[str, Any]:
        text = ""
        while True:
            event = await self._next_event()
            assert not isinstance(event, CloseConnection)
            if isinstance(event, TextMessage):
                text += event.data
                if event.message_finished:
                    message = json.loads(text)
                    if "method" in message:
                        self.seen_events.add(message["method"])
                    return message

    async def command(self, id_: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a request and wait for its response; a lost response fails the test by timeout."""
        await self.send({"id": id_, "method": method, "params": params})

        async def wait_for_response() -> dict[str, Any]:
            while True:
                message = await self.receive()
                if message.get("id") == id_:
                    return message

        return await asyncio.wait_for(wait_for_response(), TIMEOUT)

    async def _next_event(self) -> Any:
        assert self.reader is not None
        while True:
            for event in self.ws.events():
                if isinstance(event, Ping):
                    # uvicorn pings an idle connection and closes it when nothing pongs back
                    # ("keepalive ping timeout"), which killed any session that ran longer than
                    # its ping timeout - the device tests are exactly that long.
                    assert self.writer is not None
                    self.writer.write(self.ws.send(event.response()))
                    await self.writer.drain()
                    continue
                return event
            self.ws.receive_data(await self.reader.read(4096))


async def testp_cdp_server_end_to_end(lockdown: LockdownClient) -> None:
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        version = await http_get_json(port, "/json/version")
        # /json/version must not be shadowed by the /json targets catch-all
        assert version["Browser"] == "Safari"
        assert f"ws://127.0.0.1:{port}/devtools/browser/" in version["webSocketDebuggerUrl"]
        assert targets[0]["webSocketDebuggerUrl"] == f"ws://127.0.0.1:{port}/devtools/page/{targets[0]['id']}"

        async def evaluate_in_new_session() -> None:
            client = CdpWebsocketClient(port, targets[0]["id"])
            await asyncio.wait_for(client.connect(), TIMEOUT)
            try:
                result = await client.command(1, "Runtime.evaluate", {"expression": "40+2"})
                assert result["result"]["result"]["value"] == 42
            finally:
                await client.close()

        # Two sequential sessions: the second verifies the WIR socket teardown on disconnect,
        # without which webinspectord never delivers target events to a reconnecting client.
        await evaluate_in_new_session()
        await evaluate_in_new_session()


class CdpBrowserWebsocketClient(CdpWebsocketClient):
    """CDP client for the browser endpoint (flat session mode), the way Puppeteer/Playwright's
    connectOverCDP attaches: it talks to /devtools/browser/<id>, discovers page targets through
    the Target domain, and tags every per-page message with the attachment's sessionId."""

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writer.write(
            self.ws.send(WsRequest(host=f"127.0.0.1:{self.port}", target=f"/devtools/browser/{self.page_id}"))
        )
        await self.writer.drain()
        assert isinstance(await self._next_event(), AcceptConnection)

    async def wait_for_event(self, method: str) -> dict[str, Any]:
        """Wait for the next event with the given method (ignoring responses and other events)."""

        async def wait() -> dict[str, Any]:
            while True:
                message = await self.receive()
                if "id" not in message and message.get("method") == method:
                    return message

        return await asyncio.wait_for(wait(), TIMEOUT)

    async def session_command(self, session_id: str, id_: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a request under a page attachment's sessionId and wait for its response."""
        await self.send({"id": id_, "sessionId": session_id, "method": method, "params": params})

        async def wait_for_response() -> dict[str, Any]:
            while True:
                message = await self.receive()
                if message.get("id") == id_:
                    return message

        return await asyncio.wait_for(wait_for_response(), TIMEOUT)


async def testp_cdp_browser_endpoint_answers_puppeteer_connect(lockdown: LockdownClient) -> None:
    """Puppeteer's connect() over the browser endpoint calls Target.getBrowserContexts and iterates
    the result; a bare {} ack made it throw "contextIds is not iterable" before it saw a page. The
    endpoint must return the (empty) browser-context list Chrome does."""
    async with cdp_server_with_safari_page(lockdown) as (port, _):
        version = await http_get_json(port, "/json/version/")
        browser_id = urlsplit(version["webSocketDebuggerUrl"]).path.rsplit("/", 1)[1]
        client = CdpBrowserWebsocketClient(port, browser_id)
        await asyncio.wait_for(client.connect(), TIMEOUT)
        ids = itertools.count(1)
        try:
            await client.command(next(ids), "Target.attachToBrowserTarget", {})
            contexts = await client.command(next(ids), "Target.getBrowserContexts", {})
            assert isinstance(contexts["result"].get("browserContextIds"), list), (
                f"Target.getBrowserContexts must return a browserContextIds array: {contexts}"
            )
        finally:
            await client.close()


async def testp_cdp_browser_endpoint_announces_targets_after_get_targets(lockdown: LockdownClient) -> None:
    """
    VS Code's js-debug builds its target picker by calling Target.getTargets first and then
    Target.setDiscoverTargets, and waits for the initial Target.targetCreated batch before it will
    attach. The bridge announced only targets that were *new* since it last listed, so a page
    already learnt through getTargets produced no targetCreated on setDiscoverTargets and js-debug
    hung with no targets offered. Chrome reports every existing target when discovery is enabled;
    the batch must arrive whatever was asked before.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        version = await http_get_json(port, "/json/version/")
        browser_id = urlsplit(version["webSocketDebuggerUrl"]).path.rsplit("/", 1)[1]
        page_id = targets[0]["id"]
        client = CdpBrowserWebsocketClient(port, browser_id)
        await asyncio.wait_for(client.connect(), TIMEOUT)
        ids = itertools.count(1)
        try:
            await client.command(next(ids), "Target.attachToBrowserTarget", {})
            listed = await client.command(next(ids), "Target.getTargets", {})
            target_ids = {t["targetId"] for t in listed["result"]["targetInfos"]}
            assert page_id in target_ids, f"the Safari page must be listed: {target_ids}"

            # Discovery is enabled only now, after getTargets already learnt the page.
            await client.send({"id": next(ids), "method": "Target.setDiscoverTargets", "params": {"discover": True}})

            async def announced() -> set[str]:
                seen: set[str] = set()
                while page_id not in seen:
                    message = await client.receive()
                    if message.get("method") == "Target.targetCreated":
                        seen.add(message["params"]["targetInfo"]["targetId"])
                return seen

            seen = await asyncio.wait_for(announced(), TIMEOUT)
            assert page_id in seen, "setDiscoverTargets must announce the page even after getTargets"
        finally:
            await client.close()


async def testp_cdp_browser_endpoint_attaches_playwright_style(lockdown: LockdownClient) -> None:
    """
    A Chrome-protocol client attaching over the browser endpoint (Puppeteer/Playwright's
    connectOverCDP) to a page that was already loaded when it attached must be able to read and
    evaluate against it - exactly as if it had attached right after a fresh navigation.

    This exercises the whole flat-session handshake Playwright performs, and guards four separate
    regressions that each silently broke it:
      * the auto-attached target's targetInfo must carry a browserContextId (CRBrowser asserts on
        it before adopting the page);
      * Page.getFrameTree must be answered (Playwright gates page-readiness on its frame tree;
        WebKit only implements Page.getResourceTree);
      * Page.setLifecycleEventsEnabled must be accepted (WebKit has no such method, and a raw
        forward errors and rejects Playwright's initialization);
      * Runtime.enable must yield an executionContextCreated whose auxData ties the context to its
        frame and marks it the main world - without it Playwright never registers the context and
        every evaluate hangs.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        # Playwright's connectOverCDP fetches /json/version with a trailing slash; it must return
        # the version dict (with webSocketDebuggerUrl), not fall through to the target listing.
        version = await http_get_json(port, "/json/version/")
        assert version.get("webSocketDebuggerUrl"), f"/json/version/ must carry a browser ws url: {version}"
        browser_id = urlsplit(version["webSocketDebuggerUrl"]).path.rsplit("/", 1)[1]
        page_id = targets[0]["id"]
        client = CdpBrowserWebsocketClient(port, browser_id)
        await asyncio.wait_for(client.connect(), TIMEOUT)
        try:
            # Playwright's connectOverCDP enables auto-attach on the root connection and waits for
            # the page to be announced as an attached target. The Target.attachedToTarget event is
            # emitted before the setAutoAttach reply, so watch for it directly rather than through
            # command() (which would consume and discard it).
            await client.send({
                "id": 1,
                "method": "Target.setAutoAttach",
                "params": {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True},
            })

            async def wait_for_page_attached() -> dict[str, Any]:
                while True:
                    message = await client.receive()
                    if (
                        message.get("method") == "Target.attachedToTarget"
                        and message["params"]["targetInfo"]["targetId"] == page_id
                    ):
                        return message

            attached = await asyncio.wait_for(wait_for_page_attached(), TIMEOUT)
            target_info = attached["params"]["targetInfo"]
            assert target_info.get("browserContextId"), (
                f"attached targetInfo must carry a browserContextId; Playwright asserts on it: {target_info}"
            )
            session_id = attached["params"]["sessionId"]

            ids = itertools.count(2)
            await client.session_command(session_id, next(ids), "Page.enable", {})

            # Playwright sends Page.getFrameTree with no params key at all; the handler must not
            # assume one is present.
            frame_tree_id = next(ids)
            await client.send({"id": frame_tree_id, "sessionId": session_id, "method": "Page.getFrameTree"})

            async def wait_for_frame_tree() -> dict[str, Any]:
                while True:
                    message = await client.receive()
                    if message.get("id") == frame_tree_id:
                        return message

            frame_tree = await asyncio.wait_for(wait_for_frame_tree(), TIMEOUT)
            assert "result" in frame_tree, f"Page.getFrameTree must be answered, not error: {frame_tree.get('error')}"
            frame_id = frame_tree["result"]["frameTree"]["frame"]["id"]

            lifecycle = await client.session_command(
                session_id, next(ids), "Page.setLifecycleEventsEnabled", {"enabled": True}
            )
            assert "result" in lifecycle, (
                f"Page.setLifecycleEventsEnabled must be accepted, not error: {lifecycle.get('error')}"
            )

            # Playwright sends Page.enable before Runtime.enable; WebKit then retroactively
            # announces the already-existing context. Capture that event and the enable response.
            await client.send({"id": next(ids), "sessionId": session_id, "method": "Runtime.enable", "params": {}})
            context = await client.wait_for_event("Runtime.executionContextCreated")
            payload = context["params"]["context"]
            aux = payload.get("auxData", {})
            assert aux.get("isDefault") is True, f"the main-world context must be marked isDefault: {payload}"
            assert aux.get("frameId") == frame_id, (
                f"the context's auxData.frameId must match the frame tree ({frame_id}): {payload}"
            )
            # Chrome ties the top frame's id to the page's targetId; Playwright looks the page's
            # session up by the frame id and throws "Frame has been detached" if they differ.
            assert frame_id == page_id, f"the top frame id must equal the targetId {page_id}: {frame_id}"

            # The announced context must actually be usable: evaluating in it (as Playwright does,
            # addressing it by contextId) returns a value rather than hanging or erroring.
            result = await client.session_command(
                session_id,
                next(ids),
                "Runtime.evaluate",
                {"expression": "6*7", "contextId": payload["id"], "returnByValue": True},
            )
            assert result["result"]["result"]["value"] == 42, result

            # WebKit has no isolated worlds, but Playwright creates one and evaluates page.title()
            # and locator text in it, blocking until its context is announced. The bridge must
            # synthesize that world's context and let evaluations against it run (in the page's
            # real world), or those read APIs hang forever.
            world_id = next(ids)
            await client.send({
                "id": world_id,
                "sessionId": session_id,
                "method": "Page.createIsolatedWorld",
                "params": {"frameId": frame_id, "worldName": "__pmd3_test_world__", "grantUniveralAccess": True},
            })

            async def wait_for_utility_context() -> dict[str, Any]:
                while True:
                    message = await client.receive()
                    if (
                        message.get("method") == "Runtime.executionContextCreated"
                        and message["params"]["context"].get("name") == "__pmd3_test_world__"
                    ):
                        return message

            utility = await asyncio.wait_for(wait_for_utility_context(), TIMEOUT)
            utility_id = utility["params"]["context"]["id"]
            assert utility["params"]["context"]["auxData"]["frameId"] == page_id, utility
            in_world = await client.session_command(
                session_id,
                next(ids),
                "Runtime.evaluate",
                {"expression": "1+2", "contextId": utility_id, "returnByValue": True},
            )
            assert in_world["result"]["result"]["value"] == 3, in_world
        finally:
            await client.close()


async def testp_cdp_server_reports_the_navigation_lifecycle(lockdown: LockdownClient) -> None:
    """
    WebKit reports a load with the pre-lifecycle events Chrome replaced years ago, so a modern CDP
    client saw a navigation happen and never learned it finished: Playwright's page.goto(),
    page.reload() and waitForNavigation() all block on Page.lifecycleEvent, and page.goto() also
    needs the new document's loaderId back from Page.navigate - without it the client waits for a
    *same-document* navigation, which a real page load never reports. Both hung until timeout.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        page_id = targets[0]["id"]
        client = CdpWebsocketClient(port, page_id)
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:
            lifecycle: list[dict[str, Any]] = []

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                """client.command, keeping the lifecycle events it would otherwise discard."""
                id_ = next(message_ids)
                await client.send({"id": id_, "method": method, "params": params})

                async def wait_for_response() -> dict[str, Any]:
                    while True:
                        message = await client.receive()
                        if message.get("method") == "Page.lifecycleEvent":
                            lifecycle.append(message["params"])
                        if message.get("id") == id_:
                            return message

                return await asyncio.wait_for(wait_for_response(), TIMEOUT)

            async def wait_for_lifecycle(name: str) -> dict[str, Any]:
                async def wait() -> dict[str, Any]:
                    while True:
                        for event in lifecycle:
                            if event["name"] == name:
                                return event
                        message = await client.receive()
                        if message.get("method") == "Page.lifecycleEvent":
                            lifecycle.append(message["params"])

                return await asyncio.wait_for(wait(), TIMEOUT)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.setLifecycleEventsEnabled", {"enabled": True})
            lifecycle.clear()
            # Navigating must report the document it committed, or a client cannot tell this from
            # an in-page navigation.
            navigate = await command("Page.navigate", {"url": "https://example.com/"})
            assert navigate["result"].get("loaderId"), (
                f"Page.navigate must report the committed document's loaderId: {navigate}"
            )
            assert navigate["result"]["frameId"] == page_id, navigate
            # ... and the load must be announced through the modern lifecycle events.
            load = await wait_for_lifecycle("load")
            assert load["frameId"] == page_id, f"a lifecycle event must name the client's frame: {load}"
            assert {event["name"] for event in lifecycle} >= {"init", "load"}, (
                f"a committed navigation must open and finish a lifecycle: {lifecycle}"
            )
        finally:
            await client.close()


async def testp_cdp_server_implements_the_screenshot_methods(lockdown: LockdownClient) -> None:
    """
    Chrome's screenshot path is Page.getLayoutMetrics (for the clip and the device pixel ratio)
    followed by Page.captureScreenshot, and WebKit implements neither - so page.screenshot() died
    on the first of them before any capture was ever attempted. Both are synthesized: the metrics
    by measuring the page, the capture from WebKit's own Page.snapshotRect.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                return await client.command(next(message_ids), method, params)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})

            metrics = await command("Page.getLayoutMetrics", {})
            assert "result" in metrics, f"Page.getLayoutMetrics must be answered: {metrics.get('error')}"
            content_size = metrics["result"]["contentSize"]
            assert content_size["width"] > 0 and content_size["height"] > 0, metrics
            # Chrome's client divides contentSize by cssContentSize to recover the pixel ratio, so
            # the two must be consistent rather than merely present.
            assert metrics["result"]["cssContentSize"]["width"] == content_size["width"], metrics
            assert metrics["result"]["visualViewport"]["scale"], metrics

            shot = await command(
                "Page.captureScreenshot",
                {"format": "png", "clip": {"x": 0, "y": 0, "width": 64, "height": 64, "scale": 1}},
            )
            assert "result" in shot, f"Page.captureScreenshot must be answered: {shot.get('error')}"
            # The client feeds this straight to a base64 decoder, so it must be bare payload
            # rather than the data: URL WebKit answers with.
            data = shot["result"]["data"]
            assert not data.startswith("data:"), "captureScreenshot must strip the data URL prefix"
            assert base64.b64decode(data)[:8] == b"\x89PNG\r\n\x1a\n", "captureScreenshot must return a PNG"

        finally:
            await client.close()


async def testp_cdp_server_implements_the_interaction_methods(lockdown: LockdownClient) -> None:
    """
    Before every click, fill or hover, a Chrome client brings the target into view with
    DOM.scrollIntoViewIfNeeded and then picks the point to act on out of DOM.getContentQuads.
    WebKit implements neither, and Playwright treats the resulting "was not found" as a retryable
    condition - so every interaction spun until its timeout with nothing explaining why. Both are
    synthesized by measuring and scrolling the element in-page.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                return await client.command(next(message_ids), method, params)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})

            body = await command("Runtime.evaluate", {"expression": "document.body"})
            object_id = body["result"]["result"]["objectId"]
            scrolled = await command("DOM.scrollIntoViewIfNeeded", {"objectId": object_id})
            assert "result" in scrolled, f"DOM.scrollIntoViewIfNeeded must be answered: {scrolled.get('error')}"
            quads = await command("DOM.getContentQuads", {"objectId": object_id})
            assert "result" in quads, f"DOM.getContentQuads must be answered: {quads.get('error')}"
            # A quad is the element's four corners, flattened - the client picks its click point
            # out of these, so a malformed one silently misses the element.
            assert quads["result"]["quads"], f"a rendered <body> must have at least one quad: {quads}"
            assert all(len(quad) == 8 for quad in quads["result"]["quads"]), quads

            # A node that is gone must be refused with the message the client special-cases,
            # rather than looking like an unimplemented method.
            detached = await command("Runtime.evaluate", {"expression": "document.createElement('div')"})
            detached_error = await command(
                "DOM.scrollIntoViewIfNeeded", {"objectId": detached["result"]["result"]["objectId"]}
            )
            assert "Node is detached from document" in detached_error.get("error", {}).get("message", ""), (
                f"a detached node must be reported as such: {detached_error}"
            )
        finally:
            await client.close()


async def testp_cdp_server_keeps_each_frame_in_its_own_execution_context(lockdown: LockdownClient) -> None:
    """
    A page with subframes gets one main-world execution context announced per frame, and they are
    not interchangeable. The bridge used to keep only the most recently announced one as "the
    page's" context and route every isolated world to it, so the moment a subframe loaded - an ad
    or a payment iframe - evaluations meant for the main frame silently ran inside that subframe
    instead. A client's helper objects do not exist there, so its reads came back undefined.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        page_id = targets[0]["id"]
        client = CdpWebsocketClient(port, page_id)
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        contexts: list[dict[str, Any]] = []
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                """client.command, keeping the context announcements it would otherwise drop."""
                id_ = next(message_ids)
                await client.send({"id": id_, "method": method, "params": params})

                async def wait_for_response() -> dict[str, Any]:
                    while True:
                        message = await client.receive()
                        if message.get("method") == "Runtime.executionContextCreated":
                            contexts.append(message["params"]["context"])
                        if message.get("id") == id_:
                            return message

                return await asyncio.wait_for(wait_for_response(), TIMEOUT)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})
            # The navigation replaced the document; only what the fresh one announces counts (a
            # page left over from an earlier run may already have had a subframe).
            contexts.clear()
            world = await command(
                "Page.createIsolatedWorld",
                {"frameId": page_id, "worldName": "__pmd3_frame_world__", "grantUniveralAccess": True},
            )
            world_id = world["result"]["executionContextId"]

            async def in_top_frame() -> Any:
                """Is the main frame's isolated world still evaluating in the main frame?"""
                response = await command(
                    "Runtime.evaluate",
                    {"expression": "window === window.top", "contextId": world_id, "returnByValue": True},
                )
                return response.get("result", {}).get("result", {}).get("value")

            assert await in_top_frame() is True, "the isolated world must start in the main frame"

            def subframe_announced() -> bool:
                return any(context.get("auxData", {}).get("frameId") not in (page_id, None) for context in contexts)

            # A same-origin child frame makes WebKit announce a second main-world context; that
            # announcement is what used to hijack the page's default context.
            await command(
                "Runtime.evaluate",
                {
                    "expression": (
                        "const f = document.createElement('iframe');"
                        " f.src = 'https://example.com/'; document.body.appendChild(f); 'added'"
                    ),
                    "returnByValue": True,
                },
            )
            # Keep asking while the subframe loads: the drift appears the moment its context is
            # announced, and the answer must never move out of the top frame.
            for _ in range(TIMEOUT):
                assert await in_top_frame() is True, "the main frame's isolated world drifted into the subframe"
                if subframe_announced():
                    break
                await asyncio.sleep(0.5)
            assert subframe_announced(), "the subframe never announced an execution context"
            # One more read after the announcement has definitely been processed.
            assert await in_top_frame() is True, "the main frame's isolated world drifted into the subframe"

            # A frame this session cannot reach must be refused rather than quietly answered from
            # the top frame: a cross-origin child is debugged through a target of its own, and
            # silently reporting the main document instead is worse than an error.
            unreachable = await command(
                "Page.createIsolatedWorld",
                {"frameId": "0.unreachable", "worldName": "__pmd3_absent__", "grantUniveralAccess": True},
            )
            absent_world = unreachable["result"]["executionContextId"]
            refused = await command(
                "Runtime.evaluate",
                {"expression": "document.URL", "contextId": absent_world, "returnByValue": True},
            )
            assert "result" not in refused, f"an unreachable frame must not be answered: {refused}"
            assert "not reachable" in refused["error"]["message"], refused
        finally:
            await client.close()


async def testp_cdp_server_reports_remote_object_subtypes(lockdown: LockdownClient) -> None:
    """
    Chrome tags a RemoteObject with the subtype of the built-in it is - most consequentially
    `promise`, which is how a client tells a value it still has to resolve from a plain object.
    WebKit reports only a className, so those objects arrived looking like ordinary ones.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def evaluate(expression: str) -> dict[str, Any]:
                response = await client.command(next(message_ids), "Runtime.evaluate", {"expression": expression})
                return response["result"]["result"]

            promise = await evaluate("Promise.resolve(42)")
            assert promise.get("subtype") == "promise", f"a promise must be tagged as one: {promise}"
            # Where WebKit does classify an object itself, its answer is kept rather than remapped
            # (it calls a typed array an "array", which is a subtype Chrome also defines).
            typed = await evaluate("new Uint8Array(1)")
            assert typed.get("subtype") == "array", typed
            for expression, subtype in (
                ("[1, 2, 3]", "array"),
                ("new Map()", "map"),
                ("new Set()", "set"),
                ("new Date()", "date"),
                ("/x/", "regexp"),
                ("new TypeError('x')", "error"),
            ):
                result = await evaluate(expression)
                assert result.get("subtype") == subtype, f"{expression} -> {result}"
            # A page's own class is not a built-in and must stay a plain object.
            custom = await evaluate("(class Promise2 { })  && new (class Foo { })()")
            assert "subtype" not in custom, f"a plain object must not be given a subtype: {custom}"
        finally:
            await client.close()


async def testp_cdp_server_types_text_into_the_page(lockdown: LockdownClient) -> None:
    """
    WebKit has no Input domain, so the bridge types in-page. Two shapes have to work, because a
    client sends one or the other and never both: Input.insertText (what fill() uses), and a
    character carried on a key event. DevTools puts it on a "char" event; Playwright puts it on
    keyDown and never sends "char" at all, which used to type nothing - silently, with every call
    reporting success, so a form stayed empty while a test believed it was filled. The character
    must also be typed exactly once when a client sends both.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                return await client.command(next(message_ids), method, params)

            async def evaluate(expression: str) -> Any:
                response = await command("Runtime.evaluate", {"expression": expression, "returnByValue": True})
                return response.get("result", {}).get("result", {}).get("value")

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})

            async def reset_field() -> None:
                await evaluate(
                    "(function () {"
                    "  document.body.innerHTML = '';"
                    "  var el = document.createElement('input');"
                    "  el.id = 'f';"
                    "  el.type = 'text';"
                    "  document.body.appendChild(el);"
                    "  el.focus();"
                    "  return 'ok';"
                    "})()"
                )

            async def field_value() -> Any:
                return await evaluate("document.getElementById('f').value")

            # Input.insertText must reach the page rather than being acknowledged into the void.
            await reset_field()
            await command("Input.insertText", {"text": "hello"})
            assert await field_value() == "hello", "Input.insertText must type into the focused field"

            # A character carried on keyDown alone (no "char" event ever sent) must be typed.
            await reset_field()
            for char in "abc":
                await command("Input.dispatchKeyEvent", {"type": "keyDown", "key": char, "text": char})
                await command("Input.dispatchKeyEvent", {"type": "keyUp", "key": char, "text": char})
            assert await field_value() == "abc", "a character carried on keyDown must be typed"

            # A client that sends keyDown, char and keyUp for one key must type it once, not twice.
            await reset_field()
            await command("Input.dispatchKeyEvent", {"type": "keyDown", "key": "x", "text": "x"})
            await command("Input.dispatchKeyEvent", {"type": "char", "key": "x", "text": "x"})
            await command("Input.dispatchKeyEvent", {"type": "keyUp", "key": "x", "text": "x"})
            assert await field_value() == "x", "a key sent as keyDown+char+keyUp must be typed once"

            # A key that performs an action rather than producing text must not type anything.
            await reset_field()
            for type_ in ("keyDown", "keyUp"):
                await command("Input.dispatchKeyEvent", {"type": type_, "key": "ArrowLeft", "code": "ArrowLeft"})
            assert await field_value() == "", "a non-printable key must not type anything"

            # The value must be written through the native setter, or a framework that tracks its
            # inputs never sees the change (the field looks filled while the app believes it empty).
            await reset_field()
            await evaluate(
                "window.__seen = [];"
                " document.getElementById('f').addEventListener('input', e => window.__seen.push(e.target.value));"
                " 'ok'"
            )
            await command("Input.insertText", {"text": "abc"})
            assert await evaluate("JSON.stringify(window.__seen)") == '["abc"]', (
                "typing must fire a real input event carrying the new value"
            )
        finally:
            await client.close()


async def testp_cdp_server_makes_child_frames_reachable(lockdown: LockdownClient) -> None:
    """
    A client builds its frame model from the live attach/navigate pair and only walks the frame
    tree once, when it attaches. WebKit never sends Page.frameAttached, so every child frame that
    appeared later - or was recreated by a reload - stayed invisible: page.frames() never grew and
    a navigation for a frame the client did not know was discarded. Reaching into one needs two
    more things WebKit does not provide: DOM.describeNode, to resolve an <iframe> element to the
    frame it hosts, and the named isolated world Chrome creates in every document that loads.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        page_id = targets[0]["id"]
        client = CdpWebsocketClient(port, page_id)
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        world_name = "__pmd3_auto_world__"
        events: list[dict[str, Any]] = []
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                """client.command, keeping the frame and context events it would otherwise drop."""
                id_ = next(message_ids)
                await client.send({"id": id_, "method": method, "params": params})

                async def wait_for_response() -> dict[str, Any]:
                    while True:
                        message = await client.receive()
                        if "id" not in message:
                            events.append(message)
                        if message.get("id") == id_:
                            return message

                return await asyncio.wait_for(wait_for_response(), TIMEOUT)

            def child_frame_id() -> Optional[str]:
                return next(
                    (event["params"]["frameId"] for event in events if event.get("method") == "Page.frameAttached"),
                    None,
                )

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})
            # Registering a world by name is how a client asks for one in every document, rather
            # than creating it per frame - a frame that appears later has to get it too.
            await command("Page.addScriptToEvaluateOnNewDocument", {"source": "", "worldName": world_name})
            events.clear()

            await command(
                "Runtime.evaluate",
                {
                    "expression": (
                        "const f = document.createElement('iframe');"
                        " f.name = 'pmd3kid'; f.src = 'https://example.com/';"
                        " document.body.appendChild(f); 'added'"
                    ),
                    "returnByValue": True,
                },
            )
            for _ in range(TIMEOUT):
                if child_frame_id() is not None:
                    break
                await command("Runtime.evaluate", {"expression": "1", "returnByValue": True})
                await asyncio.sleep(0.5)
            frame_id = child_frame_id()
            assert frame_id is not None, "a child frame must be announced with Page.frameAttached"
            attached = next(event for event in events if event.get("method") == "Page.frameAttached")
            assert attached["params"]["parentFrameId"] == page_id, attached

            # The world the client registered by name must exist in the new frame as well.
            async def auto_world_for(frame: str) -> Optional[int]:
                for event in events:
                    if event.get("method") != "Runtime.executionContextCreated":
                        continue
                    context = event["params"]["context"]
                    if context.get("name") == world_name and context["auxData"].get("frameId") == frame:
                        return context["id"]
                return None

            for _ in range(TIMEOUT):
                if await auto_world_for(frame_id) is not None:
                    break
                await command("Runtime.evaluate", {"expression": "1", "returnByValue": True})
                await asyncio.sleep(0.5)
            world_id = await auto_world_for(frame_id)
            assert world_id is not None, f"the registered world must be created in the child frame: {world_name}"

            # It must really be the child frame's world, not the page's.
            in_child = await command(
                "Runtime.evaluate",
                {"expression": "window === window.top", "contextId": world_id, "returnByValue": True},
            )
            assert in_child["result"]["result"]["value"] is False, (
                f"the child frame's world must evaluate inside the child frame: {in_child}"
            )

            # And the <iframe> element must resolve to that same frame, which is how a client
            # reaches into it from a locator.
            element = await command(
                "Runtime.evaluate", {"expression": "document.querySelector('iframe[name=pmd3kid]')"}
            )
            described = await command("DOM.describeNode", {"objectId": element["result"]["result"]["objectId"]})
            assert described["result"]["node"].get("frameId") == frame_id, (
                f"an iframe element must resolve to the frame it hosts: {described}"
            )

            # The frame tree is the only way a client attaching later learns about frames that
            # already exist, and it walks the tree by parent: a child whose parentId names
            # WebKit's own id for the top frame refers to a frame the client never heard of, and
            # the whole subtree is dropped.
            tree = await command("Page.getFrameTree", {})
            children = tree["result"]["frameTree"].get("childFrames") or []
            assert children, f"the frame tree must report the child frame: {tree}"
            assert children[0]["frame"]["parentId"] == page_id, (
                f"a child frame's parentId must be the id the client knows the top frame by: {children[0]}"
            )
            assert children[0]["frame"]["id"] == frame_id, children[0]

            # Typing must reach the field the focus is really on, even when that is inside the
            # child frame rather than the document the session is attached to.
            await command(
                "Runtime.evaluate",
                {
                    "expression": (
                        "(function () {"
                        "  const doc = document.querySelector('iframe[name=pmd3kid]').contentDocument;"
                        "  const input = doc.createElement('input');"
                        "  input.id = 'inner';"
                        "  doc.body.appendChild(input);"
                        "  input.focus();"
                        "  return 'ok';"
                        "})()"
                    ),
                    "returnByValue": True,
                },
            )
            await command("Input.insertText", {"text": "typed"})
            typed = await command(
                "Runtime.evaluate",
                {
                    "expression": (
                        "document.querySelector('iframe[name=pmd3kid]').contentDocument.getElementById('inner').value"
                    ),
                    "returnByValue": True,
                },
            )
            assert typed["result"]["result"]["value"] == "typed", (
                f"typing must follow the focus into the child frame: {typed}"
            )
        finally:
            await client.close()


async def testp_cdp_server_correlates_frames_by_identity_not_document_order(lockdown: LockdownClient) -> None:
    """
    An <iframe> element must resolve to the frame it actually hosts, whichever order the frames
    sit in. iOS 26 orders a document's entries in the frame tree by when each frame was created,
    not by where its element sits in the document; pairing the nth <iframe> with the nth tree
    child then mis-mapped every frame whose DOM position differed from its creation order, so a
    client's frameLocator().fill()/click() drove a different cross-origin frame than the one it
    addressed. The name a frame was given, or the URL it loaded, identifies it regardless of order.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                id_ = next(message_ids)
                await client.send({"id": id_, "method": method, "params": params})
                while True:
                    message = await asyncio.wait_for(client.receive(), TIMEOUT)
                    if message.get("id") == id_:
                        return message

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})
            # Create four named child frames whose document order (d, c, a, b) is deliberately not
            # the order they were created in (a, b, c, d) - the case that mis-correlated.
            await command(
                "Runtime.evaluate",
                {
                    "expression": (
                        "(() => {"
                        "  const make = (n) => { const f = document.createElement('iframe');"
                        "    f.name = n; f.src = 'https://example.com/?' + n; return f; };"
                        "  const a = make('a'), b = make('b');"
                        "  document.body.append(a, b);"
                        "  document.body.insertBefore(make('c'), a);"
                        "  document.body.insertBefore(make('d'), document.body.firstChild);"
                        "  return 'ok';"
                        "})()"
                    ),
                    "returnByValue": True,
                },
            )

            async def child_frame_count() -> int:
                tree = await command("Page.getFrameTree", {})
                return len(tree["result"]["frameTree"].get("childFrames") or [])

            for _ in range(TIMEOUT):
                if await child_frame_count() == 4:
                    break
                await asyncio.sleep(0.5)
            assert await child_frame_count() == 4, "all four child frames must be reported"

            document_order = await command(
                "Runtime.evaluate",
                {"expression": "[...document.querySelectorAll('iframe')].map(f => f.name)", "returnByValue": True},
            )
            names = document_order["result"]["result"]["value"]
            assert names == ["d", "c", "a", "b"], names

            for index, name in enumerate(names):
                element = await command(
                    "Runtime.evaluate", {"expression": f"document.querySelectorAll('iframe')[{index}]"}
                )
                described = await command("DOM.describeNode", {"objectId": element["result"]["result"]["objectId"]})
                frame_id = described["result"]["node"].get("frameId")
                assert frame_id, f"the iframe element must resolve to a frame: {described}"
                # The frame it resolves to must be the one whose document is this element's own
                # src, proven by reading document.URL inside that frame's own world.
                world = await command("Page.createIsolatedWorld", {"frameId": frame_id, "worldName": "probe"})
                url = await command(
                    "Runtime.evaluate",
                    {
                        "expression": "document.URL",
                        "contextId": world["result"]["executionContextId"],
                        "returnByValue": True,
                    },
                )
                assert url["result"]["result"]["value"] == f"https://example.com/?{name}", (
                    f"iframe named {name} must resolve to its own frame, not another's: {url}"
                )
        finally:
            await client.close()


async def testp_cdp_server_answers_basic_auth_through_the_fetch_domain(lockdown: LockdownClient) -> None:
    """
    A client can answer an HTTP Basic auth challenge with no on-device dialog, through Chrome's
    Fetch domain translated onto WebKit's request interception: arm it with Fetch.enable, receive
    each request as Fetch.requestPaused, and inject an Authorization header on Fetch.continueRequest.
    WebKit surfaces no auth event of its own (the dialog owns the challenge), so answering it means
    supplying the credentials proactively on the request - which is what this proves end to end.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        credentials = "Basic " + base64.b64encode(b"user:pass").decode()
        try:
            # Drive the reads from one place: replies land in a dict, and each paused request is
            # continued (with the Authorization header for the protected URL) as it arrives.
            replies: dict[int, dict[str, Any]] = {}
            paused_urls: list[str] = []

            async def send(method: str, params: dict[str, Any]) -> int:
                id_ = next(message_ids)
                await client.send({"id": id_, "method": method, "params": params})
                return id_

            async def pump(seconds: float) -> None:
                deadline = asyncio.get_event_loop().time() + seconds
                while asyncio.get_event_loop().time() < deadline:
                    try:
                        message = await asyncio.wait_for(client.receive(), 0.5)
                    except (asyncio.TimeoutError, TimeoutError):
                        continue
                    if message.get("method") == "Fetch.requestPaused":
                        request = message["params"]
                        url = request["request"]["url"]
                        paused_urls.append(url)
                        if "basic-auth" in url:
                            headers = [
                                {"name": name, "value": value}
                                for name, value in (request["request"].get("headers") or {}).items()
                            ]
                            headers.append({"name": "Authorization", "value": credentials})
                            await send("Fetch.continueRequest", {"requestId": request["requestId"], "headers": headers})
                        else:
                            await send("Fetch.continueRequest", {"requestId": request["requestId"]})
                    elif "id" in message:
                        replies[message["id"]] = message

            await send("Runtime.enable", {})
            await send("Page.enable", {})
            await send("Network.enable", {})
            await send("Page.navigate", {"url": "https://example.com/"})
            await pump(4)
            await send("Fetch.enable", {"patterns": [{"urlPattern": "*"}], "handleAuthRequests": True})
            await pump(1)
            await send(
                "Runtime.evaluate",
                {
                    "expression": (
                        "window.__auth = null;"
                        " fetch('https://httpbin.org/basic-auth/user/pass', {mode: 'cors'})"
                        "  .then(r => r.json()).then(j => window.__auth = j)"
                        "  .catch(e => window.__auth = {error: '' + e});"
                    ),
                    "returnByValue": True,
                },
            )
            result: Any = None
            for _ in range(TIMEOUT):
                await pump(1)
                probe = await send("Runtime.evaluate", {"expression": "window.__auth", "returnByValue": True})
                await pump(0.8)
                value = replies.get(probe, {}).get("result", {}).get("result", {}).get("value")
                if value:
                    result = value
                    break
            assert any("basic-auth" in url for url in paused_urls), (
                f"the protected request must surface as Fetch.requestPaused: {paused_urls}"
            )
            assert result == {"authenticated": True, "user": "user"}, (
                f"the injected Authorization header must answer the Basic auth challenge: {result}"
            )
        finally:
            await client.close()


async def testp_cdp_browser_endpoint_gives_each_attachment_its_own_session(lockdown: LockdownClient) -> None:
    """
    A client may attach to one page more than once - Playwright drives a page through the session
    it was auto-attached with and opens another for raw protocol access. Handing the second
    attachment the first one's session id made each receive the other's answers, because a client
    numbers its request ids per session and both start at one. That trips an assertion inside the
    client and takes the whole connection down, not just the extra session.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        version = await http_get_json(port, "/json/version/")
        browser_id = urlsplit(version["webSocketDebuggerUrl"]).path.rsplit("/", 1)[1]
        page_id = targets[0]["id"]
        client = CdpBrowserWebsocketClient(port, browser_id)
        await asyncio.wait_for(client.connect(), TIMEOUT)
        try:
            await client.send({
                "id": 1,
                "method": "Target.setAutoAttach",
                "params": {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True},
            })

            async def wait_for_page_attached() -> dict[str, Any]:
                while True:
                    message = await client.receive()
                    if (
                        message.get("method") == "Target.attachedToTarget"
                        and message["params"]["targetInfo"]["targetId"] == page_id
                    ):
                        return message

            attached = await asyncio.wait_for(wait_for_page_attached(), TIMEOUT)
            first = attached["params"]["sessionId"]

            second_reply = await client.command(2, "Target.attachToTarget", {"targetId": page_id, "flatten": True})
            second = second_reply["result"]["sessionId"]
            assert second != first, f"a second attachment must get a session of its own: {second}"

            # The crux: both sessions use the same request id. Each answer has to come back on the
            # session that asked, carrying that session's own result.
            await client.send({
                "id": 77,
                "sessionId": first,
                "method": "Runtime.evaluate",
                "params": {"expression": "'first-session'", "returnByValue": True},
            })
            await client.send({
                "id": 77,
                "sessionId": second,
                "method": "Runtime.evaluate",
                "params": {"expression": "'second-session'", "returnByValue": True},
            })

            async def collect_answers() -> dict[str, Any]:
                answers: dict[str, Any] = {}
                while len(answers) < 2:
                    message = await client.receive()
                    if message.get("id") == 77 and "sessionId" in message:
                        answers[message["sessionId"]] = message
                return answers

            answers = await asyncio.wait_for(collect_answers(), TIMEOUT)
            assert answers[first]["result"]["result"]["value"] == "first-session", answers[first]
            assert answers[second]["result"]["result"]["value"] == "second-session", answers[second]

            # Detaching the extra session must leave the page usable through the original one.
            await client.command(3, "Target.detachFromTarget", {"sessionId": second})
            still_working = await client.session_command(
                first, 4, "Runtime.evaluate", {"expression": "40 + 2", "returnByValue": True}
            )
            assert still_working["result"]["result"]["value"] == 42, still_working
        finally:
            await client.close()


async def testp_cdp_server_resolves_a_node_back_to_a_handle(lockdown: LockdownClient) -> None:
    """
    A client moves an element between execution contexts by describing it to get a backendNodeId
    and resolving that id back to an object - which is what every locator-driven interaction with
    something inside a child frame goes through. WebKit has no node identity that outlives a
    description, so DOM.describeNode reported no usable id and the resolve that followed found
    nothing: the action retried until it timed out, with nothing explaining why.

    The resolve must also answer with a handle of its own. A client releases the handle it
    described from, so answering with that same handle returns a reference it has already dropped.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                return await client.command(next(message_ids), method, params)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})

            element = await command("Runtime.evaluate", {"expression": "document.body"})
            object_id = element["result"]["result"]["objectId"]
            described = await command("DOM.describeNode", {"objectId": object_id})
            backend_node_id = described["result"]["node"].get("backendNodeId")
            assert isinstance(backend_node_id, int) and backend_node_id, (
                f"a described node must carry an id the client can name it by again: {described}"
            )

            resolved = await command("DOM.resolveNode", {"backendNodeId": backend_node_id})
            assert "result" in resolved, f"a described node must resolve back: {resolved.get('error')}"
            resolved_object_id = resolved["result"]["object"]["objectId"]
            assert resolved_object_id != object_id, (
                "resolving must answer with a handle of its own, not the one already described from"
            )

            # Releasing the original handle must leave the resolved one usable - that is the whole
            # point of it being a separate handle.
            await command("Runtime.releaseObject", {"objectId": object_id})
            still_usable = await command(
                "Runtime.callFunctionOn",
                {
                    "objectId": resolved_object_id,
                    "functionDeclaration": "function() { return this.tagName; }",
                    "returnByValue": True,
                },
            )
            assert still_usable["result"]["result"]["value"] == "BODY", (
                f"the resolved handle must still address the node: {still_usable}"
            )
        finally:
            await client.close()


async def testp_cdp_server_carries_a_user_gesture_through(lockdown: LockdownClient) -> None:
    """
    A client marks the calls it makes on the user's behalf as a user gesture. Chrome names that
    `userGesture` and WebKit `emulateUserGesture`, and an unrecognized parameter is ignored - so
    every such call ran with no gesture behind it.

    That is not cosmetic. Anything the platform gates behind a gesture silently did nothing,
    including focusing an element inside a cross-origin frame - which is what a client's fill()
    does before typing, so it typed nowhere and left the field empty while reporting success.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                return await client.command(next(message_ids), method, params)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})

            # execCommand('copy') is refused without a user gesture and allowed with one, so it
            # reports whether the gesture actually reached the page.
            gesture_probe = (
                "(function () {"
                "  const field = document.createElement('textarea');"
                "  field.value = 'x';"
                "  document.body.appendChild(field);"
                "  field.select();"
                "  const allowed = document.execCommand('copy');"
                "  field.remove();"
                "  return allowed;"
                "})()"
            )

            async def probe(**extra: Any) -> Any:
                response = await command(
                    "Runtime.evaluate", {"expression": gesture_probe, "returnByValue": True, **extra}
                )
                return response.get("result", {}).get("result", {}).get("value")

            assert await probe() is False, "a call with no gesture must not be treated as one"
            assert await probe(userGesture=True) is True, "a call marked as a user gesture must reach the page as one"
            # Runtime.callFunctionOn carries the same flag, and is what a client actually uses to
            # run its own helpers against an element.
            window = await command("Runtime.evaluate", {"expression": "window"})
            with_gesture = await command(
                "Runtime.callFunctionOn",
                {
                    "objectId": window["result"]["result"]["objectId"],
                    "functionDeclaration": f"function() {{ return {gesture_probe}; }}",
                    "returnByValue": True,
                    "userGesture": True,
                },
            )
            assert with_gesture["result"]["result"]["value"] is True, (
                f"Runtime.callFunctionOn must carry the gesture too: {with_gesture}"
            )
        finally:
            await client.close()


async def testp_cdp_server_frees_a_withheld_evaluate_reply(lockdown: LockdownClient) -> None:
    """
    iOS 26 WebKit occasionally holds a Runtime.evaluate reply until the next message reaches the
    page, which hung a client's console evaluate - and stalled stepping - until the user's next
    action. The bridge nudges the page while such a reply is outstanding, so an evaluate returns on
    its own with nothing sent after it. A large expression source most reliably triggers the hold.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        try:
            await client.command(1, "Runtime.enable", {})
            await client.command(2, "Page.navigate", {"url": "https://example.com/"})
            await asyncio.sleep(3)
            big = "(() => { let s = 0; " + "s = s + 1; " * 10000 + "return s; })()"
            # Nothing follows the evaluate; before the fix it hung until the next command. Bound the
            # wait well under the 30s a genuine hang would take, but above the bridge's nudge cadence.
            reply = await asyncio.wait_for(
                client.command(3, "Runtime.evaluate", {"expression": big, "returnByValue": True}),
                REPLY_WAKE_INTERVAL * 8,
            )
            assert reply["result"]["result"]["value"] == 10000, reply
        finally:
            await client.close()


async def testp_cdp_server_debugs_a_megabyte_script_responsively(lockdown: LockdownClient) -> None:
    """
    The whole debugging surface on a ~1 MB script, each step bounded so a regression shows as a
    failure rather than a slow test: the script defines, a `debugger;` hits, the scope's properties
    all come back (a large scope's list used to be silently emptied by an internal five-second
    wait that also stalled event delivery), step-over/into/out land where they should with
    correct values in scope, a breakpoint set by URL is hit, the script completes with the right
    result, an armed manual pause stops the next code that runs, and the bridge does not burn CPU
    while the debugger sits idle at a breakpoint. WebKit withholds a step's reply and paused
    event until the next message about half the time on a script this size; the watchdog frees
    them, which is what keeps every bound here tight.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        paused_events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        async def reader() -> None:
            while True:
                message = await client.receive()
                if "id" in message and message["id"] in pending and not pending[message["id"]].done():
                    pending[message["id"]].set_result(message)
                elif message.get("method") == "Debugger.paused":
                    paused_events.put_nowait(message["params"])

        reader_task = asyncio.create_task(reader())

        async def call(method: str, params: dict[str, Any], budget: float = TIMEOUT) -> dict[str, Any]:
            id_ = next(message_ids)
            future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
            pending[id_] = future
            await client.send({"id": id_, "method": method, "params": params})
            return await asyncio.wait_for(future, budget)

        async def paused(budget: float = TIMEOUT) -> dict[str, Any]:
            return await asyncio.wait_for(paused_events.get(), budget)

        def value(reply: dict[str, Any]) -> Any:
            return reply.get("result", {}).get("result", {}).get("value")

        def top(frame_event: dict[str, Any]) -> dict[str, Any]:
            return frame_event["callFrames"][0]

        try:
            for method in ("Runtime.enable", "Page.enable", "Debugger.enable"):
                await call(method, {})
            await call("Page.navigate", {"url": "https://example.com/"})
            await asyncio.sleep(3)
            while not paused_events.empty():
                paused_events.get_nowait()

            # ~1 MB: a nested function to step into, a `debugger;` to hit, and 45k hoisted vars.
            var_count = 45000
            filler = "\n".join(f"  var v{i} = {i} + 1;" for i in range(var_count))
            source = (
                "function inner(x){ let y = x*2; return y+1; }\n"
                "function bigwork(){\n  let a = 1;\n  let b = 2;\n  debugger;\n  let c = a + b;\n"
                "  let d = inner(c);\n  let e = d + 1;\n" + filler + "\n  return e;\n}\n//# sourceURL=bigwork.js"
            )
            return_line = 8 + var_count
            assert len(source) > 1_000_000, len(source)
            defined = await call("Runtime.evaluate", {"expression": source, "returnByValue": True}, 60)
            assert "error" not in defined, defined

            await call("Runtime.evaluate", {"expression": "setTimeout(() => { window.__r = bigwork(); }, 200); 1"})
            hit = await paused()
            assert top(hit).get("functionName") == "bigwork" and top(hit)["location"]["lineNumber"] == 4, top(hit)

            # Idle at the breakpoint: the bridge must not spin a core waiting for nothing.
            cpu_before, wall_before = time.process_time(), time.perf_counter()
            await asyncio.sleep(3)
            cpu_share = (time.process_time() - cpu_before) / (time.perf_counter() - wall_before)
            assert cpu_share < 0.15, f"bridge burned {cpu_share:.0%} of a core idling at a breakpoint"

            assert (
                value(
                    await call(
                        "Debugger.evaluateOnCallFrame",
                        {"callFrameId": top(hit)["callFrameId"], "expression": "a+b", "returnByValue": True},
                    )
                )
                == 3
            )

            # Every non-global scope's properties, as the Sources panel fetches them on each pause.
            started = time.perf_counter()
            total = 0
            for scope in top(hit)["scopeChain"]:
                object_id = scope["object"].get("objectId")
                if scope.get("type") == "global" or not object_id:
                    continue
                reply = await call("Runtime.getProperties", {"objectId": object_id, "ownProperties": True}, 60)
                total += len(reply.get("result", {}).get("result", []))
            assert total >= var_count, f"scope properties truncated: {total} < {var_count}"
            assert time.perf_counter() - started < 10, "fetching the scope took too long"

            stepped: dict[str, Any] = {}
            for _ in range(2):  # to the inner() call line
                started = time.perf_counter()
                await call("Debugger.stepOver", {})
                stepped = await paused()
                assert time.perf_counter() - started < 2, "step-over stalled"
            assert top(stepped)["location"]["lineNumber"] == 6, top(stepped)

            await call("Debugger.stepInto", {})
            inside = await paused()
            assert top(inside).get("functionName") == "inner" and len(inside["callFrames"]) >= 3, top(inside)
            assert (
                value(
                    await call(
                        "Debugger.evaluateOnCallFrame",
                        {"callFrameId": top(inside)["callFrameId"], "expression": "x", "returnByValue": True},
                    )
                )
                == 3
            )

            await call("Debugger.stepOut", {})
            back = await paused()
            assert top(back).get("functionName") == "bigwork", top(back)

            for _ in range(3):  # through the big body
                started = time.perf_counter()
                await call("Debugger.stepOver", {})
                await paused()
                assert time.perf_counter() - started < 2, "step-over in the large body stalled"

            # A breakpoint by URL on the return line must be hit on resume, with the value in scope.
            set_reply = await call("Debugger.setBreakpointByUrl", {"lineNumber": return_line, "url": "bigwork.js"})
            assert "error" not in set_reply, set_reply
            await call("Debugger.resume", {})
            at_return = await paused()
            assert top(at_return)["location"]["lineNumber"] == return_line, top(at_return)
            assert (
                value(
                    await call(
                        "Debugger.evaluateOnCallFrame",
                        {"callFrameId": top(at_return)["callFrameId"], "expression": "e", "returnByValue": True},
                    )
                )
                == 8
            )
            await call("Debugger.resume", {})
            await asyncio.sleep(1)
            assert value(await call("Runtime.evaluate", {"expression": "window.__r", "returnByValue": True})) == 8

            # Manual pause: schedule code first, then arm the pause; it stops on that code's first
            # statement. (Arming before an evaluate pauses inside that evaluate, as in Chrome.)
            while not paused_events.empty():
                paused_events.get_nowait()
            await call("Runtime.evaluate", {"expression": "setTimeout(() => { let q = 1; q++; }, 800); 1"})
            await call("Debugger.pause", {})
            manual = await paused(10)
            assert manual["callFrames"], manual
            await call("Debugger.resume", {})
        finally:
            reader_task.cancel()
            await client.close()


async def testp_cdp_server_keeps_an_armed_pause_for_user_code(lockdown: LockdownClient) -> None:
    """
    With the Pause button armed, a late reply must not cost the user their pause. The bridge nudges
    the page to free a withheld reply; an evaluation used as that nudge was itself a statement, so
    the armed pause landed inside the nudge's own "0" and the user's code then ran unpaused. The
    nudge runs no JavaScript now, so the pause lands on the user's code and holds it.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        paused_events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        async def reader() -> None:
            while True:
                message = await client.receive()
                if "id" in message and message["id"] in pending and not pending[message["id"]].done():
                    pending[message["id"]].set_result(message)
                elif message.get("method") == "Debugger.paused":
                    paused_events.put_nowait(message["params"])

        reader_task = asyncio.create_task(reader())

        async def send(method: str, params: dict[str, Any]) -> "asyncio.Future[dict[str, Any]]":
            """Send without waiting for the reply; the returned future resolves with it."""
            id_ = next(message_ids)
            future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
            pending[id_] = future
            await client.send({"id": id_, "method": method, "params": params})
            return future

        async def call(method: str, params: dict[str, Any], budget: float = TIMEOUT) -> dict[str, Any]:
            return await asyncio.wait_for(await send(method, params), budget)

        def value(reply: dict[str, Any]) -> Any:
            return reply.get("result", {}).get("result", {}).get("value")

        try:
            for method in ("Runtime.enable", "Page.enable", "Debugger.enable"):
                await call(method, {})
            # A fresh document: an armed pause takes the very next statement to run, so a timer
            # left behind by an earlier test on this page would take it instead of the user's code.
            await call("Page.navigate", {"url": "https://example.com/"})
            await asyncio.sleep(3)
            big = await call(
                "Runtime.evaluate",
                {
                    "expression": "window.__big = Object.fromEntries(Array.from({length: 45000}, (_, i) => ['k' + i, i])); window.__big"
                },
            )
            await call(
                "Runtime.evaluate",
                {
                    "expression": (
                        "window.__ran = undefined;"
                        " function userCode(){\n  let z = 1;\n  z = z + 1;\n  window.__ran = z;\n  return z;\n}\n"
                        "//# sourceURL=user.js"
                    ),
                    "returnByValue": True,
                },
            )
            while not paused_events.empty():
                paused_events.get_nowait()
            # Schedule the user's code first, as the timer's callback itself: an evaluate sent after
            # arming would be the next statement and take the pause, and so would a wrapper arrow
            # around the call. Then arm, then cause a reply WebKit needs about a second for, so the
            # watchdog nudges while the pause is armed.
            await call("Runtime.evaluate", {"expression": "setTimeout(userCode, 1500); 1", "returnByValue": True})
            await call("Debugger.pause", {})
            late = await send(
                "Runtime.getProperties", {"objectId": big["result"]["result"]["objectId"], "ownProperties": True}
            )
            landed = await asyncio.wait_for(paused_events.get(), 10)
            frame = landed["callFrames"][0]
            assert frame.get("url") == "user.js", (
                f"the armed pause must land on the user's code, not the nudge: {frame}"
            )
            assert (
                value(await call("Runtime.evaluate", {"expression": "window.__ran", "returnByValue": True})) is None
            ), "the user's code must be held at the pause, not have run"
            await call("Debugger.resume", {})
            await asyncio.sleep(1)
            assert value(await call("Runtime.evaluate", {"expression": "window.__ran", "returnByValue": True})) == 2
            await asyncio.wait_for(late, TIMEOUT)
        finally:
            reader_task.cancel()
            await client.close()


async def testp_cdp_server_steps_through_a_large_file_end_to_end(lockdown: LockdownClient) -> None:
    """
    Step over every statement of a function in a realistic large file (thousands of helpers, async
    boundaries), doing what an IDE does at each pause - fetch the scopes and evaluate a watch - and
    each step must land promptly. This is the workflow that hung on a 22k-line file: WebKit holds
    a step's reply and paused event until the next message about half the time, and the bridge's
    watchdog is what keeps every step under the bound.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        paused_events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        async def reader() -> None:
            while True:
                message = await client.receive()
                if "id" in message and message["id"] in pending and not pending[message["id"]].done():
                    pending[message["id"]].set_result(message)
                elif message.get("method") == "Debugger.paused":
                    paused_events.put_nowait(message["params"])

        reader_task = asyncio.create_task(reader())

        async def call(method: str, params: dict[str, Any], budget: float = TIMEOUT) -> dict[str, Any]:
            id_ = next(message_ids)
            future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
            pending[id_] = future
            await client.send({"id": id_, "method": method, "params": params})
            return await asyncio.wait_for(future, budget)

        try:
            for method in ("Runtime.enable", "Page.enable", "Debugger.enable"):
                await call(method, {})
            await call("Page.navigate", {"url": "https://example.com/"})
            await asyncio.sleep(3)
            while not paused_events.empty():
                paused_events.get_nowait()

            helpers = 1200
            calls = 120
            lines: list[str] = []
            for i in range(helpers):
                lines += [
                    f"function helper{i}(x) {{",
                    "  const items = [];",
                    "  for (let k = 0; k < 3; k++) {",
                    f"    items.push({{ id: k, v: x + k + {i} }});",
                    "  }",
                    "  const total = items.reduce((s, it) => s + it.v, 0);",
                    "  if (total % 2 === 0) { return total; }",
                    "  return total + 1;",
                    "}",
                    "",
                ]
            lines += [
                "function wait(ms) { return new Promise(r => setTimeout(r, ms)); }",
                "",
                "async function main() {",
                "  let acc = 0;",
                "  debugger;",
            ]
            for i in range(calls):
                if i % 25 == 24:
                    lines.append("  await wait(10);")
                lines.append(f"  acc += helper{(i * 7) % helpers}(acc & 0xff);")
            lines += ["  window.__done = acc;", "  return acc;", "}", "//# sourceURL=large.js"]
            source = "\n".join(lines)
            assert source.count("\n") > 12000
            defined = await call("Runtime.evaluate", {"expression": source, "returnByValue": True}, 60)
            assert "error" not in defined, defined
            await call("Runtime.evaluate", {"expression": "setTimeout(() => { main(); }, 200); 1"})
            frame = (await asyncio.wait_for(paused_events.get(), TIMEOUT))["callFrames"][0]
            assert frame.get("functionName") == "main", frame

            steps = 0
            while True:
                started = time.perf_counter()
                await call("Debugger.stepOver", {})
                try:
                    paused = await asyncio.wait_for(paused_events.get(), 5)
                except (asyncio.TimeoutError, TimeoutError):
                    if steps >= calls:  # main returned; nothing left to pause in
                        break
                    raise AssertionError(f"step-over #{steps} did not land within 5s") from None
                frame = paused["callFrames"][0]
                if frame.get("functionName") != "main":
                    break
                assert time.perf_counter() - started < 2, f"step-over #{steps} took too long"
                for scope in frame["scopeChain"]:
                    object_id = scope["object"].get("objectId")
                    if scope.get("type") != "global" and object_id:
                        await call("Runtime.getProperties", {"objectId": object_id, "ownProperties": True}, 20)
                await call(
                    "Debugger.evaluateOnCallFrame",
                    {"callFrameId": frame["callFrameId"], "expression": "acc", "returnByValue": True},
                )
                steps += 1
            assert steps >= calls, f"expected to step over at least {calls} statements, did {steps}"
            await asyncio.sleep(2)
            done = await call("Runtime.evaluate", {"expression": "window.__done", "returnByValue": True})
            assert isinstance(done.get("result", {}).get("result", {}).get("value"), int), done
        finally:
            reader_task.cancel()
            await client.close()


async def testp_cdp_server_survives_debugger_edge_cases(lockdown: LockdownClient) -> None:
    """
    The corners a debugging session hits once it is more than a demo, each bounded: rapid
    step-overs fired without waiting coalesce rather than wedge, step-into descends a recursion
    and step-out climbs back, a breakpoint set deep in a large file is hit with the right value
    in scope, pause-on-exceptions lands in the throwing function, and navigating away while paused
    (a process swap mid-pause) leaves the session alive on the new document.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        paused_events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        async def reader() -> None:
            while True:
                message = await client.receive()
                if "id" in message and message["id"] in pending and not pending[message["id"]].done():
                    pending[message["id"]].set_result(message)
                elif message.get("method") == "Debugger.paused":
                    paused_events.put_nowait(message["params"])

        reader_task = asyncio.create_task(reader())

        async def send(method: str, params: dict[str, Any]) -> "asyncio.Future[dict[str, Any]]":
            id_ = next(message_ids)
            future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
            pending[id_] = future
            await client.send({"id": id_, "method": method, "params": params})
            return future

        async def call(method: str, params: dict[str, Any], budget: float = TIMEOUT) -> dict[str, Any]:
            return await asyncio.wait_for(await send(method, params), budget)

        async def paused(budget: float = 10) -> dict[str, Any]:
            return await asyncio.wait_for(paused_events.get(), budget)

        def top(event: dict[str, Any]) -> dict[str, Any]:
            return event["callFrames"][0]

        def value(reply: dict[str, Any]) -> Any:
            return reply.get("result", {}).get("result", {}).get("value")

        try:
            for method in ("Runtime.enable", "Page.enable", "Debugger.enable"):
                await call(method, {})
            await call("Page.navigate", {"url": "https://example.com/"})
            await asyncio.sleep(3)
            while not paused_events.empty():
                paused_events.get_nowait()

            filler = "\n".join(f"function h{i}(x){{ return x+{i}; }}" for i in range(3000))
            source = (
                filler + "\nfunction rec(n){\n  if (n===0) { return 0; }\n  return 1 + rec(n-1);\n}\n"
                "function deepTarget(v){\n  let w = v * 2;\n  return w;\n}\n"
                "function boom(){ throw new Error('kaboom'); }\n"
                "function main(){\n  let a=1;\n  debugger;\n  let b=a+1;\n  let c=b+1;\n  let d=c+1;\n"
                "  let g=rec(6);\n  let h=deepTarget(g);\n  return h;\n}\n//# sourceURL=edges.js"
            )
            lines = source.split("\n")
            deep_line = next(i for i, line in enumerate(lines) if line.startswith("  let w = v * 2"))
            await call("Runtime.evaluate", {"expression": source, "returnByValue": True})
            await call("Runtime.evaluate", {"expression": "setTimeout(() => { window.__m = main(); }, 150); 1"})
            event = await paused()
            first_line = top(event)["location"]["lineNumber"]

            # Rapid step-overs without waiting: they may coalesce, but must advance and never wedge.
            started = time.perf_counter()
            for _ in range(5):
                await send("Debugger.stepOver", {})
            landed: list[int] = []
            for _ in range(5):
                try:
                    landed.append(top(await paused(4))["location"]["lineNumber"])
                except (asyncio.TimeoutError, TimeoutError):
                    break
            assert landed and landed[-1] > first_line and time.perf_counter() - started < 8, landed

            # Step-into descends the recursion; step-out climbs back to main.
            event = await paused(0.5) if not paused_events.empty() else event
            for _ in range(40):
                line = top(event)["location"]["lineNumber"]
                if "rec(6)" in lines[line] or top(event).get("functionName") != "main":
                    break
                await call("Debugger.stepOver", {})
                event = await paused()
            assert "rec(6)" in lines[top(event)["location"]["lineNumber"]], top(event)
            depths: list[int] = []
            for _ in range(12):
                await call("Debugger.stepInto", {})
                event = await paused()
                depths.append(len(event["callFrames"]))
                if depths[-1] >= 5:
                    break
            assert max(depths) >= 5, f"step-into must descend the recursion: {depths}"
            for _ in range(12):
                await call("Debugger.stepOut", {})
                event = await paused()
                if top(event).get("functionName") == "main":
                    break
            assert top(event).get("functionName") == "main", top(event)

            # A breakpoint deep in the file is hit on resume, with the argument in scope.
            await call("Debugger.setBreakpointByUrl", {"lineNumber": deep_line, "url": "edges.js"})
            await call("Debugger.resume", {})
            event = await paused()
            assert (
                top(event).get("functionName") == "deepTarget" and top(event)["location"]["lineNumber"] == deep_line
            ), top(event)
            assert (
                value(
                    await call(
                        "Debugger.evaluateOnCallFrame",
                        {"callFrameId": top(event)["callFrameId"], "expression": "v", "returnByValue": True},
                    )
                )
                == 6
            )
            await call("Debugger.resume", {})
            await asyncio.sleep(1)
            while not paused_events.empty():
                paused_events.get_nowait()
            assert value(await call("Runtime.evaluate", {"expression": "window.__m", "returnByValue": True})) == 12

            # Pause on exceptions lands in the throwing function.
            await call("Debugger.setPauseOnExceptions", {"state": "all"})
            await call(
                "Runtime.evaluate",
                {
                    "expression": "setTimeout(() => { try { boom(); } catch (e) { window.__caught = e.message; } }, 150); 1"
                },
            )
            event = await paused()
            assert event.get("reason") == "exception" and top(event).get("functionName") == "boom", event.get("reason")
            await call("Debugger.resume", {})
            await call("Debugger.setPauseOnExceptions", {"state": "none"})
            await asyncio.sleep(1)
            while not paused_events.empty():
                paused_events.get_nowait()

            # Navigating while paused swaps the process mid-pause; the session must come out alive.
            await call("Runtime.evaluate", {"expression": "setTimeout(() => { main(); }, 150); 1"})
            await paused()
            await call("Page.navigate", {"url": "https://example.com/?after"})
            await asyncio.sleep(4)
            while not paused_events.empty():
                paused_events.get_nowait()
            assert (
                value(await call("Runtime.evaluate", {"expression": "location.search", "returnByValue": True}, 10))
                == "?after"
            )
        finally:
            reader_task.cancel()
            await client.close()


async def testp_cdp_server_drives_a_javascript_context(lockdown: LockdownClient) -> None:
    """
    A JSContext debuggable (any process that called -[JSContext setInspectable:YES]) implements
    only JavaScriptCore's side of the protocol: no Target domain, so no target is announced on
    attach, messages are exchanged un-multiplexed, and its console output needs Console.enable -
    which Chrome's JavaScript-only frontend never sends. The bridge must cover all of it.
    """
    async with cdp_server(lockdown) as (port, _):
        targets = [target for target in await http_get_json(port, "/json/list") if target["type"] == "node"]
        if not targets:
            pytest.skip("no inspectable JSContext on the device")
        assert targets[0]["devtoolsFrontendUrl"].startswith("/devtools/js_app.html?"), (
            "a JSContext must be handed Chrome's JavaScript-only frontend"
        )
        # A JSContext only answers the inspector while its host thread services its run loop, so
        # some of the listed ones may be dormant; any one that answers proves the path.
        for target in targets:
            if await evaluate_and_log_in_javascript_context(port, target["id"]):
                return
        pytest.skip("no listed JSContext answered the inspector")


async def evaluate_and_log_in_javascript_context(port: int, target_id: str) -> bool:
    """Evaluate an expression that also logs on a JSContext target, asserting both come back.

    :returns: False if the debuggable never answered (a dormant JSContext), True once it did.
    """
    # The debuggable replays its buffered console history on attach, so the log this test asserts
    # on must be distinguishable from whatever ran in the context before.
    marker = f"pmd3-cdp-{uuid.uuid4()}"
    client = CdpWebsocketClient(port, target_id)
    await asyncio.wait_for(client.connect(), TIMEOUT)
    marked_calls: list[dict[str, Any]] = []

    def collect(message: dict[str, Any]) -> None:
        if message.get("method") != "Runtime.consoleAPICalled":
            return
        if message["params"]["args"][0].get("value") == marker:
            marked_calls.append(message)

    async def command(id_: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """client.command, keeping the console events it would otherwise discard."""
        await client.send({"id": id_, "method": method, "params": params})
        while True:
            message = await client.receive()
            collect(message)
            if message.get("id") == id_:
                return message

    async def next_marked_call() -> dict[str, Any]:
        while not marked_calls:
            collect(await client.receive())
        return marked_calls[0]

    try:
        try:
            await asyncio.wait_for(command(1, "Runtime.enable", {}), TIMEOUT)
        except asyncio.TimeoutError:
            return False
        result = await asyncio.wait_for(
            command(2, "Runtime.evaluate", {"expression": f"console.log({marker!r}); 40+2"}), TIMEOUT
        )
        assert result["result"]["result"]["value"] == 42
        # The console event may trail the evaluate response. It is attributed to the execution
        # context synthesized on Runtime.enable; without one the frontend refuses to evaluate
        # anything at all, and WebKit sends no console event before Console.enable.
        call = await asyncio.wait_for(next_marked_call(), TIMEOUT)
        assert call["params"]["executionContextId"] == JS_CONTEXT_EXECUTION_ID
        return True
    finally:
        await client.close()


async def testp_cdp_server_rejects_the_page_domain_on_a_javascript_context(lockdown: LockdownClient) -> None:
    """
    A JSContext debuggable implements no Page domain and its global object has no window, but
    Chrome's frontends still ask for a resource tree and a screencast. Both must come back as
    protocol errors the frontend can absorb. Raising out of their translation instead loses the
    response, and a screencast kept on the target although it never started took the session's
    teardown down with it - leaking the queue-consumer tasks that then drained the next
    session's events.
    """
    async with cdp_server(lockdown) as (port, _):
        targets = await list_targets_of_type(port, "node")
        if not targets:
            pytest.skip("no inspectable JSContext on the device")
        for target in targets:
            if await page_domain_is_rejected_in_javascript_context(port, target["id"]):
                return
        pytest.skip("no listed JSContext answered the inspector")


async def list_targets_of_type(port: int, type_: str) -> list[dict[str, Any]]:
    """Listed targets of one kind. The device reports its debuggables asynchronously after the
    inspector connects, so an immediate listing is empty even when there are some."""
    for _ in range(TIMEOUT):
        targets = [target for target in await http_get_json(port, "/json/list") if target["type"] == type_]
        if targets:
            return targets
        await asyncio.sleep(1)
    return []


async def page_domain_is_rejected_in_javascript_context(port: int, target_id: str) -> bool:
    """Ask a JSContext target for page-only functionality and assert it is refused cleanly.

    :returns: False if the debuggable never answered (a dormant JSContext), True once it did.
    """
    client = CdpWebsocketClient(port, target_id)
    await asyncio.wait_for(client.connect(), TIMEOUT)
    try:
        try:
            await asyncio.wait_for(client.command(1, "Runtime.enable", {}), TIMEOUT)
        except asyncio.TimeoutError:
            return False
        for id_, method, params in (
            (2, "Page.getResourceTree", {}),
            (3, "Page.startScreencast", {"format": "jpeg", "quality": 60, "maxWidth": 480, "maxHeight": 960}),
        ):
            response = await client.command(id_, method, params)
            assert "result" not in response, f"{method} cannot succeed on a JSContext"
            assert "failed to handle" not in response["error"]["message"], (
                f"{method} must be refused, not raise out of its translation: {response['error']}"
            )
        # Refusing must leave the session usable rather than wedge it.
        result = await client.command(4, "Runtime.evaluate", {"expression": "40+2"})
        assert result["result"]["result"]["value"] == 42
    finally:
        await client.close()
    # The teardown of a session that asked for a screencast must complete, or its receive loop
    # keeps consuming the messages of every later session on the same debuggable.
    client = CdpWebsocketClient(port, target_id)
    await asyncio.wait_for(client.connect(), TIMEOUT)
    try:
        result = await client.command(1, "Runtime.evaluate", {"expression": "40+2"})
        assert result["result"]["result"]["value"] == 42
    finally:
        await client.close()
    return True


async def testp_cdp_server_takes_a_held_page_over(lockdown: LockdownClient) -> None:
    """
    A DevTools tab left attached to a page must not brick every later connection to it.

    WebKit serves a single inspector session per debuggable, so sessions are serialized per page.
    A second connection used to wait out the first one - with its websocket already accepted, so
    the frontend rendered an empty window and swallowed everything typed into it, indefinitely.
    The newcomer takes the page over instead, the way Safari's own Web Inspector does.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        page_id = targets[0]["id"]
        held = CdpWebsocketClient(port, page_id)
        await asyncio.wait_for(held.connect(), TIMEOUT)
        try:
            first = await held.command(1, "Runtime.evaluate", {"expression": "40+2"})
            assert first["result"]["result"]["value"] == 42
            # The first session is still attached and is never closed by the test.
            taking_over = CdpWebsocketClient(port, page_id)
            await asyncio.wait_for(taking_over.connect(), TIMEOUT)
            try:
                second = await taking_over.command(1, "Runtime.evaluate", {"expression": "40+2"})
                assert second["result"]["result"]["value"] == 42
            finally:
                await taking_over.close()
        finally:
            await held.close()
        # Both sessions are gone: the page must be left claimable, not pinned by a registration
        # that outlived them (which would make the next connection wait out the whole handover
        # budget before being refused).
        for _ in range(TIMEOUT):
            if page_id not in PAGE_TAKEOVERS and not PAGE_LOCKS[page_id].locked():
                break
            await asyncio.sleep(1)
        assert page_id not in PAGE_TAKEOVERS, "the page stayed registered after both sessions ended"
        assert not PAGE_LOCKS[page_id].locked(), "the page lock was not released"


async def testp_cdp_server_survives_process_swaps(lockdown: LockdownClient) -> None:
    """
    Cross-origin navigation swaps the page's WebContent process: WebKit destroys the inspector
    target and creates a fresh one with all agents disabled. The bridge must keep answering
    requests (synthesizing errors for those the dead target swallowed) and re-establish the
    frontend's domain setup on the new target, or DevTools goes silent after a couple of clicks.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        try:
            id_ = 0
            for method in ("Page.enable", "Runtime.enable", "Network.enable"):
                id_ += 1
                await client.command(id_, method, {})
            # Two distinct origins guarantee at least one process swap wherever Safari starts.
            for url, host in (("https://example.com/", "example.com"), ("https://www.apple.com/", "apple.com")):
                id_ += 1
                # Cleared before navigating, not after: Page.navigate answers once the document
                # it started has committed (that is when WebKit reveals the loaderId it must
                # report), so the new load's events are already delivered by the time it returns.
                client.seen_events.clear()
                await client.command(id_, "Page.navigate", {"url": url})
                reached = False
                for _ in range(TIMEOUT):
                    id_ += 1
                    # Never retried: any response (even an error, for a request the swap
                    # swallowed) is fine, a lost response times the test out.
                    response = await client.command(
                        id_, "Runtime.evaluate", {"expression": "location.href", "returnByValue": True}
                    )
                    if host in response.get("result", {}).get("result", {}).get("value", ""):
                        reached = True
                    # Network events of the fresh document prove the bridge re-enabled the
                    # domains on the swapped-in target; without that DevTools shows nothing.
                    if reached and "Network.requestWillBeSent" in client.seen_events:
                        break
                    await asyncio.sleep(1)
                assert reached, f"never reached {host} over the bridge"
                assert "Network.requestWillBeSent" in client.seen_events, (
                    f"no network events for the {host} load - domains were not re-enabled after the swap"
                )
        finally:
            await client.close()


async def testp_cdp_server_screencast_survives_navigation(lockdown: LockdownClient) -> None:
    """
    The screencast must keep producing frames across navigations. A snapshot request lost to a
    process swap used to burn a frame id that was never sent to DevTools; the ack for it never
    arrived, and the screen stayed frozen for the rest of the session.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        try:
            message_ids = itertools.count(1)

            async def receive_acking() -> dict[str, Any]:
                """Receive one message, acking screencast frames like DevTools does."""
                message = await client.receive()
                if message.get("method") == "Page.screencastFrame":
                    await client.send({
                        "id": next(message_ids),
                        "method": "Page.screencastFrameAck",
                        "params": {"sessionId": message["params"]["sessionId"]},
                    })
                return message

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                id_ = next(message_ids)
                await client.send({"id": id_, "method": method, "params": params})

                async def wait_for_response() -> dict[str, Any]:
                    while True:
                        message = await receive_acking()
                        if message.get("id") == id_:
                            return message

                return await asyncio.wait_for(wait_for_response(), TIMEOUT)

            async def wait_for_frame() -> None:
                async def next_frame() -> None:
                    while True:
                        if (await receive_acking()).get("method") == "Page.screencastFrame":
                            return

                await asyncio.wait_for(next_frame(), TIMEOUT)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.startScreencast", {"format": "jpeg", "quality": 60, "maxWidth": 480, "maxHeight": 960})
            await wait_for_frame()
            # Alternating origins force process swaps; frames must keep arriving through every
            # navigation. Several rounds because the frozen-screen regression this guards (a
            # snapshot lost mid-swap burning an id DevTools can never ack) is timing-dependent.
            for url in ("https://example.com/", "https://www.apple.com/") * 2:
                await command("Page.navigate", {"url": url})
                await wait_for_frame()
        finally:
            await client.close()


async def testp_cdp_server_answers_page_requests_across_a_process_swap(lockdown: LockdownClient) -> None:
    """
    A navigation that commits in a new process destroys the target the bridge is talking to, and
    WebKit never answers what was in flight to it - which is exactly when Chrome's frontend asks
    for the resource tree and starts a screencast. Both used to blow up on the answer that never
    came (a KeyError on the missing result, and "did not report its screen size"), and the
    screencast is the damaging one: the frontend never asks again, so the screen stays black for
    the rest of the session. Both must be re-asked of the target that took over.

    A live screencast runs throughout: its snapshot round-trips pause the receive loop, which is
    what keeps the targetDestroyed event queued long enough for the requests below to be routed
    to a target that is already gone.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                """client.command, acking the screencast frames it would otherwise leave unacked
                (the encoder stops after one unacked frame)."""
                id_ = next(message_ids)
                await client.send({"id": id_, "method": method, "params": params})

                async def wait_for_response() -> dict[str, Any]:
                    while True:
                        message = await client.receive()
                        if message.get("method") == "Page.screencastFrame":
                            await client.send({
                                "id": next(message_ids),
                                "method": "Page.screencastFrameAck",
                                "params": {"sessionId": message["params"]["sessionId"]},
                            })
                        if message.get("id") == id_:
                            return message

                return await asyncio.wait_for(wait_for_response(), TIMEOUT)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            screencast_params = {"format": "jpeg", "quality": 60, "maxWidth": 480, "maxHeight": 960}
            assert "result" in await command("Page.startScreencast", screencast_params)
            # Alternating origins force the swaps. The target is destroyed somewhere in the
            # couple of seconds after the navigate is issued, so keep asking across that window
            # rather than once - a single well-timed request slips through on its own.
            for url in ("https://example.com/", "https://www.apple.com/") * 3:
                await command("Page.navigate", {"url": url})
                for _ in range(6):
                    tree = await command("Page.getResourceTree", {})
                    assert "result" in tree, f"resource tree lost to the swap into {url}: {tree.get('error')}"
                    restarted = await command("Page.startScreencast", screencast_params)
                    assert "result" in restarted, f"screencast lost to the swap into {url}: {restarted.get('error')}"
                    await asyncio.sleep(0.3)
        finally:
            await client.close()


async def testp_cdp_server_keyboard_input_submits_forms(lockdown: LockdownClient) -> None:
    """
    Screencast typing arrives as Input.dispatchKeyEvent; WebKit has no Input domain, so the
    bridge synthesizes the effects in-page. Return must both fire real key events (pages like
    google submit from their own keydown listener on a <textarea>) and fall back to submitting
    the active element's form, or "type a search and hit return" does nothing.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        try:
            message_ids = itertools.count(1)

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                return await client.command(next(message_ids), method, params)

            async def evaluate(expression: str) -> Any:
                response = await command("Runtime.evaluate", {"expression": expression, "returnByValue": True})
                return response.get("result", {}).get("result", {}).get("value")

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})
            for _ in range(TIMEOUT):
                href = await evaluate("location.href")
                if (
                    isinstance(href, str)
                    and href.rstrip("/").endswith("example.com")
                    and (await evaluate("document.readyState") in ("interactive", "complete"))
                ):
                    break
                await asyncio.sleep(1)

            async def type_and_submit(text: str, expected_path: str) -> None:
                for char in text:
                    await command("Input.dispatchKeyEvent", {"type": "char", "text": char, "key": char})
                assert await evaluate("document.activeElement.value") == text
                await command("Input.dispatchKeyEvent", {"type": "char", "text": "\r", "key": "Enter"})
                href = None
                for _ in range(TIMEOUT):
                    href = await evaluate("location.href")
                    if isinstance(href, str) and f"{expected_path}?q={text}" in href:
                        return
                    await asyncio.sleep(1)
                raise AssertionError(f"return did not reach {expected_path} (still on {href!r})")

            # google-style: a <textarea> whose Enter handling lives in the page's own keydown
            # listener - the bridge must dispatch real key events for it to fire at all.
            assert await evaluate(
                "(() => {"
                "    document.body.innerHTML = '<textarea id=\"q\"></textarea>';"
                "    const box = document.getElementById('q');"
                "    box.addEventListener('keydown', (event) => {"
                "        if (event.key !== 'Enter') { return; }"
                "        event.preventDefault();"
                "        location.assign('/handled?q=' + box.value);"
                "    });"
                "    box.focus();"
                "    return document.activeElement === box;"
                "})()"
            ), "could not focus the injected textarea"
            await type_and_submit("hello", "/handled")

            # default-action fallback: no page handler, Enter submits the ancestor form
            assert await evaluate(
                "(() => {"
                '    document.body.innerHTML = \'<form action="/fallback"><input name="q"></form>\';'
                "    document.querySelector('input').focus();"
                "    return document.activeElement === document.querySelector('input');"
                "})()"
            ), "could not focus the injected form input"
            await type_and_submit("world", "/fallback")
        finally:
            await client.close()


def _inspector_with(pages: dict[str, dict[str, Page]], names: dict[str, str]) -> WebinspectorService:
    inspector = WebinspectorService.__new__(WebinspectorService)
    inspector.connection_id = "BRIDGE-CONNECTION"
    inspector.application_pages = pages
    inspector.connected_application = {
        app_id: Application(
            app_id,
            "com.example.app",
            int(app_id.split(":")[1]),
            name,
            AutomationAvailability.NOT_AVAILABLE,
            1,
            False,
            True,
        )
        for app_id, name in names.items()
    }
    return inspector


def test_landing_page_links_each_kind_to_its_own_frontend() -> None:
    """A JSContext gets Chrome's JavaScript-only frontend; a web page gets the full one."""
    inspector = _inspector_with(
        {
            "PID:1": {
                "1": Page.from_page_dictionary({
                    "WIRPageIdentifierKey": 1,
                    "WIRTypeKey": "WIRTypeWeb",
                    "WIRTitleKey": "Example",
                    "WIRURLKey": "https://example.com/",
                })
            },
            "PID:2": {
                "1": Page.from_page_dictionary({
                    "WIRPageIdentifierKey": 1,
                    "WIRTypeKey": "WIRTypeJavaScript",
                    "WIRTitleKey": "JSContext",
                })
            },
        },
        {"PID:1": "MobileSafari", "PID:2": "myapp"},
    )

    html = targets_html(inspector, "127.0.0.1:9222")

    assert '<a href="/devtools/inspector.html?ws=127.0.0.1:9222/devtools/page/PID:1:1">Example</a>' in html
    # Every JSContext of a process is titled "JSContext"; the context number tells them apart, and
    # the process is named by the header the context is listed under.
    assert '<a href="/devtools/js_app.html?ws=127.0.0.1:9222/devtools/page/PID:2:1">JSContext #1</a>' in html


def test_landing_page_groups_targets_by_process() -> None:
    """Each process gets a header with what the device reports about it - icon, name, bundle, pid -
    and its debuggables listed under it, in a group that folds on the header. A process without an
    icon gets no image."""
    inspector = _inspector_with(
        {
            "PID:1": {
                "1": Page.from_page_dictionary({
                    "WIRPageIdentifierKey": 1,
                    "WIRTypeKey": "WIRTypeWeb",
                    "WIRTitleKey": "Example",
                    "WIRURLKey": "https://example.com/",
                })
            },
            "PID:2": {
                str(n): Page.from_page_dictionary({
                    "WIRPageIdentifierKey": n,
                    "WIRTypeKey": "WIRTypeJavaScript",
                    "WIRTitleKey": "JSContext",
                })
                for n in (1, 2)
            },
        },
        {"PID:1": "MobileSafari", "PID:2": "myapp"},
    )
    inspector.connected_application["PID:1"].icon = b"\x89PNG..."

    html = targets_html(inspector, "127.0.0.1:9222")

    sections = html.split('<details class="app" open>')[1:]
    assert len(sections) == 2
    assert (
        '<summary class="app-header"><img class="icon" src="/icon/PID:1" alt=""><span class="name">MobileSafari</span>'
        '<small>com.example.app &middot; pid 1</small><small class="count">1 target</small></summary>'
    ) in sections[0]
    assert sections[0].count("<li") == 1
    assert '<summary class="app-header"><span class="name">myapp</span>' in sections[1]
    assert '<small class="count">2 targets</small>' in sections[1]
    assert sections[1].count("<li") == 2


def _listed_app(pages: dict[str, dict[str, Any]], **applications: Application) -> Any:
    app = _landing_page_app()
    app.state.inspector.connected_application = dict(applications)
    app.state.inspector.application_pages = {
        app_id: {key: Page.from_page_dictionary(listing) for key, listing in listings.items()}
        for app_id, listings in pages.items()
    }
    return app


_WEB_PAGE = {"WIRPageIdentifierKey": 1, "WIRTypeKey": "WIRTypeWeb", "WIRTitleKey": "Example", "WIRURLKey": "https://e/"}
_JS_CONTEXT = {"WIRPageIdentifierKey": 1, "WIRTypeKey": "WIRTypeJavaScript", "WIRTitleKey": "JSContext"}


@pytest.mark.asyncio
async def test_hovering_a_page_highlights_it_on_the_device() -> None:
    """The landing page forwards a hovered page to the device's indicate message, and clears it
    when the pointer leaves. A JSContext has no view to highlight; an unknown target is gone."""
    app = _listed_app(
        {"PID:1": {"1": _WEB_PAGE}, "PID:2": {"1": _JS_CONTEXT}},
        **{
            "PID:1": Application(
                "PID:1", "com.apple.mobilesafari", 1, "Safari", AutomationAvailability.AVAILABLE, 0, False, True
            ),
            "PID:2": Application("PID:2", "com.example.app", 2, "app", AutomationAvailability.UNKNOWN, 0, False, True),
        },
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        on = await client.post("/api/indicate", json={"id": "PID:1:1", "enabled": True})
        off = await client.post("/api/indicate", json={"id": "PID:1:1", "enabled": False})
        jscontext = await client.post("/api/indicate", json={"id": "PID:2:1", "enabled": True})
        gone = await client.post("/api/indicate", json={"id": "PID:3:1", "enabled": True})

    assert on.json() == {"enabled": True}
    assert off.json() == {"enabled": False}
    assert jscontext.json() == {"enabled": False}
    assert gone.json() == {"enabled": False}
    assert app.state.inspector.indicated == [("PID:1", 1, True), ("PID:1", 1, False)]


@pytest.mark.asyncio
async def test_chrome_listing_carries_the_process_icon_as_favicon() -> None:
    """chrome://inspect shows a target's faviconUrl; a process with an icon lends it to its targets."""
    with_icon = Application(
        "PID:1", "com.apple.mobilesafari", 1, "Safari", AutomationAvailability.UNKNOWN, 0, False, True
    )
    with_icon.icon = b"\x89PNG"
    without = Application("PID:2", "com.example.app", 2, "app", AutomationAvailability.UNKNOWN, 0, False, True)
    app = _listed_app(
        {"PID:1": {"1": _WEB_PAGE}, "PID:2": {"1": _JS_CONTEXT}}, **{"PID:1": with_icon, "PID:2": without}
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        targets = {target["id"]: target for target in (await client.get("/json/list")).json()}

    assert targets["PID:1:1"]["faviconUrl"] == "http://t/icon/PID:1"
    assert "faviconUrl" not in targets["PID:2:1"]


def test_landing_page_names_the_host_of_a_proxy_and_flags_automation() -> None:
    """A process running web content for another names the app it runs in; a process that accepts
    Remote Automation sessions is flagged. Neither shows on an ordinary process."""
    inspector = _inspector_with(
        {"PID:1": {"1": Page.from_page_dictionary(_WEB_PAGE)}, "PID:2": {"1": Page.from_page_dictionary(_WEB_PAGE)}},
        {"PID:1": "Safari", "PID:2": "WebContent"},
    )
    inspector.connected_application["PID:1"].availability = AutomationAvailability.AVAILABLE
    inspector.connected_application["PID:2"].proxy = True
    inspector.connected_application["PID:2"].host = "PID:1"

    html = targets_html(inspector, "127.0.0.1:9222")

    safari, webcontent = html.split('<details class="app" open>')[1:]
    assert "<small>com.example.app &middot; pid 1</small>" in safari
    assert 'class="badge auto"' in safari and ">automation</span>" in safari
    assert "<small>com.example.app &middot; pid 2 &middot; in Safari</small>" in webcontent
    assert "badge auto" not in webcontent


@pytest.mark.asyncio
async def test_landing_page_has_a_filter_and_targets_carry_what_it_matches() -> None:
    """The filter box narrows the list client-side; every target carries its searchable text, and
    web pages (not JSContexts) carry the id the hover highlight is sent for."""
    app = _listed_app(
        {"PID:1": {"1": _WEB_PAGE}, "PID:2": {"1": _JS_CONTEXT}},
        **{
            "PID:1": Application(
                "PID:1", "com.apple.mobilesafari", 1, "Safari", AutomationAvailability.UNKNOWN, 0, False, True
            ),
            "PID:2": Application("PID:2", "com.example.app", 2, "app", AutomationAvailability.UNKNOWN, 0, False, True),
        },
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        html = (await client.get("/")).text
        listing = (await client.get("/api/targets")).json()

    assert '<input class="filter" id="filter" type="search"' in html
    assert (
        '<li class="target" data-indicate="PID:1:1" data-search="example https://e/ safari com.apple.mobilesafari 1">'
        in html
    )
    assert (
        '<li class="target" data-search="jscontext #1 jscontext://com.example.app/2/1 app com.example.app 2">' in html
    )
    by_id = {target["id"]: target for target in listing["targets"]}
    assert by_id["PID:1:1"]["search"] == "example https://e/ safari com.apple.mobilesafari 1"
    assert by_id["PID:1:1"]["application"] == {
        "id": "PID:1",
        "name": "Safari",
        "pid": 1,
        "bundle": "com.apple.mobilesafari",
        "icon": "",
        "host": "",
        "automation": False,
    }


@pytest.mark.asyncio
async def test_process_icons_are_served_from_the_listing() -> None:
    """A process's icon is the PNG the device sent; a process without one, or unknown, is a 404."""
    app = _landing_page_app()
    app.state.inspector.connected_application = {
        "PID:1": Application(
            "PID:1", "com.example.app", 1, "app", AutomationAvailability.NOT_AVAILABLE, 0, False, True
        ),
    }
    app.state.inspector.connected_application["PID:1"].icon = b"\x89PNG\r\n\x1a\nicon"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        icon = await client.get("/icon/PID:1")
        missing = await client.get("/icon/PID:2")

    assert icon.status_code == 200
    assert icon.headers["content-type"] == "image/png"
    assert icon.content == b"\x89PNG\r\n\x1a\nicon"
    assert missing.status_code == 404


def test_landing_page_says_who_is_debugging_each_target() -> None:
    """A debuggable already held by a session is flagged, and whose session it is decides what
    opening it will do: a session of this bridge is taken over, another connection has to let go."""
    inspector = _inspector_with(
        {
            "PID:2": {
                "1": Page.from_page_dictionary({
                    "WIRPageIdentifierKey": 1,
                    "WIRTypeKey": "WIRTypeJavaScript",
                    "WIRTitleKey": "JSContext",
                }),
                "2": Page.from_page_dictionary({
                    "WIRPageIdentifierKey": 2,
                    "WIRTypeKey": "WIRTypeJavaScript",
                    "WIRTitleKey": "JSContext",
                    "WIRConnectionIdentifierKey": "BRIDGE-CONNECTION",
                }),
                "3": Page.from_page_dictionary({
                    "WIRPageIdentifierKey": 3,
                    "WIRTypeKey": "WIRTypeJavaScript",
                    "WIRTitleKey": "JSContext",
                    "WIRConnectionIdentifierKey": "SAFARI-CONNECTION",
                }),
            },
        },
        {"PID:2": "myapp"},
    )

    html = targets_html(inspector, "127.0.0.1:9222")

    free, bridge, other = (html.split("</li>")[i] for i in range(3))
    assert 'class="app-header"' in free
    assert "badge" not in free
    assert 'class="badge"' in bridge and ">attached here</span>" in bridge
    assert 'class="badge held"' in other and ">held elsewhere</span>" in other


def test_landing_page_escapes_titles_from_the_device() -> None:
    """Titles and URLs are whatever the inspected page says they are."""
    inspector = _inspector_with(
        {
            "PID:1": {
                "1": Page.from_page_dictionary({
                    "WIRPageIdentifierKey": 1,
                    "WIRTypeKey": "WIRTypeWeb",
                    "WIRTitleKey": "</a><script>alert(1)</script>",
                    "WIRURLKey": "https://example.com/?a=1&b=2",
                })
            }
        },
        {"PID:1": "MobileSafari"},
    )

    html = targets_html(inspector, "127.0.0.1:9222")

    assert "<script>" not in html
    assert "&lt;/a&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "https://example.com/?a=1&amp;b=2" in html


@contextmanager
def _local_asset_server(payload: bytes) -> Generator[str, None, None]:
    """Serve payload from loopback, standing in for the fallback Chrome's bundled frontend."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        # Named to match BaseHTTPRequestHandler's keyword parameter; silences the request log.
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/devtools/inspector.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(TIMEOUT)


def _refused_address() -> str:
    """An address nothing listens on, so routing to it fails immediately instead of hanging."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{probe.getsockname()[1]}"


async def test_frontend_assets_are_fetched_without_a_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """urllib routes loopback through a configured proxy as readily as anything else, and the
    fallback frontend lives on loopback: without a bypass, a proxied network serves a blank
    DevTools window because every asset request goes to the proxy instead of the local Chrome."""
    monkeypatch.setenv("http_proxy", _refused_address())
    monkeypatch.delenv("no_proxy", raising=False)
    # urlopen builds its default opener once and caches the proxies it read; drop it so the
    # environment set above is the one in effect.
    monkeypatch.setattr(urllib.request, "_opener", None, raising=False)

    with _local_asset_server(b"<html>frontend</html>") as url:
        assert urlsplit(url).hostname == "127.0.0.1"
        assert await _fetch(url) == (b"<html>frontend</html>", "text/html")


async def test_a_frontend_that_could_not_be_resolved_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remembering a failed lookup served 404s - a blank DevTools window - for the rest of the
    session, even after the cause (an unreachable network, a Chrome that lost the race to publish
    its port) had passed."""
    app.state.frontend_lock = asyncio.Lock()
    monkeypatch.delattr(app.state, "frontend_base", raising=False)
    # No Chrome to fall back to, so the first attempt cannot resolve a frontend at all.
    monkeypatch.setattr(app.state, "chrome_path", None, raising=False)
    probes: list[str] = []

    async def probe(url: str) -> Optional[tuple[bytes, str]]:
        probes.append(url)
        # The hosted build is unreachable at first, then comes back.
        return (b"<html>", "text/html") if len(probes) > 1 else None

    monkeypatch.setattr("pymobiledevice3.services.web_protocol.cdp_server._fetch", probe)

    assert await _frontend_base() is None
    assert await _frontend_base() == f"https://{DEVTOOLS_FRONTEND_HOST}/serve_rev/@{DEVTOOLS_FRONTEND_REV}"
    assert len(probes) == 2


@contextmanager
def offline_cdp_target(
    monkeypatch: pytest.MonkeyPatch, target_id: str = "page-1"
) -> Generator[tuple[CdpTarget, list[dict[str, Any]]], None, None]:
    """A CdpTarget wired to a stub inspector, for message translation that needs no device.

    Yields the target and the list of messages it sent towards the device.
    """
    sent: list[dict[str, Any]] = []
    inspector = WebinspectorService.__new__(WebinspectorService)
    inspector.wir_events = {}
    inspector.wir_message_results = {}

    async def send_socket_data(session_id: str, app_id: str, page_id: int, data: dict[str, Any]) -> None:
        sent.append(data)

    monkeypatch.setattr(inspector, "send_socket_data", send_socket_data)
    page = Page.from_page_dictionary({
        "WIRPageIdentifierKey": 1,
        "WIRTypeKey": "WIRTypeWeb",
        "WIRTitleKey": "Example",
        "WIRURLKey": "https://example.com/",
    })
    application = Application(
        "PID:1", "com.apple.mobilesafari", 1, "MobileSafari", AutomationAvailability.NOT_AVAILABLE, 1, False, True
    )
    target = CdpTarget(SessionProtocol(inspector, "SESSION", application, page, method_prefix=""), target_id)
    # The frontend had enabled a domain; a target that takes over gets it replayed.
    target._setup_messages["Runtime.enable"] = {}
    try:
        yield target, sent
    finally:
        for task in (target._input_task, target._receiving_task):
            task.cancel()


def _target_created(target_id: str, type_: str, **extra: Any) -> dict[str, Any]:
    return {"method": "Target.targetCreated", "params": {"targetInfo": {"targetId": target_id, "type": type_, **extra}}}


async def test_a_page_target_takes_over_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """The committed page target a process swap creates is what commands must be routed to."""
    with offline_cdp_target(monkeypatch) as (target, sent):
        await target._target_created(_target_created("page-2", "page"))

        assert target.target_id == "page-2"
        assert [json.loads(m["params"]["message"])["method"] for m in sent] == ["Runtime.enable"]
        assert target.output_queue.get_nowait()["method"] == "Target.targetInfoChanged"


async def test_call_function_on_without_object_id_targets_the_context_global(monkeypatch: pytest.MonkeyPatch) -> None:
    """Chrome lets Runtime.callFunctionOn target a bare execution context; WebKit requires an
    object. Puppeteer's page.evaluate relies on the former. The bridge resolves the context's
    global object (evaluate `this`) and calls the function on it."""
    with offline_cdp_target(monkeypatch) as (target, sent):
        target._flat = True  # a JSContext: the one, default context

        async def fake_result(method: str, params: dict[str, Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
            assert method == "Runtime.evaluate" and params["expression"] == "this"
            return {"result": {"result": {"type": "object", "objectId": "GLOBAL"}}}

        monkeypatch.setattr(target, "send_message_with_result", fake_result)
        await target._runtime_call_function_on({
            "id": 1,
            "method": "Runtime.callFunctionOn",
            "params": {
                "functionDeclaration": "function () { return 6 * 7; }",
                "executionContextId": 5,
                "returnByValue": True,
            },
        })
        forwarded = sent[-1]  # the flat path sends the raw message (no Target envelope)
        assert forwarded["method"] == "Runtime.callFunctionOn"
        assert forwarded["params"]["objectId"] == "GLOBAL", "the call targets the resolved global object"
        assert "executionContextId" not in forwarded["params"], "WebKit takes no execution context here"


async def test_user_preference_overrides_are_translated_and_replayed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Chrome's dark-mode emulation - Emulation.setAutoDarkModeOverride and the media features of
    Emulation.setEmulatedMedia - maps onto WebKit's Page.overrideUserPreference (the command that
    replaced Page.setForcedAppearance, which iOS 26 no longer knows). A feature dropped from the
    list is reset, as in Chrome, and the latest override per preference survives a process swap."""
    with offline_cdp_target(monkeypatch) as (target, sent):

        def device_messages() -> list[dict[str, Any]]:
            return [json.loads(m["params"]["message"]) for m in sent]

        await target._emulation_set_auto_dark_mode_override({
            "id": 1,
            "method": "Emulation.setAutoDarkModeOverride",
            "params": {"enabled": True},
        })
        assert device_messages()[-1] == {
            "id": 1,
            "method": "Page.overrideUserPreference",
            "params": {"name": "PrefersColorScheme", "value": "Dark"},
        }

        await target._emulation_set_emulated_media({
            "id": 2,
            "method": "Emulation.setEmulatedMedia",
            "params": {
                "media": "print",
                "features": [
                    {"name": "prefers-reduced-motion", "value": "reduce"},
                    {"name": "prefers-contrast", "value": "less"},
                    {"name": "color-gamut", "value": "p3"},
                ],
            },
        })
        methods = [(m["method"], m["params"]) for m in device_messages()[1:]]
        assert methods == [
            ("Page.overrideUserPreference", {"name": "PrefersReducedMotion", "value": "Reduce"}),
            # No WebKit value for "less": the override is cleared rather than guessed.
            ("Page.overrideUserPreference", {"name": "PrefersContrast"}),
            ("Page.setEmulatedMedia", {"media": "print"}),
        ]
        assert device_messages()[-1]["id"] == 2, "the client's reply must come from setEmulatedMedia"

        # Reduced motion is gone from the list, so it is reset; media is required by WebKit.
        del sent[:]
        await target._emulation_set_emulated_media({"id": 3, "method": "Emulation.setEmulatedMedia", "params": {}})
        assert [(m["method"], m["params"]) for m in device_messages()] == [
            ("Page.overrideUserPreference", {"name": "PrefersReducedMotion"}),
            ("Page.setEmulatedMedia", {"media": ""}),
        ]

        # `enabled` absent means "stop overriding", and replaces the earlier Dark for replay.
        await target._emulation_set_auto_dark_mode_override({
            "id": 4,
            "method": "Emulation.setAutoDarkModeOverride",
            "params": {},
        })
        replayed = {k: v for k, v in target._setup_messages.items() if isinstance(k, tuple)}
        assert replayed == {
            ("Page.overrideUserPreference", "PrefersColorScheme"): {"name": "PrefersColorScheme"},
            ("Page.overrideUserPreference", "PrefersReducedMotion"): {"name": "PrefersReducedMotion"},
            ("Page.overrideUserPreference", "PrefersContrast"): {"name": "PrefersContrast"},
        }
        assert target._setup_messages["Page.setEmulatedMedia"] == {"media": ""}


async def test_stepping_gets_a_synthesized_resumed_between_pauses(monkeypatch: pytest.MonkeyPatch) -> None:
    """WebKit emits no Debugger.resumed when a step resumes then repauses (it sends none at all),
    so a client would see paused-after-paused; V8 always alternates, and WebStorm's step machine
    waits for the resumed and will not step again without it. The bridge injects one before a pause
    the client is not expecting, keeping the paused/resumed alternation."""

    async def a_pause(line: int) -> dict[str, Any]:
        return {
            "method": "Debugger.paused",
            "params": {
                "reason": "other",
                "callFrames": [
                    {
                        "callFrameId": "cf",
                        "functionName": "f",
                        "location": {"scriptId": "9", "lineNumber": line, "columnNumber": 0},
                    }
                ],
            },
        }

    with offline_cdp_target(monkeypatch) as (target, _):
        target._script_id_to_url["9"] = "x.js"

        await target._debugger_paused(await a_pause(1))
        assert target.output_queue.get_nowait()["method"] == "Debugger.paused", "the first pause stands alone"
        assert target.output_queue.empty()

        # A step: WebKit sends only the next pause. The bridge precedes it with a resumed.
        await target._debugger_paused(await a_pause(2))
        assert target.output_queue.get_nowait() == {"method": "Debugger.resumed"}
        assert target.output_queue.get_nowait()["params"]["callFrames"][0]["location"]["lineNumber"] == 2
        assert target.output_queue.empty()

        # A real resumed from the device (an explicit resume-to-run) is forwarded once and clears.
        await target._debugger_resumed({"method": "Debugger.resumed"})
        assert target.output_queue.get_nowait() == {"method": "Debugger.resumed"}
        # A stray resumed while the client is already running is dropped (would break alternation).
        await target._debugger_resumed({"method": "Debugger.resumed"})
        assert target.output_queue.empty()


async def test_a_lost_device_connection_is_handled_gracefully() -> None:
    """When the device restarts or disconnects, the Web Inspector socket dies. Serving the landing
    page (get_open_pages) must not raise per request - it once spewed a traceback on every poll -
    but note the loss, keep the last-known pages, and leave the bridge up to recover."""
    inspector = WebinspectorService.__new__(WebinspectorService)
    inspector._connection_lost = False
    inspector.logger = logging.getLogger("test.webinspector")
    inspector.connection_id = "CONN"
    application = Application(
        "PID:1", "com.example.app", 1, "App", AutomationAvailability.NOT_AVAILABLE, 1, False, True
    )
    page = Page.from_page_dictionary({
        "WIRPageIdentifierKey": 1,
        "WIRTypeKey": "WIRTypeWeb",
        "WIRTitleKey": "Example",
        "WIRURLKey": "https://example.com/",
    })
    inspector.connected_application = {"PID:1": application}
    inspector.application_pages = {"PID:1": {1: page}}

    class DeadService:
        async def send_plist(self, _: Any) -> None:
            raise ConnectionResetError("Connection lost")

    inspector._service = DeadService()  # type: ignore[assignment]  # the `service` property returns this

    disconnected: list[bool] = []
    inspector.on_connection_lost = lambda: disconnected.append(True)

    assert inspector.is_connected
    pages = await inspector.get_open_pages()  # must not raise
    assert inspector.is_connected is False, "the loss is noted"
    assert list(pages) == ["App"] and list(pages["App"]) == [page], "the last-known pages are still served"
    assert disconnected == [True], "with no reconnect wired, the loss fires on_connection_lost (the bridge fails fast)"

    # A further send while lost is a quiet no-op, not another failure or a repeated callback.
    await inspector._send_message("_rpc_forwardGetListing:", {"WIRApplicationIdentifierKey": "PID:1"})
    assert disconnected == [True]


async def test_a_paused_stack_drops_webkit_native_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    """WebKit puts a native entry frame - scriptId "0", lineNumber -1 - at the bottom of a paused
    call stack. Chrome's protocol has no such frame and js-debug/WebStorm build the stack strictly;
    the bad frame desynced their step handling, so stepping stopped advancing after one step. The
    bridge drops it and reshapes the real frames (url filled in, scope types mapped)."""
    with offline_cdp_target(monkeypatch) as (target, _):
        target._script_id_to_url["294"] = "jscontext:///294.js"
        await target._debugger_paused({
            "method": "Debugger.paused",
            "params": {
                "reason": "DebuggerStatement",
                "callFrames": [
                    {
                        "callFrameId": "cf0",
                        "functionName": "global code",
                        "location": {"scriptId": "294", "lineNumber": 2, "columnNumber": 0},
                        "scopeChain": [
                            {
                                "type": "global",
                                "object": {"objectId": "s0"},
                                "location": {"scriptId": "294", "lineNumber": 0},
                            }
                        ],
                    },
                    {
                        "callFrameId": "cf1",
                        "functionName": "",
                        "location": {"scriptId": "0", "lineNumber": -1, "columnNumber": -1},
                        "scopeChain": [],
                    },
                ],
            },
        })
        event = target.output_queue.get_nowait()
        frames = event["params"]["callFrames"]
        assert [f["callFrameId"] for f in frames] == ["cf0"], "the native scriptId-0 frame must be gone"
        assert frames[0]["url"] == "jscontext:///294.js", "the real frame gets its url filled in"
        scope = frames[0]["scopeChain"][0]
        assert scope["type"] == "global" and "startLocation" in scope and "location" not in scope
        assert event["params"]["reason"] == "other", "DebuggerStatement maps to Chrome's 'other'"


async def test_a_paused_stack_drops_the_injected_script_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    """WebKit runs a console evaluation through its InjectedScript, so a pause inside it carries
    that harness beneath the user's frame - `_wrapCall` and an anon frame in a script with no
    source. V8 shows only the user frame; WebStorm built the stack strictly and stopped stepping
    after one step. On a JSContext (flat) session the bridge strips those frames, leaving the
    single user frame node reports. Recognized by the id of a script hidden as internal, or - the
    JSContext case, where every real script is known - a frame in a script never seen parsed."""
    with offline_cdp_target(monkeypatch) as (target, _):
        target._flat = True
        # The console eval's own script, given a synthetic URL when it was parsed.
        await target._debugger_script_parsed({
            "method": "Debugger.scriptParsed",
            "params": {"scriptId": "675", "url": "", "startLine": 0, "endLine": 0, "endColumn": 3},
        })
        # WebKit's InjectedScript, hidden from the client (its source carries the marker).
        await target._debugger_script_parsed({
            "method": "Debugger.scriptParsed",
            "params": {"scriptId": "27", "sourceURL": "__InjectedScript_WebKit.js"},
        })
        assert "27" in target._internal_script_ids
        assert target.output_queue.get_nowait()["method"] == "Debugger.scriptParsed", (
            "only the user script is forwarded"
        )
        assert target.output_queue.empty()

        await target._debugger_paused({
            "method": "Debugger.paused",
            "params": {
                "reason": "DebuggerStatement",
                "callFrames": [
                    {
                        "callFrameId": "cf0",
                        "functionName": "global code",
                        "location": {"scriptId": "675", "lineNumber": 1, "columnNumber": 0},
                    },
                    {
                        "callFrameId": "cf1",
                        "functionName": "",
                        "location": {"scriptId": "0", "lineNumber": -1, "columnNumber": -1},
                    },
                    {
                        "callFrameId": "cf2",
                        "functionName": "",
                        "location": {"scriptId": "27", "lineNumber": 444, "columnNumber": 79},
                    },
                    {
                        "callFrameId": "cf3",
                        "functionName": "_wrapCall",
                        "location": {"scriptId": "27", "lineNumber": 451, "columnNumber": 9},
                    },
                ],
            },
        })
        frames = target.output_queue.get_nowait()["params"]["callFrames"]
        assert [f["callFrameId"] for f in frames] == ["cf0"], "only the user's own frame survives"
        assert frames[0]["url"] == "jscontext:///675.js"


async def test_a_paused_stack_keeps_the_top_frame_even_if_it_looks_native(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pause must never be frameless: if every frame failed the real-source test, keep the top one."""
    with offline_cdp_target(monkeypatch) as (target, _):
        await target._debugger_paused({
            "method": "Debugger.paused",
            "params": {
                "reason": "other",
                "callFrames": [
                    {"callFrameId": "cf0", "functionName": "x", "location": {"scriptId": "0", "lineNumber": -1}}
                ],
            },
        })
        frames = target.output_queue.get_nowait()["params"]["callFrames"]
        assert [f["callFrameId"] for f in frames] == ["cf0"]


async def test_golden_chrome_remote_interface_stepping_flow() -> None:
    """Replay a real chrome-remote-interface debugging session - a raw CDP client that speaks the
    protocol with almost no abstraction - and assert stepping advances with the paused/resumed
    alternation and every emitted event matches Chrome's schema. A different client than WebStorm
    or js-debug over the same page path."""
    emitted = await replay_page_session(load_fixture("chrome_remote_interface_stepping"))
    methods = [m.get("method", "<reply>") for m in emitted]
    paused = [m for m in emitted if m.get("method") == "Debugger.paused"]
    assert [p["params"]["callFrames"][0]["location"]["lineNumber"] for p in paused] == [2, 3, 4], methods
    paused_at = [i for i, method in enumerate(methods) if method == "Debugger.paused"]
    for first, second in zip(paused_at, paused_at[1:]):
        assert "Debugger.resumed" in methods[first + 1 : second], (
            f"each step must read paused -> resumed -> paused: {methods}"
        )
    cdp = load_spec("cdp")
    problems = [problem for message in emitted for problem in validate_editor_event(cdp, message)]
    assert problems == [], f"emitted events violate Chrome's schema: {sorted(set(problems))}"


async def test_golden_safari_page_stepping_flow() -> None:
    """Replay a real Safari-page debugging session - the Target-multiplexed path - through the
    current bridge and assert stepping advances line by line with the paused/resumed alternation
    editors need, and that every event emitted carries Chrome's required parameters. Guards the
    page path (most editor use) the way the JSContext golden guards the flat path, without a device."""
    emitted = await replay_page_session(load_fixture("safari_page_stepping"))
    methods = [m.get("method", "<reply>") for m in emitted]

    paused = [m for m in emitted if m.get("method") == "Debugger.paused"]
    assert [p["params"]["callFrames"][0]["location"]["lineNumber"] for p in paused] == [2, 3, 4], (
        f"the debugger; statement pauses, then two steps advance a line each: {methods}"
    )
    for event in paused:
        for frame in event["params"]["callFrames"]:
            assert frame["location"]["scriptId"] != "0" and frame["location"]["lineNumber"] >= 0

    paused_at = [i for i, method in enumerate(methods) if method == "Debugger.paused"]
    for first, second in zip(paused_at, paused_at[1:]):
        assert "Debugger.resumed" in methods[first + 1 : second], (
            f"each step must read paused -> resumed -> paused: {methods}"
        )

    cdp = load_spec("cdp")
    problems = [problem for message in emitted for problem in validate_editor_event(cdp, message)]
    assert problems == [], f"emitted events violate Chrome's schema: {sorted(set(problems))}"


async def test_golden_webstorm_jscontext_stepping_flow() -> None:
    """Replay a real WebStorm JSContext debugging session (its editor commands and the device's
    responses) through the current bridge and assert the editor-visible behavior the step-over bug
    broke: the paused stack is the single user frame node reports, and a step reads as
    paused -> resumed -> paused (WebKit sends no resumed of its own). A regression in either
    breaks this without a device."""
    emitted = await replay_flat_session(load_fixture("webstorm_jscontext_stepping"))
    methods = [m.get("method", "<reply>") for m in emitted]

    paused = [m for m in emitted if m.get("method") == "Debugger.paused"]
    assert len(paused) == 2, f"the debugger; statement and the step each pause: {methods}"
    for event in paused:
        frames = event["params"]["callFrames"]
        assert len(frames) == 1, f"only the user's own frame survives, not WebKit's harness: {frames}"
        location = frames[0]["location"]
        assert location["scriptId"] != "0" and location["lineNumber"] >= 0
    assert paused[0]["params"]["callFrames"][0]["location"]["lineNumber"] == 1
    assert paused[1]["params"]["callFrames"][0]["location"]["lineNumber"] == 2, "the step advanced a line"

    # The alternation: a resumed between the two pauses (synthesized; WebKit sends none).
    first, second = (
        methods.index("Debugger.paused"),
        methods.index("Debugger.paused", methods.index("Debugger.paused") + 1),
    )
    assert "Debugger.resumed" in methods[first + 1 : second], f"a step must read paused -> resumed -> paused: {methods}"

    assert "Runtime.consoleAPICalled" in methods, "console output reaches the editor"
    assert not any(
        m.get("method") == "Log.entryAdded" and m["params"]["entry"].get("source") == "javascript" for m in emitted
    ), "engine errors are Runtime.exceptionThrown, not Log entries"

    # Every event the bridge emitted must carry the required parameters of Chrome's protocol.
    cdp = load_spec("cdp")
    problems = [problem for message in emitted for problem in validate_editor_event(cdp, message)]
    assert problems == [], f"emitted events violate Chrome's schema: {sorted(set(problems))}"


async def test_javascript_errors_become_runtime_exception_thrown(monkeypatch: pytest.MonkeyPatch) -> None:
    """WebKit reports uncaught exceptions, unhandled rejections and parse errors as error console
    messages of source "javascript"; Chrome reports them as Runtime.exceptionThrown, the only form
    VS Code's debugger renders. Lines and columns are 1-based in WebKit's message, 0-based in Chrome's."""
    with offline_cdp_target(monkeypatch) as (target, _):
        target._script_id_to_url["2308"] = ""
        await target._console_message_added({
            "method": "Console.messageAdded",
            "params": {
                "message": {
                    "source": "javascript",
                    "level": "error",
                    "text": "TypeError: boom",
                    "type": "log",
                    "line": 3,
                    "column": 23,
                    "url": "undefined",
                    "stackTrace": {
                        "callFrames": [
                            {
                                "functionName": "later",
                                "url": "undefined",
                                "scriptId": "2308",
                                "lineNumber": 3,
                                "columnNumber": 23,
                            },
                            {"functionName": "", "url": "", "scriptId": "2308", "lineNumber": 1, "columnNumber": 84},
                        ]
                    },
                }
            },
        })
        event = target.output_queue.get_nowait()
        assert event["method"] == "Runtime.exceptionThrown"
        details = event["params"]["exceptionDetails"]
        assert details["text"] == "Uncaught"
        assert details["exception"] == {
            "type": "object",
            "subtype": "error",
            "className": "TypeError",
            "description": "TypeError: boom",
        }
        assert (details["lineNumber"], details["columnNumber"], details["url"], details["scriptId"]) == (
            2,
            22,
            "",
            "2308",
        )
        assert details["stackTrace"]["callFrames"][0] == {
            "functionName": "later",
            "scriptId": "2308",
            "url": "",
            "lineNumber": 2,
            "columnNumber": 22,
        }
        assert target.output_queue.empty(), "the error must not also be reported as a Log entry"

        await target._console_message_added({
            "method": "Console.messageAdded",
            "params": {
                "message": {
                    "source": "javascript",
                    "level": "error",
                    "text": "Unhandled Promise Rejection: Error: nope",
                    "line": 1,
                    "column": 15,
                    "url": "",
                }
            },
        })
        details = target.output_queue.get_nowait()["params"]["exceptionDetails"]
        assert details["text"] == "Uncaught (in promise)"
        assert details["exception"]["description"] == "Error: nope"
        assert details["exceptionId"] == 2

        # Console output stays console output.
        await target._console_message_added({
            "method": "Console.messageAdded",
            "params": {
                "message": {
                    "source": "console-api",
                    "level": "error",
                    "text": "plain",
                    "type": "log",
                    "parameters": [{"type": "string", "value": "plain"}],
                }
            },
        })
        assert target.output_queue.get_nowait()["method"] == "Runtime.consoleAPICalled"


async def test_bindings_are_installed_per_context_and_calls_come_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """Runtime.addBinding defines a page function whose calls surface as Runtime.bindingCalled;
    it is (re)installed in every main-world context, including ones announced later, and the
    console message that carries a call never reaches the client as console output."""
    with offline_cdp_target(monkeypatch) as (target, sent):

        def device_messages() -> list[dict[str, Any]]:
            return [json.loads(m["params"]["message"]) for m in sent]

        target._frame_execution_ids["page-1"] = 7
        await target._runtime_add_binding({"id": 1, "method": "Runtime.addBinding", "params": {"name": "hook"}})
        assert target.output_queue.get_nowait() == {"id": 1, "result": {}}
        install = device_messages()[-1]
        assert install["method"] == "Runtime.evaluate" and install["params"]["contextId"] == 7
        assert 'globalThis["hook"]' in install["params"]["expression"]
        assert "__pymobiledevice3_binding__" in install["params"]["expression"]

        # A context created later gets the binding too, after its announcement.
        del sent[:]
        await target._runtime_execution_context_created({
            "method": "Runtime.executionContextCreated",
            "params": {"context": {"id": 9, "type": "normal", "frameId": "page-1", "name": ""}},
        })
        assert target.output_queue.get_nowait()["method"] == "Runtime.executionContextCreated"
        assert device_messages()[-1]["params"]["contextId"] == 9

        await target._console_message_added({
            "method": "Console.messageAdded",
            "params": {
                "message": {
                    "source": "console-api",
                    "level": "debug",
                    "type": "log",
                    "text": "__pymobiledevice3_binding__",
                    "parameters": [
                        {"type": "string", "value": "__pymobiledevice3_binding__"},
                        {"type": "string", "value": "hook"},
                        {"type": "string", "value": '{"a":1}'},
                        {"type": "number", "value": 9},
                    ],
                }
            },
        })
        assert target.output_queue.get_nowait() == {
            "method": "Runtime.bindingCalled",
            "params": {"name": "hook", "payload": '{"a":1}', "executionContextId": 9},
        }
        assert target.output_queue.empty()

        del sent[:]
        await target._runtime_remove_binding({"id": 2, "method": "Runtime.removeBinding", "params": {"name": "hook"}})
        assert target.output_queue.get_nowait() == {"id": 2, "result": {}}
        assert all('delete globalThis["hook"]' in m["params"]["expression"] for m in device_messages())
        assert "hook" not in target._bindings


async def test_context_teardown_and_inspect_are_announced(monkeypatch: pytest.MonkeyPatch) -> None:
    """Runtime.executionContextDestroyed precedes executionContextsCleared on a reload and follows
    a frame's detach; the console's inspect() becomes Runtime.inspectRequested."""
    with offline_cdp_target(monkeypatch) as (target, _):
        target._frame_execution_ids["page-1"] = 7
        world = await target._announce_isolated_world("page-1", "utility")
        target.output_queue.get_nowait()
        await target._debugger_global_object_cleared({"method": "Debugger.globalObjectCleared", "params": {}})
        methods = []
        while not target.output_queue.empty():
            methods.append(target.output_queue.get_nowait())
        assert [m["method"] for m in methods] == [
            "Runtime.executionContextDestroyed",
            "Runtime.executionContextDestroyed",
            "Runtime.executionContextsCleared",
            "DOM.documentUpdated",
        ]
        assert methods[0]["params"] == {"executionContextId": world, "executionContextUniqueId": f"page-1.{world}"}
        assert methods[1]["params"] == {"executionContextId": 7, "executionContextUniqueId": "page-1.7"}

        await target._inspector_inspect({
            "method": "Inspector.inspect",
            "params": {"object": {"type": "object", "subtype": "node", "objectId": "x"}, "hints": {}},
        })
        assert target.output_queue.get_nowait() == {
            "method": "Runtime.inspectRequested",
            "params": {
                "object": {"type": "object", "subtype": "node", "objectId": "x"},
                "hints": {},
                "executionContextId": 0,
            },
        }


async def test_node_domains_are_acknowledged_with_empty_results(monkeypatch: pytest.MonkeyPatch) -> None:
    """An editor attaching "as Node" enables Node's own domains; WebKit has none, and Chrome's
    protocol defines empty results for commands that return nothing."""
    with offline_cdp_target(monkeypatch) as (target, sent):
        for id_, (method, params) in enumerate(
            [
                ("NodeWorker.enable", {"waitForDebuggerOnStart": True}),
                ("NodeRuntime.notifyWhenWaitingForDisconnect", {"enabled": True}),
                ("Debugger.setAsyncCallStackDepth", {"maxDepth": 32}),
            ],
            start=1,
        ):
            await target.from_cdp_special_messages_methods[method]({"id": id_, "method": method, "params": params})
            assert target.output_queue.get_nowait() == {"id": id_, "result": {}}, method
        await target.from_cdp_special_messages_methods["NodeTracing.getCategories"]({
            "id": 9,
            "method": "NodeTracing.getCategories",
            "params": {},
        })
        assert target.output_queue.get_nowait() == {"id": 9, "result": {"categories": []}}
        assert sent == [], "nothing Node-specific may reach the device"


async def test_a_frame_target_does_not_take_over_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """WebKit announces site-isolated subframes as "frame" targets. Their backend implements a
    far smaller domain set than a page's - with site isolation off, no domains at all - so a
    session that adopted one answered every request with "'<domain>' domain was not found", and
    never recovered: no didCommitProvisionalTarget or targetDestroyed follows to move it back."""
    with offline_cdp_target(monkeypatch) as (target, sent):
        await target._target_created(_target_created("frame-2", "frame"))

        assert target.target_id == "page-1"
        assert sent == []
        assert target.output_queue.empty()


async def test_a_frame_target_going_away_does_not_reset_the_frontend(monkeypatch: pytest.MonkeyPatch) -> None:
    """A subframe target is not the inspected document; announcing a load and a document update
    for it would clear panels the frontend filled from the page."""
    with offline_cdp_target(monkeypatch) as (target, _):
        await target._target_created(_target_created("frame-2", "frame"))
        await target._target_destroyed({"method": "Target.targetDestroyed", "params": {"targetId": "frame-2"}})

        assert target.output_queue.empty()
        assert "frame-2" not in target._destroyed_targets


def _landing_page_app() -> Any:
    """The bridge app wired to a fake inspector so the landing page can be served without a device."""

    class _Inspector:
        def __init__(self) -> None:
            self.connection_id = "BRIDGE-CONNECTION"
            self.application_pages: dict[str, dict[str, Page]] = {}
            self.connected_application: dict[str, Application] = {}
            self.indicated: list[tuple[str, int, bool]] = []
            self.is_connected = True

        async def get_open_pages(self) -> None:
            pass

        def find_page_id(self, page_id: str) -> tuple[Application, Page]:
            return WebinspectorService.find_page_id(cast(Any, self), page_id)

        async def indicate_web_view(self, application: Application, page: Page, enable: bool) -> None:
            self.indicated.append((application.id_, page.id_, enable))

    class _Holder:
        running = False

    app.state.inspector = _Inspector()
    app.state.holder = _Holder()
    return app


@pytest.mark.asyncio
async def test_landing_page_names_its_version_and_explains_chrome_inspect() -> None:
    """The header says which pymobiledevice3 is serving the page, and a note tells people how to
    reach chrome://inspect - the page cannot link to it, Chrome blocks such navigations."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=_landing_page_app()), base_url="http://t") as client:
        html = (await client.get("/")).text

    version = bridge_version()
    assert version
    assert f"<small>pymobiledevice3 {escape(version)} &middot; inspectable pages" in html
    assert "<summary>Using chrome://inspect instead</summary>" in html
    assert "<code>chrome://inspect/#devices</code>" in html
    # The bridge's own address, for Chrome's discovery list when it is not the default one.
    assert "add <code>t</code> under <b>Configure...</b>" in html


@pytest.mark.asyncio
async def test_landing_page_carries_the_project_favicon_and_logo() -> None:
    """The landing page declares the project logo as its icon and shows it next to the title."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=_landing_page_app()), base_url="http://t") as client:
        html = (await client.get("/")).text

    assert '<link rel="icon" type="image/png" href="/logo.png">' in html
    assert '<img class="logo" src="/logo.png" alt="">' in html


@pytest.mark.asyncio
async def test_logo_is_served_as_png_under_both_names() -> None:
    """/logo.png is the bundled PNG; /favicon.ico answers browsers that ask for the default icon path."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=_landing_page_app()), base_url="http://t") as client:
        logo = await client.get("/logo.png")
        favicon = await client.get("/favicon.ico")

    assert logo.status_code == 200
    assert logo.headers["content-type"] == "image/png"
    assert logo.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"] == "image/png"
    assert favicon.content == logo.content


async def testp_cdp_server_handles_editing_keys(lockdown: LockdownClient) -> None:
    """
    Editing keys act on the focused field the way a keyboard's would - on keyDown, so a held key
    repeats: Backspace used to act on keyUp only, so holding it deleted one character. Cmd/Ctrl-A
    selects all, the arrows and Home/End move the caret (with Shift extending the selection),
    Delete deletes forward, and typing or Backspace replace whatever is selected. The page's own
    keydown listeners run first and can prevent the default, as they would in a browser.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                return await client.command(next(message_ids), method, params)

            async def evaluate(expression: str) -> Any:
                response = await command("Runtime.evaluate", {"expression": expression, "returnByValue": True})
                return response.get("result", {}).get("result", {}).get("value")

            async def key(key_: str, modifiers: int = 0, repeats: int = 0) -> None:
                """Press a key the way DevTools' screencast does: keyDown (and its auto-repeats), keyUp."""
                params: dict[str, Any] = {"key": key_, "code": key_, "modifiers": modifiers}
                await command("Input.dispatchKeyEvent", {"type": "keyDown", "autoRepeat": False, **params})
                for _ in range(repeats):
                    await command("Input.dispatchKeyEvent", {"type": "keyDown", "autoRepeat": True, **params})
                await command("Input.dispatchKeyEvent", {"type": "keyUp", **params})

            async def type_char(char: str) -> None:
                for type_ in ("keyDown", "char", "keyUp"):
                    params: dict[str, Any] = {"type": type_, "key": char, "code": f"Key{char.upper()}"}
                    if type_ == "char":
                        params["text"] = char
                    await command("Input.dispatchKeyEvent", params)

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})

            async def reset_field(value: str = "") -> None:
                await evaluate(
                    "(function () {"
                    "  document.body.innerHTML = '';"
                    "  var el = document.createElement('input');"
                    "  el.id = 'f';"
                    "  el.type = 'text';"
                    f"  el.value = {json.dumps(value)};"
                    "  document.body.appendChild(el);"
                    "  el.focus();"
                    "  el.setSelectionRange(el.value.length, el.value.length);"
                    "  return 'ok';"
                    "})()"
                )

            async def field_value() -> Any:
                return await evaluate("document.getElementById('f').value")

            META, SHIFT = 4, 8

            await reset_field("hello")
            await key("Backspace", repeats=2)
            assert await field_value() == "he", "a held Backspace must delete once per repeat"

            await reset_field("hello")
            await key("a", modifiers=META)
            await type_char("x")
            assert await field_value() == "x", "typing after Cmd-A must replace the whole value"

            await reset_field("hello")
            await key("a", modifiers=META)
            await key("Backspace")
            assert await field_value() == "", "Backspace after Cmd-A must clear the field"

            await reset_field("abc")
            await key("ArrowLeft")
            await type_char("X")
            assert await field_value() == "abXc", "ArrowLeft must move the caret back one character"

            await key("ArrowLeft", modifiers=SHIFT, repeats=1)
            await type_char("Y")
            assert await field_value() == "aYc", "Shift-ArrowLeft must extend the selection, replaced by typing"

            await key("Home")
            await key("Delete")
            assert await field_value() == "Yc", "Home then Delete must delete the first character"

            await key("End")
            await key("Backspace")
            assert await field_value() == "Y", "End then Backspace must delete the last character"

            # A page that handles the shortcut itself keeps it: preventing the default on keydown
            # stops the bridge's select-all, exactly as it stops a browser's.
            await reset_field("hello")
            await evaluate(
                "window.__keys = [];"
                " document.getElementById('f').addEventListener('keydown', e => {"
                "   window.__keys.push(e.key + (e.metaKey ? '+meta' : ''));"
                "   if (e.metaKey && e.key === 'a') { e.preventDefault(); }"
                " });"
                " 'ok'"
            )
            await key("a", modifiers=META)
            await type_char("z")
            assert await evaluate("JSON.stringify(window.__keys)") == '["a+meta","z"]', (
                "the page's keydown listener must see every key with its modifiers"
            )
            assert await field_value() == "helloz", "a page that prevents Cmd-A's default must keep its value"
        finally:
            await client.close()


async def testp_cdp_server_emulates_user_preferences(lockdown: LockdownClient) -> None:
    """
    Chrome's rendering emulation (prefers-color-scheme, prefers-reduced-motion, prefers-contrast,
    print media) must reach the page. The WebKit command the bridge used to send for dark mode no
    longer exists on iOS 26 ("'Page.setForcedAppearance' was not found"), so the page kept its own
    scheme while the editor showed the emulation as active.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        ids = itertools.count(1)
        try:
            await client.command(next(ids), "Page.enable", {})
            await client.command(next(ids), "Runtime.enable", {})
            await client.command(next(ids), "Page.navigate", {"url": "https://example.com/"})
            await asyncio.sleep(3)

            async def preferences() -> str:
                reply = await client.command(
                    next(ids),
                    "Runtime.evaluate",
                    {
                        "expression": "['(prefers-color-scheme: dark)', '(prefers-reduced-motion: reduce)', "
                        "'(prefers-contrast: more)', 'print'].map((m) => matchMedia(m).matches).join('/')",
                        "returnByValue": True,
                    },
                )
                return reply["result"]["result"]["value"]

            assert await preferences() == "false/false/false/false"

            reply = await client.command(next(ids), "Emulation.setAutoDarkModeOverride", {"enabled": True})
            assert "error" not in reply, reply
            assert await preferences() == "true/false/false/false"
            await client.command(next(ids), "Emulation.setAutoDarkModeOverride", {})
            assert await preferences() == "false/false/false/false"

            features = [
                {"name": "prefers-color-scheme", "value": "dark"},
                {"name": "prefers-reduced-motion", "value": "reduce"},
                {"name": "prefers-contrast", "value": "more"},
            ]
            reply = await client.command(next(ids), "Emulation.setEmulatedMedia", {"media": "", "features": features})
            assert "error" not in reply, reply
            assert await preferences() == "true/true/true/false"
            # Chrome semantics: features left out of the next list are reset.
            await client.command(next(ids), "Emulation.setEmulatedMedia", {"media": "", "features": features[:1]})
            assert await preferences() == "true/false/false/false"
            # WebKit renders an emulated print media type with the light scheme, whatever the
            # override says (verified on iOS 26 in either order), so print is checked on its own.
            await client.command(next(ids), "Emulation.setEmulatedMedia", {"media": "print", "features": []})
            assert await preferences() == "false/false/false/true"
            await client.command(next(ids), "Emulation.setEmulatedMedia", {"media": "", "features": []})
            assert await preferences() == "false/false/false/false"
        finally:
            await client.close()


async def testp_cdp_server_reports_the_node_inspector_events(lockdown: LockdownClient) -> None:
    """
    The events a Node.js inspector target emits and Chrome's debugger clients rely on, on a page:
    an uncaught exception, an unhandled rejection and a parse error arrive as Runtime.exceptionThrown
    (VS Code renders exceptions from nothing else), a Runtime.addBinding function calls back through
    Runtime.bindingCalled, the console's inspect() becomes Runtime.inspectRequested, and a navigation
    destroys the contexts it announced before clearing them.
    """
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        client = CdpWebsocketClient(port, targets[0]["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        ids = itertools.count(1)
        events: list[dict[str, Any]] = []

        async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
            id_ = next(ids)
            await client.send({"id": id_, "method": method, "params": params})

            async def wait() -> dict[str, Any]:
                while True:
                    message = await client.receive()
                    if message.get("id") == id_:
                        return message
                    if "method" in message:
                        events.append(message)

            return await asyncio.wait_for(wait(), TIMEOUT)

        async def drain(seconds: float) -> None:
            end = asyncio.get_event_loop().time() + seconds
            while True:
                left = end - asyncio.get_event_loop().time()
                if left <= 0:
                    return
                try:
                    message = await asyncio.wait_for(client.receive(), left)
                except asyncio.TimeoutError:
                    return
                if "method" in message:
                    events.append(message)

        def named(method: str) -> list[dict[str, Any]]:
            return [e["params"] for e in events if e["method"] == method]

        try:
            for method in ("Page.enable", "Runtime.enable", "Debugger.enable", "Log.enable"):
                await command(method, {})
            await command("Page.navigate", {"url": "https://example.com/"})
            await drain(3)
            events.clear()

            # An uncaught exception thrown on the third line of a timer callback.
            await command(
                "Runtime.evaluate",
                {
                    "expression": "setTimeout(function later() {\n  const a = 1;\n  throw new RangeError('line3');\n}, 10)"
                },
            )
            await command("Runtime.evaluate", {"expression": "Promise.reject(new Error('nope'))"})
            await drain(2)
            thrown = named("Runtime.exceptionThrown")
            assert len(thrown) == 2, thrown
            # The rejection is reported before the timer fires; match by text, not order.
            by_text = {t["exceptionDetails"]["text"]: t for t in thrown}
            details = by_text["Uncaught"]["exceptionDetails"]
            assert details["exception"]["description"] == "RangeError: line3"
            assert details["exception"]["className"] == "RangeError"
            assert details["lineNumber"] == 2, "Chrome counts lines from 0"
            assert details["stackTrace"]["callFrames"][0]["functionName"] == "later"
            assert details["url"] == "", "an evaluation has no URL; WebKit's 'undefined' must not leak"
            assert by_text["Uncaught (in promise)"]["exceptionDetails"]["exception"]["description"] == "Error: nope"
            assert not [e for e in named("Log.entryAdded") if e["entry"]["source"] == "javascript"], (
                "exceptions must not be reported twice"
            )

            # A binding: install, call from the page, receive the call; survive a reload.
            events.clear()
            reply = await command("Runtime.addBinding", {"name": "toEditor"})
            assert reply == {"id": reply["id"], "result": {}}
            await drain(0.5)
            reply = await command(
                "Runtime.evaluate",
                {"expression": "toEditor(JSON.stringify({n: 1})); typeof toEditor", "returnByValue": True},
            )
            assert reply["result"]["result"]["value"] == "function"
            await drain(1)
            calls = named("Runtime.bindingCalled")
            assert calls and calls[0]["name"] == "toEditor" and calls[0]["payload"] == '{"n":1}', calls
            assert not named("Runtime.consoleAPICalled"), "the binding's transport must not show as console output"

            events.clear()
            await command("Page.navigate", {"url": "https://example.com/?again"})
            await drain(3)
            methods = [e["method"] for e in events]
            destroyed = methods.index("Runtime.executionContextDestroyed")
            assert destroyed < methods.index("Runtime.executionContextsCleared"), methods
            created = methods.index("Runtime.executionContextCreated", destroyed)
            assert created > destroyed
            reply = await command("Runtime.evaluate", {"expression": "typeof toEditor", "returnByValue": True})
            assert reply["result"]["result"]["value"] == "function", "a binding outlives navigation, as in Chrome"

            # inspect() from the console.
            events.clear()
            await command("Runtime.evaluate", {"expression": "inspect(document.body)", "includeCommandLineAPI": True})
            await drain(1)
            requested = named("Runtime.inspectRequested")
            assert requested and requested[0]["object"]["className"] == "HTMLBodyElement", requested

            await command("Runtime.removeBinding", {"name": "toEditor"})
            await drain(0.5)
            reply = await command("Runtime.evaluate", {"expression": "typeof toEditor", "returnByValue": True})
            assert reply["result"]["result"]["value"] == "undefined"
        finally:
            await client.close()


async def testp_cdp_server_binds_url_breakpoints_set_before_a_jscontext_script(lockdown: LockdownClient) -> None:
    """
    An editor sets its breakpoints by URL as soon as it attaches, before the script exists. A
    JSContext script only gets its (synthetic) URL when it is parsed, so such a breakpoint could
    not bind; the bridge now keeps it, binds it when the script appears, reports
    Debugger.breakpointResolved as V8 would - and the breakpoint hits. (A bare JSContext has no
    timers and reports no unhandled rejection through the console, so the exception path is
    covered on a page, where WebKit does report them.)
    """
    async with cdp_server(lockdown) as (port, _):
        targets = [target for target in await http_get_json(port, "/json/list") if target["type"] == "node"]
        if not targets:
            pytest.skip("no inspectable JSContext on the device")
        for target in targets:
            if await evaluate_and_log_in_javascript_context(port, target["id"]):
                break
        else:
            pytest.skip("no listed JSContext answered the inspector")
        client = CdpWebsocketClient(port, target["id"])
        await asyncio.wait_for(client.connect(), TIMEOUT)
        ids = itertools.count(1)
        events: list[dict[str, Any]] = []

        async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
            id_ = next(ids)
            await client.send({"id": id_, "method": method, "params": params})

            async def wait() -> dict[str, Any]:
                while True:
                    message = await client.receive()
                    if message.get("id") == id_:
                        return message
                    if "method" in message:
                        events.append(message)

            return await asyncio.wait_for(wait(), TIMEOUT)

        async def until(method: str, seconds: float = 10) -> dict[str, Any]:
            async def wait() -> dict[str, Any]:
                while True:
                    for event in events:
                        if event["method"] == method:
                            events.remove(event)
                            return event["params"]
                    message = await client.receive()
                    if "method" in message:
                        events.append(message)

            return await asyncio.wait_for(wait(), seconds)

        async def drain(seconds: float) -> None:
            end = asyncio.get_event_loop().time() + seconds
            while True:
                left = end - asyncio.get_event_loop().time()
                if left <= 0:
                    return
                try:
                    message = await asyncio.wait_for(client.receive(), left)
                except asyncio.TimeoutError:
                    return
                if "method" in message:
                    events.append(message)

        try:
            await command("Runtime.enable", {})
            await command("Debugger.enable", {})
            await command("Debugger.setBreakpointsActive", {"active": True})
            await drain(1.5)  # the context's existing scripts are announced on enable
            events.clear()
            # Learn the next script id from a throwaway evaluation: JSContext scripts are numbered
            # consecutively, so the editor's breakpoint can target the script that follows.
            await command("Runtime.evaluate", {"expression": "0"})
            await drain(1)
            parsed = [e["params"] for e in events if e["method"] == "Debugger.scriptParsed"]
            next_id = int(parsed[-1]["scriptId"]) + 1
            events.clear()
            url = f"jscontext:///{next_id}.js"
            reply = await command("Debugger.setBreakpointByUrl", {"url": url, "lineNumber": 1})
            breakpoint_id = reply["result"]["breakpointId"]
            assert reply["result"]["locations"] == [], "not bound yet: the script does not exist"

            # The script defines a function; the breakpoint binds as it is parsed and hits when the
            # function runs later (a one-shot evaluation would have finished before binding).
            await command("Runtime.evaluate", {"expression": "function bpTarget() {\n  return 41 + 1;\n}\n'defined'"})
            resolved = await until("Debugger.breakpointResolved")
            assert resolved["breakpointId"] == breakpoint_id
            assert resolved["location"]["scriptId"] == str(next_id) and resolved["location"]["lineNumber"] == 1
            await client.send({"id": next(ids), "method": "Runtime.evaluate", "params": {"expression": "bpTarget()"}})
            paused = await until("Debugger.paused")
            location = paused["callFrames"][0]["location"]
            assert (location["scriptId"], location["lineNumber"]) == (str(next_id), 1), location
            await command("Debugger.resume", {})

            reply = await command("Debugger.removeBreakpoint", {"breakpointId": breakpoint_id})
            assert reply == {"id": reply["id"], "result": {}}
            events.clear()
            await command("Runtime.evaluate", {"expression": "bpTarget()", "returnByValue": True})
            await drain(1)
            assert not [e for e in events if e["method"] == "Debugger.paused"], "removed breakpoints must not hit"
        finally:
            await client.close()


async def test_a_child_frame_navigation_ends_its_contexts_and_recreates_its_worlds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child frame committing a new document loses the contexts its old document had, and the
    worlds a client registered are created afresh for the new one, as Chrome does. WebKit only
    announces the new main-world context; without the destroy, a client kept using what it built
    in the old document (Playwright its injected utility script in the synthesized world) and a
    payment iframe the SDK navigated after the client first touched it was never found (#1919)."""
    with offline_cdp_target(monkeypatch) as (target, _):
        await target._page_add_script_to_evaluate_on_new_document({
            "id": 1,
            "method": "Page.addScriptToEvaluateOnNewDocument",
            "params": {"source": "", "worldName": "utility"},
        })
        # The top frame commits, then a child frame commits its first document.
        await target._page_frame_navigated({
            "method": "Page.frameNavigated",
            "params": {"frame": {"id": "0.1", "loaderId": "0.2", "url": "https://a/"}},
        })
        await target._runtime_execution_context_created({
            "method": "Runtime.executionContextCreated",
            "params": {"context": {"id": 5, "type": "normal", "name": "", "frameId": "0.1"}},
        })
        child = {"id": "0.26", "loaderId": "0.27", "url": "https://pay/bootstrap", "parentId": "0.1", "name": "card"}
        await target._page_frame_navigated({"method": "Page.frameNavigated", "params": {"frame": child}})
        await target._runtime_execution_context_created({
            "method": "Runtime.executionContextCreated",
            "params": {"context": {"id": 68, "type": "normal", "name": "", "frameId": "0.26"}},
        })
        announced: list[dict[str, Any]] = []
        while not target.output_queue.empty():
            announced.append(target.output_queue.get_nowait())
        worlds = [
            m["params"]["context"]["id"]
            for m in announced
            if m.get("method") == "Runtime.executionContextCreated" and m["params"]["context"]["name"] == "utility"
        ]
        first_world = [w for w in worlds if target._isolated_world_frames.get(w) == "0.26"]
        assert len(first_world) == 1, "the registered world is created in the child frame's first document"
        assert target._real_context_id(first_world[0]) == 68

        # The payment SDK navigates the frame to the real form; WebKit reports it (didCommitLoad)
        # and then announces the new document's context.
        child = {**child, "loaderId": "0.28", "url": "https://pay/form"}
        await target._page_frame_navigated({"method": "Page.frameNavigated", "params": {"frame": child}})
        await target._runtime_execution_context_created({
            "method": "Runtime.executionContextCreated",
            "params": {"context": {"id": 71, "type": "normal", "name": "", "frameId": "0.26"}},
        })
        emitted: list[dict[str, Any]] = []
        while not target.output_queue.empty():
            emitted.append(target.output_queue.get_nowait())
        methods = [m["method"] for m in emitted]
        assert methods[:3] == [
            "Runtime.executionContextDestroyed",
            "Runtime.executionContextDestroyed",
            "Page.frameNavigated",
        ], methods
        assert emitted[0]["params"]["executionContextId"] == first_world[0]
        assert emitted[1]["params"]["executionContextId"] == 68
        created = [m["params"]["context"] for m in emitted if m["method"] == "Runtime.executionContextCreated"]
        assert [c["id"] for c in created if c["name"] == ""] == [71]
        new_worlds = [c["id"] for c in created if c["name"] == "utility"]
        assert len(new_worlds) == 1 and new_worlds[0] != first_world[0], "a fresh world for the new document"
        assert target._real_context_id(new_worlds[0]) == 71
        # The old world is gone for good: it is no longer resolved to any context of the frame.
        assert first_world[0] not in target._isolated_world_context_ids
        assert target._real_context_id(first_world[0]) == first_world[0]


async def testp_cdp_server_reaches_a_child_frame_after_it_navigates(lockdown: LockdownClient) -> None:
    """A world created in a child frame before the frame navigated to a new document is ended,
    and a fresh one announced, so a client that touched the frame early still reaches the
    document it shows now (#1919: a payment iframe navigated by its SDK after Playwright's first
    look at it kept being queried in the old document, and fill() never found the field)."""
    async with cdp_server_with_safari_page(lockdown) as (port, targets):
        page_id = targets[0]["id"]
        client = CdpWebsocketClient(port, page_id)
        await asyncio.wait_for(client.connect(), TIMEOUT)
        message_ids = itertools.count(1)
        events: list[dict[str, Any]] = []
        try:

            async def command(method: str, params: dict[str, Any]) -> dict[str, Any]:
                id_ = next(message_ids)
                await client.send({"id": id_, "method": method, "params": params})

                async def wait_for_response() -> dict[str, Any]:
                    while True:
                        message = await client.receive()
                        if "id" not in message:
                            events.append(message)
                        elif message["id"] == id_:
                            return message

                return await asyncio.wait_for(wait_for_response(), TIMEOUT)

            async def drain(seconds: float) -> None:
                deadline = asyncio.get_event_loop().time() + seconds
                while asyncio.get_event_loop().time() < deadline:
                    with suppress(asyncio.TimeoutError):
                        events.append(await asyncio.wait_for(client.receive(), 0.5))

            def child_frame_id() -> Optional[str]:
                for event in events:
                    if event.get("method") == "Page.frameNavigated":
                        frame = event["params"]["frame"]
                        if frame.get("parentId") == page_id and frame.get("name") == "pmd3-card":
                            return frame["id"]
                return None

            await command("Page.enable", {})
            await command("Runtime.enable", {})
            await command("Page.navigate", {"url": "https://example.com/"})
            await drain(2)
            events.clear()
            await command(
                "Runtime.evaluate",
                {
                    "expression": (
                        "const f = document.createElement('iframe'); f.name = 'pmd3-card';"
                        " f.src = 'https://httpbin.org/html'; document.body.appendChild(f); 'added'"
                    ),
                    "returnByValue": True,
                },
            )
            await drain(4)
            frame_id = child_frame_id()
            assert frame_id is not None, "the child frame's first document was announced"
            world = await command(
                "Page.createIsolatedWorld",
                {"frameId": frame_id, "worldName": "__pmd3_touch__", "grantUniveralAccess": True},
            )
            old_world = world["result"]["executionContextId"]
            first = await command(
                "Runtime.evaluate", {"expression": "document.URL", "contextId": old_world, "returnByValue": True}
            )
            assert first["result"]["result"]["value"] == "https://httpbin.org/html", (
                "the world starts in the first document"
            )

            # The frame's owner (a payment SDK) navigates it to the real form.
            events.clear()
            await command(
                "Runtime.evaluate",
                {
                    "expression": "document.querySelector('iframe[name=pmd3-card]').src = 'https://httpbin.org/forms/post'; 'swapped'",
                    "returnByValue": True,
                },
            )
            await drain(5)
            destroyed = [
                e["params"]["executionContextId"]
                for e in events
                if e.get("method") == "Runtime.executionContextDestroyed"
            ]
            assert old_world in destroyed, "the world of the old document is ended"
            fresh = [
                e["params"]["context"]
                for e in events
                if e.get("method") == "Runtime.executionContextCreated"
                and e["params"]["context"].get("auxData", {}).get("frameId") == frame_id
            ]
            assert fresh, "the new document's context is announced"
            new_world = await command(
                "Page.createIsolatedWorld",
                {"frameId": frame_id, "worldName": "__pmd3_after__", "grantUniveralAccess": True},
            )
            found = await command(
                "Runtime.evaluate",
                {
                    "expression": "[document.URL, !!document.querySelector('input[name=custname]')]",
                    "contextId": new_world["result"]["executionContextId"],
                    "returnByValue": True,
                },
            )
            assert found["result"]["result"]["value"] == ["https://httpbin.org/forms/post", True]
            stale = await command(
                "Runtime.evaluate", {"expression": "document.URL", "contextId": old_world, "returnByValue": True}
            )
            assert (
                "error" in stale or stale.get("result", {}).get("result", {}).get("value") != "https://example.com/"
            ), "a world that is gone is refused, not answered from the top frame"
        finally:
            await client.close()
