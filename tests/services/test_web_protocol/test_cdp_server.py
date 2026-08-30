import asyncio
import itertools
import json
import socket
import threading
import urllib.request
import uuid
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlsplit

import pytest
import uvicorn
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, CloseConnection, TextMessage
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
    targets_html,
)
from pymobiledevice3.services.web_protocol.cdp_target import JS_CONTEXT_EXECUTION_ID, CdpTarget
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import SAFARI, Application, AutomationAvailability, Page, WebinspectorService

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
                await client.command(id_, "Page.navigate", {"url": url})
                client.seen_events.clear()
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
    assert '<a href="/devtools/js_app.html?ws=127.0.0.1:9222/devtools/page/PID:2:1">myapp (2): JSContext</a>' in html


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
