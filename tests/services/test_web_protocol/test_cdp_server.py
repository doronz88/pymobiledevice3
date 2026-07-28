import asyncio
import itertools
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, Optional

import pytest
import uvicorn
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, CloseConnection, TextMessage
from wsproto.events import Request as WsRequest

from pymobiledevice3.exceptions import WebInspectorNotEnabledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.web_protocol.cdp_server import app
from pymobiledevice3.services.webinspector import SAFARI, WebinspectorService

TIMEOUT = 30


@asynccontextmanager
async def cdp_server_with_safari_page(
    lockdown: LockdownClient,
) -> AsyncGenerator[tuple[int, list[dict[str, Any]]], None]:
    """Run the CDP server against the device and yield (port, listed Safari targets)."""
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
        port = server.servers[0].sockets[0].getsockname()[1]
        await inspector.open_app(SAFARI)
        targets = []
        for _ in range(TIMEOUT):
            targets = await http_get_json(port, "/json/list")
            if targets:
                break
            await asyncio.sleep(1)
        assert targets, "no inspectable Safari page was listed"
        yield port, targets
    finally:
        # force_exit skips uvicorn's graceful wait so a wedged debugger session can't hang the test
        server.should_exit = True
        server.force_exit = True
        await asyncio.wait_for(serve_task, TIMEOUT)
        await inspector.close()


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
