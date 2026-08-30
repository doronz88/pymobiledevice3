import asyncio
import logging
import uuid
from collections.abc import Iterator
from typing import Any, Optional

from fastapi import WebSocket

from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import Application, Page, WebinspectorService, WirTypes, make_target_id

logger = logging.getLogger(__name__)

# Debuggable types the bridge can drive: WebKit's web pages, and JavaScriptCore's JSContexts
# (an app or daemon that called -[JSContext setInspectable:YES], and every WKWebView's own
# JSContext). The latter implement only the JS-side domains, so they are advertised to the
# frontend as Chrome does for a bare V8 target - see JS_TARGET_TYPE.
INSPECTABLE_TYPES = (WirTypes.WEB, WirTypes.WEB_PAGE, WirTypes.JAVASCRIPT)

# Chrome's target type for a JavaScript-only debuggable (its Node.js targets). It is what makes
# the frontend leave out the Elements/Network/Application panels and the Page/DOM/CSS domains a
# JSContext does not implement.
JS_TARGET_TYPE = "node"

# Seconds to let webinspectord reply with the updated page listings before answering /json
PAGE_LISTING_FLUSH = 0.5
# Seconds to wait for the device to report the inspection target of a new debugger session
TARGET_CREATION_TIMEOUT = 30
# Seconds between page-listing refreshes while target discovery/auto-attach is active
TARGET_POLL_INTERVAL = 2.0
# Seconds to wait for another debugger session on the same page to tear down before skipping it
PAGE_LOCK_TIMEOUT = 5
# Seconds a page-endpoint connection waits for the page after asking the session holding it to hand
# it over. Far longer than PAGE_LOCK_TIMEOUT: the handover itself is quick, but several connections
# to one page are served one after another, and dropping a client that is merely queued behind the
# others would trade one silent failure for another. Only a session wedged mid-teardown reaches it.
PAGE_HANDOVER_TIMEOUT = 30

# WebKit supports a single inspector session per page, so sessions are serialized per page:
# a new debugger connection waits until the previous session's WIR socket teardown completed
# (otherwise its socket setup races the teardown and webinspectord ignores it). Shared between
# the page endpoint and browser-endpoint attachments.
PAGE_LOCKS: dict[str, asyncio.Lock] = {}

# Page-endpoint sessions that can be superseded, by page id. A DevTools tab left attached holds
# its page for as long as it stays open, so without this every later connection to that page waits
# behind it - its websocket already accepted, which is what a blank, unresponsive frontend is. A
# new connection sets the event to hand the page over, then waits for PAGE_LOCKS as usual so the
# old session's WIR teardown still completes before the new one's socket setup.
PAGE_TAKEOVERS: dict[str, asyncio.Event] = {}


def iter_inspectable(inspector: WebinspectorService) -> "Iterator[tuple[str, Application, Page]]":
    """Walk every debuggable the bridge can attach to, as (target id, application, page).

    The target id qualifies the page with its application (see `make_target_id`); the bare page
    identifier would collide, most visibly across JSContexts.
    """
    for app_id, pages in inspector.application_pages.items():
        application = inspector.connected_application.get(app_id)
        if application is None:
            continue
        for page_id, page in pages.items():
            if page.type_ in INSPECTABLE_TYPES:
                yield make_target_id(app_id, page_id), application, page


def target_type(page: Page) -> str:
    """Chrome target type to advertise a debuggable as."""
    return JS_TARGET_TYPE if page.type_ == WirTypes.JAVASCRIPT else "page"


def target_title(application: Application, page: Page) -> str:
    """Title to advertise a debuggable under. JSContexts are all named "JSContext" and have no URL
    to tell them apart, so name their process instead."""
    if page.type_ == WirTypes.JAVASCRIPT:
        return f"{application.name} ({application.pid}): {page.web_title or 'JSContext'}"
    return page.web_title or ""


class _PageSession:
    """A flat-mode CDP session attached to one device page."""

    def __init__(
        self, session_id: str, page_id: str, target: CdpTarget, pump: "asyncio.Task[None]", lock: asyncio.Lock
    ) -> None:
        self.session_id = session_id
        self.page_id = page_id
        self.target = target
        self.pump = pump
        self.lock = lock


class CdpBrowser:
    """
    Browser-level CDP endpoint (flat session mode) over the Web Inspector page targets.

    Chrome-compatible debugger clients (VS Code's js-debug, Puppeteer, ...) connect to the
    browser websocket advertised by /json/version rather than to a page websocket, then discover
    and attach pages through the Target domain: Target.attachToBrowserTarget ->
    Target.setDiscoverTargets -> Target.targetCreated -> Target.attachToTarget, with every
    per-page message carrying the attachment's sessionId. Each attached page is backed by an
    ordinary CdpTarget whose messages are tagged/untagged with that sessionId here.
    """

    def __init__(self, inspector: WebinspectorService, websocket: WebSocket) -> None:
        self.inspector = inspector
        self.websocket = websocket
        # sessionIds handed out by Target.attachToBrowserTarget; commands arriving under them are
        # browser-level commands, not page messages
        self._browser_sessions: set[str] = set()
        self._page_sessions: dict[str, _PageSession] = {}
        self._attached_pages: dict[str, str] = {}  # page_id -> sessionId
        self._known_targets: dict[str, dict[str, Any]] = {}  # page_id -> targetInfo
        self._discover = False
        self._auto_attach = False
        # session under which discovery/auto-attach was enabled; lifecycle events are tagged with
        # it (js-debug listens on the browser session, Puppeteer on the root connection)
        self._events_session: Optional[str] = None
        self._poll_task: Optional[asyncio.Task[None]] = None
        self._refresh_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._handlers = {
            "Browser.getVersion": self._browser_get_version,
            "Browser.close": self._generic_ack,
            "Target.attachToBrowserTarget": self._target_attach_to_browser_target,
            "Target.setDiscoverTargets": self._target_set_discover_targets,
            "Target.setAutoAttach": self._target_set_auto_attach,
            "Target.getTargets": self._target_get_targets,
            "Target.getTargetInfo": self._target_get_target_info,
            "Target.attachToTarget": self._target_attach_to_target,
            "Target.detachFromTarget": self._target_detach_from_target,
        }

    async def run(self) -> None:
        """Serve the connection until the client disconnects."""
        async for message in self.websocket.iter_json():
            logger.debug(f"BROWSER CDP INPUT: {message}")
            try:
                await self._handle(message)
            except Exception:
                logger.exception(f"failed handling browser message: {message}")

    async def close(self) -> None:
        if self._poll_task is not None:
            self._poll_task.cancel()
            await asyncio.gather(self._poll_task, return_exceptions=True)
            self._poll_task = None
        for session in list(self._page_sessions.values()):
            await self._close_session(session, notify=False)

    async def _send(self, message: dict[str, Any]) -> None:
        logger.debug(f"BROWSER CDP OUTPUT: {message}")
        async with self._send_lock:
            await self.websocket.send_json(message)

    async def _reply(self, message: dict[str, Any], result: dict[str, Any]) -> None:
        response: dict[str, Any] = {"id": message["id"], "result": result}
        if "sessionId" in message:
            response["sessionId"] = message["sessionId"]
        await self._send(response)

    async def _handle(self, message: dict[str, Any]) -> None:
        session_id = message.get("sessionId")
        if session_id is not None and session_id not in self._browser_sessions:
            page_session = self._page_sessions.get(session_id)
            if page_session is None:
                if "id" in message:
                    await self._send({
                        "id": message["id"],
                        "sessionId": session_id,
                        "error": {"code": -32001, "message": f"Session with given id not found: {session_id}"},
                    })
                return
            await page_session.target.send({k: v for k, v in message.items() if k != "sessionId"})
            return
        handler = self._handlers.get(message.get("method", ""))
        if handler is not None:
            await handler(message)
        elif "id" in message:
            # Unsupported browser-level method: acknowledge so clients treating these as
            # best-effort configuration don't stall on a missing response.
            logger.debug(f"acking unsupported browser method: {message.get('method')}")
            await self._reply(message, {})

    async def _generic_ack(self, message: dict[str, Any]) -> None:
        await self._reply(message, {})

    async def _browser_get_version(self, message: dict[str, Any]) -> None:
        await self._reply(
            message,
            {
                "protocolVersion": "1.3",
                "product": "Safari",
                "revision": "",
                "userAgent": "pymobiledevice3",
                "jsVersion": "",
            },
        )

    async def _target_attach_to_browser_target(self, message: dict[str, Any]) -> None:
        session_id = str(uuid.uuid4()).upper()
        self._browser_sessions.add(session_id)
        await self._reply(message, {"sessionId": session_id})

    async def _target_set_discover_targets(self, message: dict[str, Any]) -> None:
        self._discover = bool(message.get("params", {}).get("discover"))
        if self._discover:
            self._events_session = message.get("sessionId")
            # Announce the current pages before answering so a client awaiting the response
            # observes the initial Target.targetCreated batch immediately after it.
            await self._refresh_targets()
            self._ensure_poll()
        await self._reply(message, {})

    async def _target_set_auto_attach(self, message: dict[str, Any]) -> None:
        self._auto_attach = bool(message.get("params", {}).get("autoAttach"))
        if self._auto_attach:
            self._events_session = message.get("sessionId")
            await self._refresh_targets()
            self._ensure_poll()
        await self._reply(message, {})

    async def _target_get_targets(self, message: dict[str, Any]) -> None:
        await self._refresh_targets()
        await self._reply(message, {"targetInfos": list(self._known_targets.values())})

    async def _target_get_target_info(self, message: dict[str, Any]) -> None:
        target_id = message.get("params", {}).get("targetId")
        info: Optional[dict[str, Any]] = self._known_targets.get(target_id) if target_id is not None else None
        if info is None:
            info = {
                "targetId": self.inspector.connection_id,
                "type": "browser",
                "title": "",
                "url": "",
                "attached": True,
                "canAccessOpener": False,
            }
        await self._reply(message, {"targetInfo": info})

    async def _target_attach_to_target(self, message: dict[str, Any]) -> None:
        page_id = message["params"]["targetId"]
        session_id = await self._attach_page(page_id)
        if session_id is None:
            await self._send({
                "id": message["id"],
                **({"sessionId": message["sessionId"]} if "sessionId" in message else {}),
                "error": {"code": -32000, "message": f"Cannot attach to target: {page_id}"},
            })
            return
        await self._reply(message, {"sessionId": session_id})

    async def _target_detach_from_target(self, message: dict[str, Any]) -> None:
        session_id = message.get("params", {}).get("sessionId")
        session = self._page_sessions.get(session_id)
        if session is not None:
            await self._close_session(session, notify=False)
        await self._reply(message, {})

    def _ensure_poll(self) -> None:
        if self._poll_task is None or self._poll_task.done():
            self._poll_task = asyncio.create_task(self._poll())

    async def _poll(self) -> None:
        """Keep the client's target list current: pages opened/closed on the device after the
        initial discovery are announced/destroyed (and auto-attached) as they appear."""
        while self._discover or self._auto_attach:
            await asyncio.sleep(TARGET_POLL_INTERVAL)
            try:
                await self._refresh_targets()
            except Exception:
                logger.exception("target refresh failed")

    def _list_pages(self) -> dict[str, tuple[Application, Page]]:
        return {target_id: (application, page) for target_id, application, page in iter_inspectable(self.inspector)}

    async def _refresh_targets(self) -> None:
        async with self._refresh_lock:
            await self.inspector.get_open_pages()
            await self.inspector.flush_input(PAGE_LISTING_FLUSH)
            pages = self._list_pages()
            for page_id in [known for known in self._known_targets if known not in pages]:
                await self._destroy_target(page_id)
            for page_id, (application, page) in pages.items():
                is_new = page_id not in self._known_targets
                self._known_targets[page_id] = {
                    "targetId": page_id,
                    "type": target_type(page),
                    "title": target_title(application, page),
                    "url": page.web_url or "",
                    "attached": page_id in self._attached_pages,
                    "canAccessOpener": False,
                }
                if is_new and self._discover:
                    await self._send_event("Target.targetCreated", {"targetInfo": self._known_targets[page_id]})
                if self._auto_attach and page_id not in self._attached_pages:
                    await self._auto_attach_page(page_id)

    async def _destroy_target(self, page_id: str) -> None:
        self._known_targets.pop(page_id, None)
        session_id = self._attached_pages.get(page_id)
        if session_id is not None:
            await self._close_session(self._page_sessions[session_id], notify=True)
        if self._discover:
            await self._send_event("Target.targetDestroyed", {"targetId": page_id})

    async def _send_event(self, method: str, params: dict[str, Any]) -> None:
        event: dict[str, Any] = {"method": method, "params": params}
        if self._events_session is not None:
            event["sessionId"] = self._events_session
        await self._send(event)

    async def _auto_attach_page(self, page_id: str) -> None:
        session_id = await self._attach_page(page_id)
        if session_id is None:
            return
        await self._send_event(
            "Target.attachedToTarget",
            {
                "sessionId": session_id,
                "targetInfo": self._known_targets[page_id],
                "waitingForDebugger": False,
            },
        )

    async def _attach_page(self, page_id: str) -> Optional[str]:
        """Open a WIR debugger session on the page and return its CDP sessionId (an existing
        attachment's id when already attached), or None when the page cannot be attached."""
        existing = self._attached_pages.get(page_id)
        if existing is not None:
            return existing
        try:
            application, page = self.inspector.find_page_id(page_id)
        except Exception:
            logger.warning(f"cannot attach: page {page_id} not found")
            return None
        lock = PAGE_LOCKS.setdefault(page_id, asyncio.Lock())
        try:
            await asyncio.wait_for(lock.acquire(), PAGE_LOCK_TIMEOUT)
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning(f"page {page_id}: busy with another debugger session, not attaching")
            return None
        wir_session_id = str(uuid.uuid4()).upper()
        protocol = SessionProtocol(self.inspector, wir_session_id, application, page, method_prefix="")
        try:
            target = await asyncio.wait_for(CdpTarget.create(protocol), TARGET_CREATION_TIMEOUT)
        except (asyncio.TimeoutError, TimeoutError):
            # A page already being debugged over another Web Inspector connection - a second
            # pymobiledevice3, Safari's own Web Inspector, or a client that exited without
            # detaching - never reports a target, and the listing says who holds it. Naming them
            # beats "the device did not answer", which sends people looking at the device.
            holder = page.web_connection_id
            if holder and holder != self.inspector.connection_id:
                logger.error(
                    f"page {page_id}: already being debugged over Web Inspector connection {holder}; "
                    "close that debugger, or the process that left it attached, and reconnect"
                )
            else:
                logger.error(f"page {page_id}: device did not report an inspection target in time")
            await self.inspector.teardown_inspector_socket(wir_session_id, application.id_, page.id_)
            lock.release()
            return None
        session_id = str(uuid.uuid4()).upper()
        pump = asyncio.create_task(self._pump(session_id, target))
        self._page_sessions[session_id] = _PageSession(session_id, page_id, target, pump, lock)
        self._attached_pages[page_id] = session_id
        if page_id in self._known_targets:
            self._known_targets[page_id]["attached"] = True
        return session_id

    async def _pump(self, session_id: str, target: CdpTarget) -> None:
        """Forward everything the page target emits to the client, tagged with its sessionId."""
        while True:
            message = await target.receive()
            message["sessionId"] = session_id
            await self._send(message)

    async def _close_session(self, session: _PageSession, notify: bool) -> None:
        self._page_sessions.pop(session.session_id, None)
        self._attached_pages.pop(session.page_id, None)
        if session.page_id in self._known_targets:
            self._known_targets[session.page_id]["attached"] = False
        session.pump.cancel()
        await asyncio.gather(session.pump, return_exceptions=True)
        try:
            await session.target.close()
        finally:
            session.lock.release()
        if notify:
            await self._send_event(
                "Target.detachedFromTarget", {"sessionId": session.session_id, "targetId": session.page_id}
            )
