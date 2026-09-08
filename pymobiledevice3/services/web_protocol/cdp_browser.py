import asyncio
import itertools
import logging
import uuid
from collections.abc import Iterator
from typing import Any, Optional, cast

from fastapi import WebSocket

from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.web_protocol.cdp_trace import (
    BRIDGE_TO_EDITOR,
    EDITOR_TO_BRIDGE,
    ProtocolTrace,
)
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import (
    Application,
    AutomaticInspectionCandidate,
    Page,
    WebinspectorService,
    WirTypes,
    make_target_id,
)

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
# Seconds a JSContext that appeared in a listing is left to its automatic-inspection candidate
# before being attached as an already-running target. The device pushes the listing a few
# milliseconds ahead of the candidate; a context that never gets one (made inspectable before
# automatic inspection reached its process) is picked up by the poll after this.
CANDIDATE_GRACE = 3.0
# Seconds to wait for another debugger session on the same page to tear down before skipping it
PAGE_LOCK_TIMEOUT = 5
# Seconds a page-endpoint connection waits for the page after asking the session holding it to hand
# it over. Far longer than PAGE_LOCK_TIMEOUT: the handover itself is quick, but several connections
# to one page are served one after another, and dropping a client that is merely queued behind the
# others would trade one silent failure for another. Only a session wedged mid-teardown reaches it.
PAGE_HANDOVER_TIMEOUT = 30

# Playwright's CRBrowser asserts every attached page's targetInfo carries a browserContextId
# before it will adopt the page. It only uses the value to look the browser context up, falling
# back to its default context when the id is unrecognized, so a single stable id is enough - the
# bridge exposes no browser-context concept of its own. Chrome's own DevTools frontend ignores it.
DEFAULT_BROWSER_CONTEXT_ID = "pymobiledevice3-default-context"

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

# Debuggables the bridge itself attached to before they ran and is keeping paused for whichever
# frontend opens them (see HeldTargets), by page id. Both endpoints adopt from here before
# setting up a session of their own.
HELD_TARGETS: dict[str, CdpTarget] = {}


def adopt_held_target(page_id: str) -> Optional[CdpTarget]:
    """Take the session the bridge is holding for a page, if any, to attach a frontend to it."""
    target = HELD_TARGETS.pop(page_id, None)
    if target is not None:
        target.adopt()
    return target


def iter_inspectable(inspector: WebinspectorService) -> "Iterator[tuple[str, Application, Page]]":
    """Walk every debuggable the bridge can attach to, as (target id, application, page).

    The target id qualifies the page with its application (see `make_target_id`); the bare page
    identifier would collide, most visibly across JSContexts.
    """
    # The device reports a process's pages in whatever order it holds them (3, 1, 4, 2, 5 for
    # JSContexts); list applications by name and each one's pages by number.
    applications = sorted(
        ((application, app_id) for app_id, application in inspector.connected_application.items()),
        key=lambda item: (item[0].name.lower(), item[0].pid),
    )
    for application, app_id in applications:
        pages = inspector.application_pages.get(app_id, {})
        for page_id, page in sorted(
            pages.items(), key=lambda item: (not item[0].isdigit(), int(item[0]) if item[0].isdigit() else 0, item[0])
        ):
            if page.type_ in INSPECTABLE_TYPES:
                yield make_target_id(app_id, page_id), application, page


def target_type(page: Page) -> str:
    """Chrome target type to advertise a debuggable as."""
    return JS_TARGET_TYPE if page.type_ == WirTypes.JAVASCRIPT else "page"


def target_url(application: Application, page: Page) -> str:
    """URL to advertise a debuggable under. A JSContext has no document; name it after its
    process instead of leaving the field empty - WebStorm builds its Node-style target from
    this field and fails with "Malformed URL" on an empty one."""
    if page.type_ == WirTypes.JAVASCRIPT:
        return f"jscontext://{application.bundle}/{application.pid}/{page.id_}"
    return page.web_url


def target_title(application: Application, page: Page) -> str:
    """Title to advertise a debuggable under. JSContexts are all named "JSContext" and have no URL
    to tell them apart, so name their process and their number instead."""
    if page.type_ == WirTypes.JAVASCRIPT:
        return f"{application.name} ({application.pid}): {page.web_title or 'JSContext'} #{page.id_}"
    return page.web_title or ""


class _PageAttachment:
    """One device page, and every flat-mode CDP session attached to it.

    A client may attach to the same page more than once - Playwright drives a page through the
    session it was auto-attached with and opens a second one for raw protocol access - and each
    attachment is a session of its own. WebKit allows a single inspector session per page, so the
    one underlying target is shared, and the ids of requests are rewritten on the way through so
    each answer can be returned to the session that asked (their ids are numbered independently
    and would otherwise collide).
    """

    def __init__(self, page_id: str, target: CdpTarget, lock: asyncio.Lock) -> None:
        self.page_id = page_id
        self.target = target
        self.lock = lock
        self.pump: Optional[asyncio.Task[None]] = None
        self.session_ids: list[str] = []
        # wire id handed to the target -> (session that asked, the id it used)
        self.pending: dict[int, tuple[str, Any]] = {}
        self._next_wire_id = itertools.count(1)

    def claim_wire_id(self, session_id: str, original_id: Any) -> int:
        wire_id = next(self._next_wire_id)
        self.pending[wire_id] = (session_id, original_id)
        return wire_id


class CdpBrowser:
    """
    Browser-level CDP endpoint (flat session mode) over the Web Inspector page targets.

    Chrome-compatible debugger clients (VS Code's js-debug, Puppeteer, ...) connect to the
    browser websocket advertised by /json/version rather than to a page websocket, then discover
    and attach pages through the Target domain: Target.attachToBrowserTarget ->
    Target.setDiscoverTargets -> Target.targetCreated -> Target.attachToTarget, with every
    per-page message carrying the attachment's sessionId. Each attached page is backed by an
    ordinary CdpTarget whose messages are tagged/untagged with that sessionId here.

    Target.setAutoAttach with waitForDebuggerOnStart attaches debuggables before they run: the
    bridge enables webinspectord's automatic inspection, so an application creating a JSContext
    (or service worker) blocks until this client has attached and released it with
    Runtime.runIfWaitingForDebugger - Safari's "Automatically Show Web Inspector for JSContexts".
    WebKit offers no such hold for a WKWebView's page; those are attached the moment the device
    pushes the listing they appear in, and the navigation-created targets of an attached page
    are held (Target.setPauseOnStart) until the client's debugger setup reached them.

    :param pause_on_start: Also stop every auto-attached debuggable on its first statement -
        Safari's "Automatically Pause Connecting to JSContexts" (see CdpTarget.pause_on_start).
    """

    def __init__(
        self,
        inspector: WebinspectorService,
        websocket: WebSocket,
        pause_on_start: bool = False,
        trace: Optional[ProtocolTrace] = None,
    ) -> None:
        self.inspector = inspector
        self.websocket = websocket
        # The --trace recorder, if any: the browser endpoint is what VS Code's js-debug and
        # Playwright attach to, so its editor side is recorded here.
        self._trace = trace
        self._pause_on_start = pause_on_start
        # Target.setAutoAttach(waitForDebuggerOnStart): attach before the debuggable runs.
        self._wait_for_debugger = False
        self._automatic_inspection_enabled = False
        self._candidates: Optional[asyncio.Queue[AutomaticInspectionCandidate]] = None
        self._candidate_task: Optional[asyncio.Task[None]] = None
        self._listings: Optional[asyncio.Queue[str]] = None
        self._listing_task: Optional[asyncio.Task[None]] = None
        # JSContexts left to their candidate: page_id -> loop time to stop waiting for one
        self._awaiting_candidate: dict[str, float] = {}
        # sessionIds handed out by Target.attachToBrowserTarget; commands arriving under them are
        # browser-level commands, not page messages
        self._browser_sessions: set[str] = set()
        self._attachments: dict[str, _PageAttachment] = {}  # page_id -> attachment
        self._sessions: dict[str, _PageAttachment] = {}  # sessionId -> the page it is attached to
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
            if self._trace is not None:
                self._trace.record(EDITOR_TO_BRIDGE, message, session="browser")
            try:
                await self._handle(message)
            except Exception:
                logger.exception(f"failed handling browser message: {message}")

    async def close(self) -> None:
        if self._poll_task is not None:
            self._poll_task.cancel()
            await asyncio.gather(self._poll_task, return_exceptions=True)
            self._poll_task = None
        await self._stop_waiting_for_new_targets()
        for attachment in list(self._attachments.values()):
            await self._close_attachment(attachment, notify=False)

    async def _start_waiting_for_new_targets(self) -> None:
        """Take automatic-inspection candidates and pushed listings as they come."""
        # With the pause flag on, the bridge's own holder takes every candidate (HeldTargets) and
        # this client adopts the held session when the context shows up in a listing.
        if self._candidates is None and not self._pause_on_start:
            self._candidates = self.inspector.subscribe_automatic_inspection()
            self._candidate_task = asyncio.create_task(self._consume_candidates(self._candidates))
        if self._listings is None:
            self._listings = self.inspector.subscribe_listings()
            self._listing_task = asyncio.create_task(self._consume_listings(self._listings))
        if not self._automatic_inspection_enabled:
            self._automatic_inspection_enabled = True
            await self.inspector.set_automatic_inspection_enabled(True)

    async def _stop_waiting_for_new_targets(self) -> None:
        for task in (self._candidate_task, self._listing_task):
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self._candidate_task = self._listing_task = None
        if self._candidates is not None:
            self.inspector.unsubscribe_automatic_inspection(self._candidates)
            # Candidates offered but not yet taken would otherwise keep their apps waiting.
            while not self._candidates.empty():
                await self.inspector.reject_automatic_inspection(self._candidates.get_nowait())
            self._candidates = None
        if self._listings is not None:
            self.inspector.unsubscribe_listings(self._listings)
            self._listings = None
        if self._automatic_inspection_enabled:
            self._automatic_inspection_enabled = False
            await self.inspector.set_automatic_inspection_enabled(False)

    async def _consume_candidates(self, candidates: "asyncio.Queue[AutomaticInspectionCandidate]") -> None:
        while True:
            candidate = await candidates.get()
            try:
                await self._take_candidate(candidate)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(f"failed taking automatic inspection candidate {candidate}")
                await self.inspector.reject_automatic_inspection(candidate)

    async def _take_candidate(self, candidate: AutomaticInspectionCandidate) -> None:
        """Attach to a debuggable its application is holding for us, or decline it."""
        page_id = make_target_id(candidate.app_id, str(candidate.page_id))
        self._awaiting_candidate.pop(page_id, None)
        # The application pushed its listing right before the candidate was reported, so the
        # page is already known; announce it to the client, then attach.
        await self._sync_targets(attach=False)
        if page_id not in self._known_targets:
            logger.warning(f"declining automatic inspection of {page_id}: not in the application's listing")
            await self.inspector.reject_automatic_inspection(candidate)
            return
        if not await self._auto_attach_page(page_id, waiting_for_debugger=True):
            await self.inspector.reject_automatic_inspection(candidate)

    async def _consume_listings(self, listings: "asyncio.Queue[str]") -> None:
        while True:
            await listings.get()
            # One pass covers every listing that arrived meanwhile.
            while not listings.empty():
                listings.get_nowait()
            try:
                await self._sync_targets()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("target sync failed")

    async def _send(self, message: dict[str, Any]) -> None:
        logger.debug(f"BROWSER CDP OUTPUT: {message}")
        async with self._send_lock:
            if self._trace is not None:
                self._trace.record(BRIDGE_TO_EDITOR, message, session="browser")
            await self.websocket.send_json(message)

    async def _reply(self, message: dict[str, Any], result: dict[str, Any]) -> None:
        response: dict[str, Any] = {"id": message["id"], "result": result}
        if "sessionId" in message:
            response["sessionId"] = message["sessionId"]
        await self._send(response)

    async def _handle(self, message: dict[str, Any]) -> None:
        session_id = message.get("sessionId")
        if session_id is not None and session_id not in self._browser_sessions:
            attachment = self._sessions.get(session_id)
            if attachment is None:
                if "id" in message:
                    await self._send({
                        "id": message["id"],
                        "sessionId": session_id,
                        "error": {"code": -32001, "message": f"Session with given id not found: {session_id}"},
                    })
                return
            forwarded = {k: v for k, v in message.items() if k != "sessionId"}
            if "id" in forwarded:
                # Renumber, so two sessions using the same id do not consume each other's answers.
                forwarded["id"] = attachment.claim_wire_id(session_id, forwarded["id"])
            await attachment.target.send(forwarded)
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
        params = message.get("params", {})
        self._auto_attach = bool(params.get("autoAttach"))
        wait_for_debugger = self._auto_attach and bool(params.get("waitForDebuggerOnStart"))
        if self._auto_attach:
            self._events_session = message.get("sessionId")
            # The debuggables that exist now are already running: attach them as such, before
            # new JSContexts start being left to their candidates.
            await self._refresh_targets()
            self._ensure_poll()
        self._wait_for_debugger = wait_for_debugger
        if wait_for_debugger:
            for attachment in self._attachments.values():
                await attachment.target.hold_new_targets()
            await self._start_waiting_for_new_targets()
        else:
            await self._stop_waiting_for_new_targets()
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
        attachment = self._sessions.get(session_id) if session_id else None
        if attachment is not None:
            await self._detach_session(attachment, cast(str, session_id))
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
        """Ask every application for its listing, then bring the client's target list up to date."""
        await self.inspector.get_open_pages()
        await self.inspector.flush_input(PAGE_LISTING_FLUSH)
        await self._sync_targets()

    async def _sync_targets(self, attach: bool = True) -> None:
        """Bring the client's target list in line with the listings already received: announce
        new pages, destroy gone ones and, unless `attach` is off, auto-attach the new ones."""
        async with self._refresh_lock:
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
                    "attached": page_id in self._attachments,
                    "canAccessOpener": False,
                    "browserContextId": DEFAULT_BROWSER_CONTEXT_ID,
                }
                if is_new and self._discover:
                    await self._send_event("Target.targetCreated", {"targetInfo": self._known_targets[page_id]})
                if attach and self._auto_attach and page_id not in self._attachments:
                    if self._left_to_its_candidate(page_id, page):
                        continue
                    await self._auto_attach_page(page_id)

    def _left_to_its_candidate(self, page_id: str, page: Page) -> bool:
        """Whether a listed JSContext is to be attached from its automatic-inspection candidate
        rather than from the listing - like Safari, which only ever attaches on the candidate.

        The listing lands a few milliseconds ahead of the candidate; attaching from it would
        adopt the context as running and the candidate would find it already attached, leaving
        the application waiting for a release that never comes. Give up after CANDIDATE_GRACE.
        """
        if not self._wait_for_debugger or page.type_ != WirTypes.JAVASCRIPT or page_id in HELD_TARGETS:
            return False
        now = asyncio.get_event_loop().time()
        deadline = self._awaiting_candidate.get(page_id)
        if deadline is None:
            self._awaiting_candidate[page_id] = now + CANDIDATE_GRACE
            return True
        if now < deadline:
            return True
        del self._awaiting_candidate[page_id]
        return False

    async def _destroy_target(self, page_id: str) -> None:
        self._known_targets.pop(page_id, None)
        self._awaiting_candidate.pop(page_id, None)
        attachment = self._attachments.get(page_id)
        if attachment is not None:
            await self._close_attachment(attachment, notify=True)
        if self._discover:
            await self._send_event("Target.targetDestroyed", {"targetId": page_id})

    async def _send_event(self, method: str, params: dict[str, Any]) -> None:
        event: dict[str, Any] = {"method": method, "params": params}
        if self._events_session is not None:
            event["sessionId"] = self._events_session
        await self._send(event)

    async def _auto_attach_page(self, page_id: str, waiting_for_debugger: bool = False) -> bool:
        """Attach and announce the attachment.

        :param waiting_for_debugger: The debuggable is held until the client releases it with
            Runtime.runIfWaitingForDebugger (an automatic-inspection candidate).
        :returns: Whether the page was attached.
        """
        session_id = await self._attach_page(page_id, waiting_for_debugger)
        if session_id is None:
            return False
        await self._send_event(
            "Target.attachedToTarget",
            {
                "sessionId": session_id,
                "targetInfo": self._known_targets[page_id],
                "waitingForDebugger": waiting_for_debugger,
            },
        )
        return True

    async def _attach_page(self, page_id: str, waiting_for_debugger: bool = False) -> Optional[str]:
        """Attach to a page and return the CDP sessionId of this attachment.

        Attaching to a page that is already attached opens an additional session onto the same
        target rather than handing back the existing one: a client keeps its own request ids per
        session, and giving two of them the same session id makes each receive the other's
        answers - which trips an assertion in the client and takes the whole connection down.

        :param waiting_for_debugger: The debuggable is held for us (see _auto_attach_page).
        """
        attachment = self._attachments.get(page_id)
        if attachment is not None:
            return self._open_session(attachment)
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
        held = adopt_held_target(page_id)
        if held is not None:
            # The bridge attached before the context ran and has kept it paused; the client gets
            # that session, already released, and sees the pause once its debugger is on.
            target = held
            waiting_for_debugger = False
        else:
            target = await self._create_target(page_id, application, page, waiting_for_debugger, lock)
            if target is None:
                return None
        target.waiting_for_debugger = waiting_for_debugger
        # Pause mode is for debuggables created while the client waits for new ones; the ones
        # that already existed when it enabled auto-attach (attached before _wait_for_debugger
        # is set) are running and stay that way.
        target.pause_on_start = self._pause_on_start and self._wait_for_debugger
        if self._wait_for_debugger:
            await target.hold_new_targets()
        attachment = _PageAttachment(page_id, target, lock)
        attachment.pump = asyncio.create_task(self._pump(attachment))
        self._attachments[page_id] = attachment
        if page_id in self._known_targets:
            self._known_targets[page_id]["attached"] = True
        return self._open_session(attachment)

    async def _create_target(
        self, page_id: str, application: Application, page: Page, waiting_for_debugger: bool, lock: asyncio.Lock
    ) -> Optional[CdpTarget]:
        """Set up a fresh inspector session on a page. Releases `lock` and returns None if the
        device never reports the target."""
        wir_session_id = str(uuid.uuid4()).upper()
        protocol = SessionProtocol(self.inspector, wir_session_id, application, page, method_prefix="")
        try:
            # A held debuggable is paused by WebKit itself on release when asked to; anything
            # else the bridge pauses once its debugger is enabled (see CdpTarget.pause_on_start).
            return await asyncio.wait_for(
                CdpTarget.create(protocol, automatically_pause=waiting_for_debugger and self._pause_on_start),
                TARGET_CREATION_TIMEOUT,
            )
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

    def _open_session(self, attachment: _PageAttachment) -> str:
        """Register one more CDP session onto an attached page."""
        session_id = str(uuid.uuid4()).upper()
        attachment.session_ids.append(session_id)
        self._sessions[session_id] = attachment
        return session_id

    async def _pump(self, attachment: _PageAttachment) -> None:
        """Forward what the page target emits to the session it belongs to.

        An answer goes back to the session that asked, under the id it used; an event is not tied
        to a request, so - as a real backend does - it is reported to every session attached to
        the page.
        """
        while True:
            message = await attachment.target.receive()
            claimed = attachment.pending.pop(message["id"], None) if "id" in message else None
            if claimed is not None:
                session_id, original_id = claimed
                message["id"] = original_id
                message["sessionId"] = session_id
                await self._send(message)
                continue
            if "id" in message:
                # An answer to something this bridge asked on its own behalf, or to a request of a
                # session that has since gone away; there is nobody to hand it to.
                continue
            for session_id in list(attachment.session_ids):
                await self._send({**message, "sessionId": session_id})

    async def _detach_session(self, attachment: _PageAttachment, session_id: str) -> None:
        """Drop one session; the page stays attached while any other session still holds it."""
        self._sessions.pop(session_id, None)
        if session_id in attachment.session_ids:
            attachment.session_ids.remove(session_id)
        for wire_id, (owner, _) in list(attachment.pending.items()):
            if owner == session_id:
                del attachment.pending[wire_id]
        if not attachment.session_ids:
            await self._close_attachment(attachment, notify=False)

    async def _close_attachment(self, attachment: _PageAttachment, notify: bool) -> None:
        """Tear the page's target down and end every session attached to it."""
        self._attachments.pop(attachment.page_id, None)
        sessions = list(attachment.session_ids)
        attachment.session_ids.clear()
        for session_id in sessions:
            self._sessions.pop(session_id, None)
        if attachment.page_id in self._known_targets:
            self._known_targets[attachment.page_id]["attached"] = False
        if attachment.pump is not None:
            attachment.pump.cancel()
            await asyncio.gather(attachment.pump, return_exceptions=True)
        try:
            await attachment.target.close()
        finally:
            attachment.lock.release()
        if notify:
            for session_id in sessions:
                await self._send_event(
                    "Target.detachedFromTarget",
                    {"sessionId": session_id, "targetId": attachment.page_id},
                )


class HeldTargets:
    """The bridge's own automatic-inspection debugger: `cdp --pause-new-targets` for frontends
    that cannot be attached before a debuggable exists - DevTools opened from the landing page.

    What Safari does with both Develop-menu options on: every JSContext (or service worker) an
    application creates is accepted before it runs, its session initialized so WebKit stops it on
    its first statement, and the session kept - listed as paused - until a frontend opens it and
    adopts the session (see adopt_held_target), finding it paused where it was stopped. The
    application itself resumes right away, blocked only for the milliseconds the setup takes.
    """

    def __init__(self, inspector: WebinspectorService) -> None:
        self.inspector = inspector
        self._candidates: Optional[asyncio.Queue[AutomaticInspectionCandidate]] = None
        self._listings: Optional[asyncio.Queue[str]] = None
        self._tasks: list[asyncio.Task[None]] = []

    @property
    def running(self) -> bool:
        return self._candidates is not None

    async def start(self) -> None:
        if self.running:
            return
        self._candidates = self.inspector.subscribe_automatic_inspection()
        self._listings = self.inspector.subscribe_listings()
        self._tasks = [
            asyncio.create_task(self._consume_candidates(self._candidates)),
            asyncio.create_task(self._consume_listings(self._listings)),
        ]
        await self.inspector.set_automatic_inspection_enabled(True)

    async def stop(self) -> None:
        """Let go of every held session and stop being offered new ones."""
        if not self.running:
            return
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        if self._candidates is not None:
            self.inspector.unsubscribe_automatic_inspection(self._candidates)
            while not self._candidates.empty():
                await self.inspector.reject_automatic_inspection(self._candidates.get_nowait())
            self._candidates = None
        if self._listings is not None:
            self.inspector.unsubscribe_listings(self._listings)
            self._listings = None
        for page_id in list(HELD_TARGETS):
            await self._drop(page_id)
        await self.inspector.set_automatic_inspection_enabled(False)

    async def _consume_candidates(self, candidates: "asyncio.Queue[AutomaticInspectionCandidate]") -> None:
        while True:
            candidate = await candidates.get()
            try:
                await self._hold(candidate)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(f"failed holding automatic inspection candidate {candidate}")
                await self.inspector.reject_automatic_inspection(candidate)

    async def _hold(self, candidate: AutomaticInspectionCandidate) -> None:
        page_id = make_target_id(candidate.app_id, str(candidate.page_id))
        try:
            application, page = self.inspector.find_page_id(page_id)
        except KeyError:
            logger.warning(f"declining automatic inspection of {page_id}: not in the application's listing")
            await self.inspector.reject_automatic_inspection(candidate)
            return
        lock = PAGE_LOCKS.setdefault(page_id, asyncio.Lock())
        if page.type_ not in INSPECTABLE_TYPES or lock.locked() or page_id in HELD_TARGETS:
            await self.inspector.reject_automatic_inspection(candidate)
            return
        # Held only while the session is set up: a frontend adopting the session takes the lock
        # for itself the usual way, and finds the session in HELD_TARGETS once it has it.
        async with lock:
            protocol = SessionProtocol(self.inspector, str(uuid.uuid4()).upper(), application, page, method_prefix="")
            try:
                target = await asyncio.wait_for(
                    CdpTarget.create(protocol, automatically_pause=True), TARGET_CREATION_TIMEOUT
                )
            except (asyncio.TimeoutError, TimeoutError):
                logger.error(f"page {page_id}: device did not report an inspection target in time")
                await self.inspector.teardown_inspector_socket(protocol.id_, application.id_, page.id_)
                await self.inspector.reject_automatic_inspection(candidate)
                return
            target.waiting_for_debugger = True
            target.pause_on_start = True
            target.start_holding()
            # The debugger must be on for the pause to land; then let the application go - WebKit
            # stops the context on its first statement (the socket was set up to pause).
            await target.enable_debugger()
            await target.release_debugger()
            HELD_TARGETS[page_id] = target
        logger.info(f"holding {page_id} paused on its first statement")

    async def _consume_listings(self, listings: "asyncio.Queue[str]") -> None:
        while True:
            await listings.get()
            while not listings.empty():
                listings.get_nowait()
            listed = {page_id for page_id, _, _ in iter_inspectable(self.inspector)}
            for page_id in [held for held in HELD_TARGETS if held not in listed]:
                # The context went away (its process exited) with nobody ever having opened it.
                await self._drop(page_id)

    async def _drop(self, page_id: str) -> None:
        target = HELD_TARGETS.pop(page_id, None)
        if target is not None:
            await target.close()
