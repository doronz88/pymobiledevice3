import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from contextlib import asynccontextmanager
from html import escape
from ipaddress import ip_address
from pathlib import Path
from string import Template
from typing import Any, Optional
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener, urlopen

from fastapi import FastAPI, Request, WebSocket
from fastapi.logger import logger
from fastapi.responses import HTMLResponse, Response

from pymobiledevice3.services.web_protocol.cdp_browser import (
    PAGE_HANDOVER_TIMEOUT,
    PAGE_LOCKS,
    PAGE_TAKEOVERS,
    TARGET_CREATION_TIMEOUT,
    CdpBrowser,
    iter_inspectable,
    target_title,
    target_type,
)
from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import Page, WebinspectorService, WirTypes

# chrome://inspect routes a network target's DevTools through Chrome's browser-process relay,
# which deadlocks after sustained console traffic (the console/screen freeze). Serving the DevTools
# frontend here - opened as an ordinary http page - makes it connect straight to the bridge's
# WebSocket, bypassing that relay entirely. The frontend is proxied (not bundled): from the
# officially hosted build (pinned to a revision compatible with the WIR<->CDP translation) when it
# is reachable, otherwise from a locally installed Chrome, which serves its own bundled frontend.
DEVTOOLS_FRONTEND_REV = "0fcdce5f4fdec8d442d7df760cb541f1ca6e446d"
DEVTOOLS_FRONTEND_HOST = "chrome-devtools-frontend.appspot.com"
_frontend_cache: dict[str, tuple[bytes, str]] = {}

# The local Chrome's assets must be fetched without a proxy. urllib applies proxy configuration
# to loopback addresses as well - neither the no_proxy/ExceptionsList defaults nor macOS'
# "exclude simple hostnames" cover 127.0.0.1 - so on a proxied network every asset request for
# the fallback frontend would be sent to the proxy and come back empty, leaving a blank DevTools
# window. Browsers bypass loopback implicitly; this opener does the same.
_DIRECT_OPENER = build_opener(ProxyHandler({}))

# Names/locations for the Chrome/Chromium binary used for the offline frontend fallback.
_CHROME_BINARY_NAMES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    "chrome.exe",
)
_CHROME_DEFAULT_PATHS: dict[str, tuple[str, ...]] = {
    "darwin": (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ),
    "win32": (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ),
    "linux": (
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ),
}


NO_TARGETS_MESSAGE = "No inspectable pages. Open a page in Safari."
NO_TARGETS_MESSAGE_HTML = f"<p>{NO_TARGETS_MESSAGE}</p>"

# How often the landing page re-reads the target list. Serving one is a read of already-pushed
# state (see refresh_listings), so this can be short enough that a tab opened or closed on the
# device shows up about as fast as it does in Safari's own Develop menu. The page still stops
# polling while it is not the visible tab.
INDEX_POLL_INTERVAL_MS = 750

INDEX_SCRIPT = Template("""
(function () {
  const container = document.getElementById('targets');
  let rendered = null;
  function render(targets) {
    container.textContent = '';
    if (!targets.length) {
      const empty = document.createElement('p');
      empty.textContent = $empty;
      container.appendChild(empty);
      return;
    }
    const list = document.createElement('ul');
    for (const target of targets) {
      const link = document.createElement('a');
      link.href = target.devtoolsFrontendUrl;
      link.textContent = target.title || target.url || ('page ' + target.id);
      const url = document.createElement('small');
      url.textContent = target.url;
      const item = document.createElement('li');
      item.append(link, document.createElement('br'), url);
      list.appendChild(item);
    }
    container.appendChild(list);
  }
  async function poll() {
    if (!document.hidden) {
      try {
        const targets = await (await fetch('/json/list', {cache: 'no-store'})).json();
        const serialized = JSON.stringify(targets);
        if (serialized !== rendered) {
          rendered = serialized;
          render(targets);
        }
      } catch (error) {
        // The bridge is momentarily busy or gone; leave the list as it is and try again.
      }
    }
    setTimeout(poll, $interval);
  }
  setTimeout(poll, $interval);
})();
""").substitute(empty=json.dumps(NO_TARGETS_MESSAGE), interval=INDEX_POLL_INTERVAL_MS)


def find_chrome(explicit: Optional[str] = None) -> Optional[str]:
    """Locate a Chrome/Chromium binary for the offline frontend fallback: an explicit path, then
    the PATH, then the running platform's known install locations. Returns None if none is found."""
    if explicit:
        return explicit if Path(explicit).exists() else None
    for name in _CHROME_BINARY_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for candidate in _CHROME_DEFAULT_PATHS.get(sys.platform, ()):
        if Path(candidate).exists():
            return candidate
    return None


def _reap_local_frontend() -> None:
    """Tear down the fallback Chrome and its throwaway profile, if one is running."""
    proc: Optional[subprocess.Popen[bytes]] = getattr(app.state, "local_chrome_proc", None)
    if proc is not None:
        proc.terminate()
        app.state.local_chrome_proc = None
    profile: Optional[str] = getattr(app.state, "local_chrome_profile", None)
    if profile:
        shutil.rmtree(profile, ignore_errors=True)
        app.state.local_chrome_profile = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.frontend_lock = asyncio.Lock()
    # Per-page state belongs to one run of the bridge. An asyncio primitive binds to the event loop
    # that created it, and a page handler killed without unwinding - a forced shutdown, a loop torn
    # down under it - leaves its lock held. Either one carried into a later run in the same process
    # (a second asyncio.run, a test) wedges every connection to that page: it waits out
    # PAGE_HANDOVER_TIMEOUT for a lock nobody is left to release, then fails outright because the
    # lock belongs to a loop that is gone.
    PAGE_LOCKS.clear()
    PAGE_TAKEOVERS.clear()
    await app.state.inspector.connect()
    yield
    _reap_local_frontend()


app = FastAPI(lifespan=lifespan)


def _is_loopback(url: str) -> bool:
    """Whether url addresses this machine, and so must be fetched without going through a proxy."""
    host = urlsplit(url).hostname or ""
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(".localhost")


async def _fetch(url: str) -> Optional[tuple[bytes, str]]:
    """Fetch a frontend asset off the event loop; None on any failure."""

    def _get() -> tuple[bytes, str]:
        # Anything on this machine - the fallback Chrome - is fetched directly; see _DIRECT_OPENER.
        opener = _DIRECT_OPENER.open if _is_loopback(url) else urlopen
        with opener(url, timeout=20) as response:
            return response.read(), response.headers.get_content_type()

    try:
        return await asyncio.get_event_loop().run_in_executor(None, _get)
    except Exception:
        return None


async def _launch_local_frontend() -> Optional[str]:
    """Start a throwaway headless Chrome that serves its own bundled DevTools frontend over http and
    return its origin. Used only when the hosted build is unreachable."""
    chrome = getattr(app.state, "chrome_path", None)
    if not chrome:
        logger.error(
            "DevTools frontend unavailable: the hosted build is unreachable and no Chrome binary "
            "was found. Install Chrome/Chromium or pass --chrome <path>."
        )
        return None
    _reap_local_frontend()
    profile = tempfile.mkdtemp(prefix="pmd3-devtools-frontend-")
    app.state.local_chrome_profile = profile
    app.state.local_chrome_proc = subprocess.Popen(
        [
            chrome,
            "--headless=new",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    port_file = Path(profile) / "DevToolsActivePort"
    for _ in range(80):
        if port_file.exists():
            try:
                return f"http://127.0.0.1:{int(port_file.read_text().splitlines()[0])}"
            except (ValueError, IndexError):
                return None
        await asyncio.sleep(0.1)
    logger.error("local Chrome did not expose a debugging port in time")
    return None


async def _frontend_base() -> Optional[str]:
    """Base URL to serve the DevTools frontend from: the hosted build when reachable, otherwise a
    locally launched Chrome. Resolved once per run and kept, but a failure is deliberately not
    remembered - the causes are transient (a network that comes back, a Chrome that lost the race
    to publish its port), and remembering one served 404s, and so a blank DevTools window, for the
    rest of the session."""
    base = getattr(app.state, "frontend_base", None)
    if base:
        return base
    async with app.state.frontend_lock:
        base = getattr(app.state, "frontend_base", None)
        if base:
            return base
        rev = getattr(app.state, "frontend_rev", DEVTOOLS_FRONTEND_REV)
        hosted = f"https://{DEVTOOLS_FRONTEND_HOST}/serve_rev/@{rev}"
        if await _fetch(f"{hosted}/inspector.html") is not None:
            app.state.frontend_base = hosted
        else:
            local = await _launch_local_frontend()
            app.state.frontend_base = f"{local}/devtools" if local else None
            if local:
                logger.info("serving the DevTools frontend from a local Chrome (hosted build unreachable)")
        return app.state.frontend_base


# Both spellings: Chrome's DevTools HTTP endpoint answers /json/version and /json/version/
# identically, and Playwright's connectOverCDP fetches the trailing-slash form. Without the second
# route it falls through to the /json catch-all below and gets the target list (no
# webSocketDebuggerUrl), so connectOverCDP fails with "Invalid URL: undefined".
@app.get("/json/version")
@app.get("/json/version/")
def version(request: Request):
    host = request.headers.get("host", "localhost:9222")
    return {
        "Browser": "Safari",
        "Protocol-Version": "1.1",
        "User-Agent": "pymobiledevice3",
        "V8-Version": "7.2.233",
        "WebKit-Version": "537.36 (@cfede9db1d154de0468cb0538479f34c0755a0f4)",
        "webSocketDebuggerUrl": f"ws://{host}/devtools/browser/{app.state.inspector.connection_id}",
    }


async def refresh_listings() -> None:
    """Ask every connected application to re-report its pages, without waiting for the replies.

    `webinspectord` pushes a fresh listing on its own whenever a page opens, closes or navigates,
    so the cached state is already live and the answer can be built from it straight away; the
    request is only a nudge for anything that does not announce itself. Blocking on the replies
    instead put a fixed half-second on every listing request - the whole cost of serving one.
    """
    await app.state.inspector.get_open_pages()


@app.get("/json{_:path}")
async def available_targets(request: Request, _: str):
    await refresh_listings()
    host = request.headers.get("host", "localhost:9222")
    targets: list[dict[str, Any]] = []
    for target_id, application, page in iter_inspectable(app.state.inspector):
        targets.append({
            "description": "",
            "id": target_id,
            "title": target_title(application, page),
            "type": target_type(page),
            "url": page.web_url,
            "webSocketDebuggerUrl": f"ws://{host}/devtools/page/{target_id}",
            "devtoolsFrontendUrl": f"{_frontend_url(page)}?ws={host}/devtools/page/{target_id}",
        })
    return targets


def _frontend_url(page: Page) -> str:
    """DevTools frontend entry point for a debuggable. A JSContext gets Chrome's JavaScript-only
    entry point (the one it uses for Node.js); inspector.html would come up expecting the Page/DOM
    domains that JavaScriptCore's inspector does not implement."""
    return "/devtools/js_app.html" if page.type_ == WirTypes.JAVASCRIPT else "/devtools/inspector.html"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Landing page: link each inspectable page to the locally-served DevTools frontend, which
    connects directly to the bridge (bypassing chrome://inspect's relay). Use this instead of
    chrome://inspect to avoid the console/screen freeze.

    The listing keeps itself current, so a tab opened - or a JSContext made inspectable - after
    the page was loaded appears without reloading it by hand."""
    await refresh_listings()
    host = request.headers.get("host", "127.0.0.1:9222")
    return HTMLResponse(
        f"<!doctype html><meta charset=utf-8><title>pymobiledevice3 Web Inspector</title>"
        f"<h2>pymobiledevice3 Web Inspector</h2>"
        # Rendered server-side once so the list is there before any script runs, then kept up to
        # date in place by INDEX_SCRIPT.
        f'<div id="targets">{targets_html(app.state.inspector, host)}</div>'
        f"<script>{INDEX_SCRIPT}</script>"
    )


def targets_html(inspector: WebinspectorService, host: str) -> str:
    """The landing page's target list. Titles and URLs come from the device, so they are escaped."""
    items: list[str] = []
    for target_id, application, page in iter_inspectable(inspector):
        frontend = f"{_frontend_url(page)}?ws={host}/devtools/page/{target_id}"
        title = target_title(application, page) or page.web_url or f"page {target_id}"
        items.append(
            f'<li><a href="{escape(frontend)}">{escape(title)}</a><br><small>{escape(page.web_url)}</small></li>'
        )
    if not items:
        return NO_TARGETS_MESSAGE_HTML
    return "<ul>" + "".join(items) + "</ul>"


@app.get("/devtools/{path:path}")
async def devtools_frontend(path: str) -> Response:
    """Serve the DevTools frontend so it connects to the bridge's WebSocket directly instead of
    through chrome://inspect's relay. Assets are proxied - from the hosted build, or from a local
    Chrome when that is unreachable - and cached per run."""
    if path not in _frontend_cache:
        base = await _frontend_base()
        if base is None:
            return Response(status_code=404)
        result = await _fetch(f"{base}/{path}")
        if result is None:
            return Response(status_code=404)
        _frontend_cache[path] = result
    data, content_type = _frontend_cache[path]
    return Response(content=data, media_type=content_type)


async def from_cdp(target: CdpTarget, websocket: WebSocket) -> None:
    async for message in websocket.iter_json():
        logger.debug(f"CDP INPUT:  {message}")
        await target.send(message)


async def to_cdp(target: CdpTarget, websocket: WebSocket) -> None:
    while True:
        message = await target.receive()
        logger.debug(f"CDP OUTPUT:  {message}")
        await websocket.send_json(message)


@app.websocket("/devtools/browser/{connection_id}")
async def browser_debugger(websocket: WebSocket, connection_id: str):
    """Browser-level endpoint (the one /json/version advertises): flat-session Target-domain
    debugging for Chrome-compatible clients such as VS Code's js-debug and Puppeteer."""
    await websocket.accept()
    browser = CdpBrowser(app.state.inspector, websocket)
    try:
        await browser.run()
    finally:
        await browser.close()


@app.websocket("/devtools/page/{page_id}")
async def page_debugger(websocket: WebSocket, page_id: str):
    try:
        application, page = app.state.inspector.find_page_id(page_id)
    except KeyError:
        # The page closed on the device between being listed and being opened here - a link the
        # user had on screen a moment too long. Refuse the connection instead of erroring out.
        logger.warning(f"page {page_id} is no longer inspectable")
        await websocket.close()
        return
    session_id = str(uuid.uuid4()).upper()
    protocol = SessionProtocol(app.state.inspector, session_id, application, page, method_prefix="")
    # Accept before the device-side target setup: DevTools drops the connection if the
    # websocket handshake stalls behind the WIR socket establishment.
    await websocket.accept()
    # WebKit serves one inspector session per debuggable, so sessions are serialized per page.
    # Ask whoever holds this one to hand it over: a DevTools tab left attached (in a background
    # tab, another window, a frontend the user never closed) holds the page for as long as it
    # lives, and waiting it out behind PAGE_LOCKS is invisible to the newcomer - its websocket is
    # already accepted, so the frontend just comes up blank and swallows everything typed into it.
    # Most visible on JSContexts, whose debuggable outlives every page that ever inspected it.
    superseded = PAGE_TAKEOVERS.get(page_id)
    if superseded is not None:
        logger.info(f"page {page_id}: taking the page over from the session holding it")
        superseded.set()
    # The lock is still taken, so the old session's WIR teardown completes before this one's
    # socket setup (webinspectord ignores a setup that races a teardown). Only the session holding
    # the page when this one arrived is asked to step aside - connections that are merely queued
    # here alongside it are left to run in turn, so a burst of them still all get served.
    lock = PAGE_LOCKS.setdefault(page_id, asyncio.Lock())
    try:
        await asyncio.wait_for(lock.acquire(), PAGE_HANDOVER_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        logger.error(f"page {page_id}: the session holding it did not release it in time")
        await websocket.close()
        return
    taken_over = asyncio.Event()
    PAGE_TAKEOVERS[page_id] = taken_over
    try:
        try:
            # Bound the wait: if the device never reports the target (e.g. webinspectord is in a
            # bad state), fail the connection instead of keeping a zombie handler alive forever.
            target = await asyncio.wait_for(CdpTarget.create(protocol), TARGET_CREATION_TIMEOUT)
        except (asyncio.TimeoutError, TimeoutError):
            # A page already being debugged over another Web Inspector connection - a second
            # pymobiledevice3, Safari's own Web Inspector, or a client that exited without
            # detaching - never reports a target, and the listing says who holds it. Naming them
            # beats "the device did not answer", which sends people looking at the device.
            holder = page.web_connection_id
            if holder and holder != app.state.inspector.connection_id:
                logger.error(
                    f"page {page_id}: already being debugged over Web Inspector connection {holder}; "
                    "close that debugger, or the process that left it attached, and reconnect"
                )
            else:
                logger.error(f"page {page_id}: device did not report an inspection target in time")
            await app.state.inspector.teardown_inspector_socket(session_id, application.id_, page.id_)
            await websocket.close()
            return
        tasks: list[asyncio.Task[Any]] = [
            asyncio.create_task(from_cdp(target, websocket)),
            asyncio.create_task(to_cdp(target, websocket)),
            asyncio.create_task(taken_over.wait()),
        ]
        try:
            # from_cdp ends when the client disconnects, taken_over when a newer connection claims
            # the page; tear everything down so the target's queue-consumer tasks don't keep
            # draining wir_events of future sessions.
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await target.close()
            if taken_over.is_set():
                # Close rather than leave it hanging: the superseded frontend shows a disconnect
                # instead of silently going dead.
                await websocket.close()
    finally:
        if PAGE_TAKEOVERS.get(page_id) is taken_over:
            del PAGE_TAKEOVERS[page_id]
        lock.release()
