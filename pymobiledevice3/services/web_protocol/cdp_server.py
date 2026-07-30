import asyncio
import shutil
import subprocess
import sys
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional
from urllib.request import urlopen

from fastapi import FastAPI, Request, WebSocket
from fastapi.logger import logger
from fastapi.responses import HTMLResponse, Response

from pymobiledevice3.services.web_protocol.cdp_browser import (
    PAGE_LISTING_FLUSH,
    PAGE_LOCKS,
    TARGET_CREATION_TIMEOUT,
    CdpBrowser,
)
from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import WirTypes

# chrome://inspect routes a network target's DevTools through Chrome's browser-process relay,
# which deadlocks after sustained console traffic (the console/screen freeze). Serving the DevTools
# frontend here - opened as an ordinary http page - makes it connect straight to the bridge's
# WebSocket, bypassing that relay entirely. The frontend is proxied (not bundled): from the
# officially hosted build (pinned to a revision compatible with the WIR<->CDP translation) when it
# is reachable, otherwise from a locally installed Chrome, which serves its own bundled frontend.
DEVTOOLS_FRONTEND_REV = "0fcdce5f4fdec8d442d7df760cb541f1ca6e446d"
DEVTOOLS_FRONTEND_HOST = "chrome-devtools-frontend.appspot.com"
_frontend_cache: dict[str, tuple[bytes, str]] = {}

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.frontend_lock = asyncio.Lock()
    await app.state.inspector.connect()
    yield
    proc: Optional[subprocess.Popen[bytes]] = getattr(app.state, "local_chrome_proc", None)
    if proc is not None:
        proc.terminate()
    profile: Optional[str] = getattr(app.state, "local_chrome_profile", None)
    if profile:
        shutil.rmtree(profile, ignore_errors=True)


app = FastAPI(lifespan=lifespan)


async def _fetch(url: str) -> Optional[tuple[bytes, str]]:
    """Fetch a frontend asset off the event loop; None on any failure."""

    def _get() -> tuple[bytes, str]:
        with urlopen(url, timeout=20) as response:
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
    """Base URL to serve the DevTools frontend from, decided once per run: the hosted build when
    reachable, otherwise a locally launched Chrome. None if neither is available."""
    base = getattr(app.state, "frontend_base", None)
    if base is not None:
        return base or None
    async with app.state.frontend_lock:
        base = getattr(app.state, "frontend_base", None)
        if base is not None:
            return base or None
        rev = getattr(app.state, "frontend_rev", DEVTOOLS_FRONTEND_REV)
        hosted = f"https://{DEVTOOLS_FRONTEND_HOST}/serve_rev/@{rev}"
        if await _fetch(f"{hosted}/inspector.html") is not None:
            app.state.frontend_base = hosted
        else:
            local = await _launch_local_frontend()
            app.state.frontend_base = f"{local}/devtools" if local else ""
            if local:
                logger.info("serving the DevTools frontend from a local Chrome (hosted build unreachable)")
        return app.state.frontend_base or None


@app.get("/json/version")
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


@app.get("/json{_:path}")
async def available_targets(request: Request, _: str):
    await app.state.inspector.get_open_pages()
    await app.state.inspector.flush_input(PAGE_LISTING_FLUSH)
    host = request.headers.get("host", "localhost:9222")
    targets: list[dict[str, Any]] = []
    for app_id in app.state.inspector.application_pages:
        for page_id, page in app.state.inspector.application_pages[app_id].items():
            if page.type_ not in (WirTypes.WEB, WirTypes.WEB_PAGE):
                continue
            targets.append({
                "description": "",
                "id": page_id,
                "title": page.web_title,
                "type": "page",
                "url": page.web_url,
                "webSocketDebuggerUrl": f"ws://{host}/devtools/page/{page_id}",
                "devtoolsFrontendUrl": f"/devtools/inspector.html?ws={host}/devtools/page/{page_id}",
            })
    return targets


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Landing page: link each inspectable page to the locally-served DevTools frontend, which
    connects directly to the bridge (bypassing chrome://inspect's relay). Use this instead of
    chrome://inspect to avoid the console/screen freeze."""
    await app.state.inspector.get_open_pages()
    await app.state.inspector.flush_input(PAGE_LISTING_FLUSH)
    host = request.headers.get("host", "127.0.0.1:9222")
    items: list[str] = []
    for app_id in app.state.inspector.application_pages:
        for page_id, page in app.state.inspector.application_pages[app_id].items():
            if page.type_ not in (WirTypes.WEB, WirTypes.WEB_PAGE):
                continue
            frontend = f"/devtools/inspector.html?ws={host}/devtools/page/{page_id}"
            title = page.web_title or page.web_url or f"page {page_id}"
            items.append(f'<li><a href="{frontend}">{title}</a><br><small>{page.web_url}</small></li>')
    body = "<ul>" + "".join(items) + "</ul>" if items else "<p>No inspectable pages. Open a page in Safari.</p>"
    return HTMLResponse(
        f"<!doctype html><meta charset=utf-8><title>pymobiledevice3 Web Inspector</title>"
        f"<h2>pymobiledevice3 Web Inspector</h2>{body}"
    )


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
    application, page = app.state.inspector.find_page_id(page_id)
    session_id = str(uuid.uuid4()).upper()
    protocol = SessionProtocol(app.state.inspector, session_id, application, page, method_prefix="")
    # Accept before the device-side target setup: DevTools drops the connection if the
    # websocket handshake stalls behind the WIR socket establishment.
    await websocket.accept()
    async with PAGE_LOCKS.setdefault(page_id, asyncio.Lock()):
        try:
            # Bound the wait: if the device never reports the target (e.g. webinspectord is in a
            # bad state), fail the connection instead of keeping a zombie handler alive forever.
            target = await asyncio.wait_for(CdpTarget.create(protocol), TARGET_CREATION_TIMEOUT)
        except (asyncio.TimeoutError, TimeoutError):
            logger.error(f"page {page_id}: device did not report an inspection target in time")
            await app.state.inspector.teardown_inspector_socket(session_id, application.id_, page.id_)
            await websocket.close()
            return
        tasks: list[asyncio.Task[None]] = [
            asyncio.create_task(from_cdp(target, websocket)),
            asyncio.create_task(to_cdp(target, websocket)),
        ]
        try:
            # from_cdp ends when the client disconnects; tear everything down so the target's
            # queue-consumer tasks don't keep draining wir_events of future sessions.
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await target.close()
