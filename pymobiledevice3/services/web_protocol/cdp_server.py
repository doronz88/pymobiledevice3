import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, WebSocket
from fastapi.logger import logger

from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import WirTypes

# Seconds to let webinspectord reply with the updated page listings before answering /json
PAGE_LISTING_FLUSH = 0.5
# Seconds to wait for the device to report the inspection target of a new debugger session
TARGET_CREATION_TIMEOUT = 30


@asynccontextmanager
async def lifespan(app: FastAPI):
    await app.state.inspector.connect()
    yield


app = FastAPI(lifespan=lifespan)


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


async def from_cdp(target: CdpTarget, websocket: WebSocket) -> None:
    async for message in websocket.iter_json():
        logger.debug(f"CDP INPUT:  {message}")
        await target.send(message)


async def to_cdp(target: CdpTarget, websocket: WebSocket) -> None:
    while True:
        message = await target.receive()
        logger.debug(f"CDP OUTPUT:  {message}")
        await websocket.send_json(message)


# WebKit supports a single inspector session per page, so sessions are serialized per page:
# a new debugger connection waits until the previous session's WIR socket teardown completed
# (otherwise its socket setup races the teardown and webinspectord ignores it).
_page_locks: dict[str, asyncio.Lock] = {}


@app.websocket("/devtools/page/{page_id}")
async def page_debugger(websocket: WebSocket, page_id: str):
    application, page = app.state.inspector.find_page_id(page_id)
    session_id = str(uuid.uuid4()).upper()
    protocol = SessionProtocol(app.state.inspector, session_id, application, page, method_prefix="")
    # Accept before the device-side target setup: DevTools drops the connection if the
    # websocket handshake stalls behind the WIR socket establishment.
    await websocket.accept()
    async with _page_locks.setdefault(page_id, asyncio.Lock()):
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
