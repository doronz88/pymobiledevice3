import asyncio
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket
from fastapi.logger import logger

from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.web_protocol.session_protocol import SessionProtocol
from pymobiledevice3.services.webinspector import WirTypes


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.inspector.connect()
    yield


app = FastAPI(lifespan=lifespan)


@app.get('/json{_:path}')
async def available_targets(_: str):
    app.state.inspector.get_open_pages()
    targets = []
    for app_id in app.state.inspector.application_pages:
        for page_id, page in app.state.inspector.application_pages[app_id].items():
            if page.type_ not in (WirTypes.WEB, WirTypes.WEB_PAGE):
                continue
            targets.append({
                'description': '',
                'id': page_id,
                'title': page.web_title,
                'type': 'page',
                'url': page.web_url,
                'webSocketDebuggerUrl': f'ws://localhost:9222/devtools/page/{page_id}',
                'devtoolsFrontendUrl': f'/devtools/inspector.html?ws://localhost:9222/devtools/page/{page_id}',
            })
    return targets


@app.get('/json/version')
def version():
    return {
        'Browser': 'Safari',
        'Protocol-Version': '1.1',
        'User-Agent': 'pymobiledevice3',
        'V8-Version': '7.2.233',
        'WebKit-Version': '537.36 (@cfede9db1d154de0468cb0538479f34c0755a0f4)',
        'webSocketDebuggerUrl': f'ws://localhost:9222/devtools/browser/{app.state.inspector.connection_id}'
    }


async def from_cdp(target: CdpTarget, websocket):
    async for message in websocket.iter_json():
        logger.debug(f'CDP INPUT:  {message}')
        await target.send(message)


async def to_cdp(target: CdpTarget, websocket):
    while True:
        message = await target.receive()
        logger.debug(f'CDP OUTPUT:  {message}')
        await websocket.send_json(message)


@app.websocket('/devtools/page/{page_id}')
async def page_debugger(websocket: WebSocket, page_id: str):
    application, page = app.state.inspector.find_page_id(page_id)
    session_id = str(uuid.uuid4()).upper()
    protocol = SessionProtocol(app.state.inspector, session_id, application, page, method_prefix='')
    target = await CdpTarget.create(protocol)
    await websocket.accept()
    await asyncio.gather(
        from_cdp(target, websocket),
        to_cdp(target, websocket),
    )
