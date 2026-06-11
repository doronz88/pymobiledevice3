"""
MJPEG variant of the screen-stream server.

Pipeline::

    device → DisplayService.start_video_stream() → UDP RTP/HEVC packets
    → asyncio UDP receive → RFC 7798 RTP/HEVC depacketize → Annex-B AU
    → ffmpeg subprocess (HW HEVC decode via VideoToolbox, MJPEG encode)
    → JPEG-per-frame broadcast over HTTP multipart/x-mixed-replace
    → browser <img src="/stream.mjpg"> -- the browser's native renderer
      handles the rest, no WebCodecs / canvas / decoder state involved.

Why have this alongside the WebCodecs path:
    The WebCodecs HEVC decoder silently accumulates long-term-reference-
    picture state under heavy motion and starts rendering torn frames
    without firing any error -- the only consistent recovery is a full
    page reload. The MJPEG path avoids the issue entirely because every
    frame is a complete, self-contained image. Trade-off: ~5-10x
    bandwidth (localhost = fine, LAN = OK, WAN = painful) and ~5-10x
    host CPU (VT decode + MJPEG encode every frame -- VT does the
    expensive part on hardware).

This is intentionally a thinner server than :class:`ScreenStreamServer`:
no audio, no /restart, no eager_stream_start. Just video + HID input,
to make A/B-comparing the two paths straightforward. If the MJPEG path
turns out to be the one we keep, audio + the polish can be ported over.
"""

import asyncio
import contextlib
import json
import logging
import socket
import uuid
from typing import Optional

from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.hevc_phantom import build_phantoms_for_bootstrap
from pymobiledevice3.remote.core_device.hid_service import (
    DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
    HID_BUTTON_STATE_DOWN,
    HID_BUTTON_STATE_UP,
    TOUCHSCREEN_STATE_CONTACT,
    TOUCHSCREEN_STATE_RELEASE,
    IndigoHIDService,
    UniversalHIDServiceService,
)
from pymobiledevice3.remote.core_device.screen_stream import depacketize_hevc
from pymobiledevice3.remote.core_device.vt_jpeg import HevcToJpegTranscoder
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

logger = logging.getLogger(__name__)

_NAMED_BUTTONS: dict[str, tuple[int, int]] = {
    "home": (0x0C, 0x40),
    "power": (0x0C, 0x30),
    "lock": (0x0C, 0x30),
    "sleep": (0x0C, 0x32),
    "volume-up": (0x0C, 0xE9),
    "volume-down": (0x0C, 0xEA),
    "mute": (0x0C, 0xE2),
    "siri": (0x0C, 0xCF),
}

_HEVC_NAL_IDR_W_RADL = 19
_HEVC_NAL_IDR_N_LP = 20
_HEVC_NAL_CRA = 21
_HEVC_NAL_VPS = 32
_HEVC_NAL_SPS = 33
_HEVC_NAL_PPS = 34
_MJPEG_BOUNDARY = "frame"


def _is_key_nal(nal_type: int) -> bool:
    return nal_type in (_HEVC_NAL_IDR_W_RADL, _HEVC_NAL_IDR_N_LP, _HEVC_NAL_CRA)


VIEWER_HTML = rb"""<!doctype html>
<html><head><meta charset="utf-8"><title>iPhone screen (MJPEG)</title>
<style>
 body{margin:0;background:#111;color:#ccc;font-family:system-ui;
      display:flex;flex-direction:column;align-items:center;justify-content:flex-start;
      min-height:100vh;gap:8px;padding:8px;box-sizing:border-box}
 img{max-width:100vw;max-height:calc(100vh - 80px);touch-action:none;
     cursor:crosshair;background:#000;display:block}
 #buttons{display:flex;flex-wrap:wrap;gap:6px;justify-content:center}
 #buttons button{background:#222;color:#ddd;border:1px solid #444;border-radius:6px;
                 padding:8px 14px;font-size:13px;cursor:pointer}
 #buttons button:hover{background:#333}
 #status{position:fixed;top:8px;left:12px;font-size:12px;opacity:.8;
         background:#0008;padding:4px 8px;border-radius:4px;white-space:pre;
         max-width:90vw;overflow:hidden;pointer-events:none}
</style></head>
<body>
<img id="v" src="/stream.mjpg" alt="">
<div id="buttons">
 <button data-btn="home">Home</button>
 <button data-btn="power">Power</button>
 <button data-btn="lock">Lock</button>
 <button data-btn="sleep">Sleep</button>
 <button data-btn="volume-up">Vol +</button>
 <button data-btn="volume-down">Vol -</button>
 <button data-btn="mute">Mute</button>
 <button data-btn="siri">Siri</button>
</div>
<div id="status">mjpeg viewer</div>
<script>
const img = document.getElementById('v');
const statusEl = document.getElementById('status');
function log(msg) { statusEl.textContent = msg; }

function coords(e) {
    const rect = img.getBoundingClientRect();
    const xn = (e.clientX - rect.left) / rect.width;
    const yn = (e.clientY - rect.top) / rect.height;
    return {
        x: Math.max(0, Math.min(65535, Math.round(xn * 65535))),
        y: Math.max(0, Math.min(65535, Math.round(yn * 65535))),
    };
}

async function postJson(path, payload) {
    try {
        await fetch(path, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
    } catch (e) { log(path + ' err: ' + e.message); }
}

let activePointer = null;
img.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    img.setPointerCapture(e.pointerId);
    activePointer = e.pointerId;
    const c = coords(e);
    postJson('/touch', {type: 'contact', x: c.x, y: c.y});
});
img.addEventListener('pointermove', (e) => {
    if (e.pointerId !== activePointer) return;
    e.preventDefault();
    const c = coords(e);
    postJson('/touch', {type: 'contact', x: c.x, y: c.y});
});
function endContact(e) {
    if (e.pointerId !== activePointer) return;
    e.preventDefault();
    activePointer = null;
    const c = coords(e);
    postJson('/touch', {type: 'release', x: c.x, y: c.y});
}
img.addEventListener('pointerup', endContact);
img.addEventListener('pointercancel', endContact);
img.addEventListener('contextmenu', (e) => e.preventDefault());

document.querySelectorAll('#buttons button').forEach(btn => {
    btn.addEventListener('click', () => {
        const name = btn.dataset.btn;
        postJson('/button', {name, state: 'press'}).then(() => log('button: ' + name));
    });
});
</script>
</body></html>
"""


class JpegStreamServer:
    """HEVC-decoded-on-host, JPEG-per-frame served over HTTP. See module
    docstring for the why."""

    def __init__(
        self,
        rsd: RemoteServiceDiscoveryService,
        *,
        bind: str = "127.0.0.1",
        http_port: int = 8081,
        display_id: int = 1,
        jpeg_quality: float = 0.7,  # 0.0 - 1.0 (VT quality)
    ) -> None:
        self._rsd = rsd
        self._bind = bind
        self._http_port = http_port
        self._display_id = display_id
        self._jpeg_quality = jpeg_quality
        self._sender_ip = rsd.service.address[0]

        # Each JPEG subscriber gets its own queue. The reader task pushes
        # the SAME jpeg bytes object into every queue. Queue is bounded so
        # a slow browser drops frames rather than blocking the pipeline.
        self._mjpeg_subs: dict[asyncio.Queue[bytes], None] = {}
        # Latest JPEG (used for /stream.jpg single-frame snapshots if we
        # add them later, also for new subscribers' first frame so the
        # <img> shows something immediately).
        self._latest_jpeg: Optional[bytes] = None
        self._first_jpeg = asyncio.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # VT transcoder (HEVC -> JPEG via VideoToolbox). Lazy-built once
        # we have VPS/SPS/PPS from the device-side stream.
        self._transcoder: Optional[HevcToJpegTranscoder] = None

        # Lazy HID services.
        self._uhs: Optional[UniversalHIDServiceService] = None
        self._indigo: Optional[IndigoHIDService] = None
        self._hid_lock = asyncio.Lock()

    # ----- HID lazy open -----------------------------------------------------
    async def _ensure_hid(self) -> None:
        async with self._hid_lock:
            if self._uhs is None:
                uhs = UniversalHIDServiceService(self._rsd)
                await uhs.connect()
                self._uhs = uhs
            if self._indigo is None:
                indigo = IndigoHIDService(self._rsd)
                await indigo.connect()
                self._indigo = indigo

    async def _stop_hid(self) -> None:
        for attr in ("_uhs", "_indigo"):
            svc = getattr(self, attr)
            if svc is not None:
                with contextlib.suppress(Exception):
                    await svc.close()
                setattr(self, attr, None)

    # ----- VT transcoder callback (worker thread -> asyncio) ----------------
    def _on_jpeg_from_worker(self, jpeg: bytes) -> None:
        """Called from the VT transcoder's worker thread. Marshal to the
        asyncio loop and broadcast."""
        loop = self._loop
        if loop is None:
            return
        loop.call_soon_threadsafe(self._broadcast_jpeg, jpeg)

    def _broadcast_jpeg(self, jpeg: bytes) -> None:
        self._latest_jpeg = jpeg
        if not self._first_jpeg.is_set():
            self._first_jpeg.set()
        for q in list(self._mjpeg_subs):
            if q.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            q.put_nowait(jpeg)

    async def _udp_recv_and_pipe(
        self,
        sock: socket.socket,
    ) -> None:
        """Receive RTP/HEVC, depacketize into AUs, feed each AU to the
        VT transcoder. The transcoder fires ``_on_jpeg_from_worker``
        on every produced JPEG, which marshals back to this loop and
        broadcasts to /stream.mjpg subscribers.

        Includes phantom-NAL synthesis on the first non-key AU (same
        pattern as ``screen_stream.ScreenStreamServer``): bridges the
        bootstrap POC gap so VT's reference picture set is valid for
        the first delta after the initial IDR."""
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        fu_buffer = bytearray()
        current_au: list[bytes] = []
        last_seq: Optional[int] = None
        au_corrupt = False
        au_is_key = False
        nals: list[bytes] = []
        cached_vps: Optional[bytes] = None
        cached_sps: Optional[bytes] = None
        cached_pps: Optional[bytes] = None
        cached_idr: Optional[bytes] = None
        phantoms_built = False
        while True:
            try:
                data = await loop.sock_recv(sock, 65535)
            except (OSError, asyncio.CancelledError):
                return
            if len(data) < 12:
                continue
            pt = data[1] & 0x7F
            if 64 <= pt <= 95:  # RTCP
                continue
            marker = (data[1] >> 7) & 1
            cc = data[0] & 0x0F
            header_len = 12 + cc * 4
            if data[0] & 0x10:
                ext_len = int.from_bytes(data[header_len + 2 : header_len + 4], "big")
                header_len += 4 + ext_len * 4
            payload = data[header_len:]

            seq = int.from_bytes(data[2:4], "big")
            if last_seq is not None and seq != ((last_seq + 1) & 0xFFFF):
                fu_buffer.clear()
                au_corrupt = True
            if last_seq is None or ((seq - last_seq) & 0xFFFF) < 0x8000:
                last_seq = seq

            nals.clear()
            depacketize_hevc(payload, fu_buffer, nals)
            for nal in nals:
                if not nal:
                    continue
                nt = (nal[0] >> 1) & 0x3F
                if nt == _HEVC_NAL_VPS:
                    cached_vps = bytes(nal)
                elif nt == _HEVC_NAL_SPS:
                    cached_sps = bytes(nal)
                elif nt == _HEVC_NAL_PPS:
                    cached_pps = bytes(nal)
                elif _is_key_nal(nt):
                    cached_idr = bytes(nal)
                    au_is_key = True
                current_au.append(nal)

            if marker:
                if current_au and not au_corrupt:
                    # Lazy-build the VT transcoder once we have all the
                    # parameter sets cached (they arrive in the same AU
                    # as the initial IDR).
                    if (
                        self._transcoder is None
                        and au_is_key
                        and cached_vps is not None
                        and cached_sps is not None
                        and cached_pps is not None
                    ):
                        try:
                            self._transcoder = HevcToJpegTranscoder(
                                cached_vps,
                                cached_sps,
                                cached_pps,
                                on_jpeg=self._on_jpeg_from_worker,
                                quality=self._jpeg_quality,
                            )
                            logger.info(
                                "VT transcoder started: HEVC %dx%d -> JPEG (quality=%.2f)",
                                self._transcoder.width,
                                self._transcoder.height,
                                self._jpeg_quality,
                            )
                        except Exception:
                            logger.exception("VT transcoder construction failed")
                    # Phantom synthesis bridges the bootstrap POC gap.
                    if (
                        self._transcoder is not None
                        and not au_is_key
                        and not phantoms_built
                        and cached_vps is not None
                        and cached_sps is not None
                        and cached_pps is not None
                        and cached_idr is not None
                    ):
                        try:
                            phantoms = build_phantoms_for_bootstrap(
                                cached_vps, cached_sps, cached_pps, cached_idr, current_au[0]
                            )
                            logger.info(
                                "phantom synthesis: first delta NAL %d B, produced %d phantoms",
                                len(current_au[0]),
                                len(phantoms),
                            )
                            for ph in phantoms:
                                self._transcoder.feed(b"\x00\x00\x00\x01" + ph)
                        except Exception:
                            logger.exception("phantom synthesis failed")
                        phantoms_built = True
                    # Feed the AU into the transcoder.
                    if self._transcoder is not None:
                        annexb = b"".join(b"\x00\x00\x00\x01" + nal for nal in current_au)
                        self._transcoder.feed(annexb)
                current_au = []
                au_is_key = False
                au_corrupt = False

    # ----- HTTP server -------------------------------------------------------
    async def _read_request_line_and_headers(self, reader: asyncio.StreamReader) -> tuple[str, str, dict[str, str]]:
        line = await reader.readline()
        parts = line.decode("iso-8859-1").rstrip("\r\n").split(" ")
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else ""
        headers: dict[str, str] = {}
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b"\n", b""):
                break
            k, _, v = h.decode("iso-8859-1").partition(":")
            headers[k.strip().lower()] = v.strip()
        return method, path, headers

    @staticmethod
    async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
        n = int(headers.get("content-length", "0") or "0")
        return await reader.readexactly(n) if n > 0 else b""

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            method, path, headers = await self._read_request_line_and_headers(reader)
            if method == "POST" and path == "/touch":
                body = await self._read_body(reader, headers)
                status, msg = await self._handle_touch(body)
                writer.write(
                    f"HTTP/1.1 {status} OK\r\nContent-Length: {len(msg)}\r\nConnection: close\r\n\r\n".encode() + msg
                )
                await writer.drain()
                writer.close()
                return
            if method == "POST" and path == "/button":
                body = await self._read_body(reader, headers)
                status, msg = await self._handle_button(body)
                writer.write(
                    f"HTTP/1.1 {status} OK\r\nContent-Length: {len(msg)}\r\nConnection: close\r\n\r\n".encode() + msg
                )
                await writer.drain()
                writer.close()
                return
            if method == "GET" and path in ("/", "/index.html"):
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                    b"Content-Length: " + str(len(VIEWER_HTML)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + VIEWER_HTML
                )
                await writer.drain()
                writer.close()
                return
            if method == "GET" and path == "/stream.mjpg":
                # multipart/x-mixed-replace -- the browser's <img> element
                # natively renders each part as the next frame.
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: multipart/x-mixed-replace; boundary=" + _MJPEG_BOUNDARY.encode() + b"\r\n"
                    b"Cache-Control: no-cache\r\n"
                    b"Connection: close\r\n\r\n"
                )
                await writer.drain()
                # Wait for the first JPEG so the browser doesn't see an
                # immediate boundary-with-no-body.
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._first_jpeg.wait(), timeout=5.0)
                queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=4)
                if self._latest_jpeg is not None:
                    queue.put_nowait(self._latest_jpeg)
                self._mjpeg_subs[queue] = None
                try:
                    while True:
                        jpeg = await queue.get()
                        part = (
                            b"--" + _MJPEG_BOUNDARY.encode() + b"\r\n"
                            b"Content-Type: image/jpeg\r\n"
                            b"Content-Length: " + str(len(jpeg)).encode() + b"\r\n\r\n" + jpeg + b"\r\n"
                        )
                        writer.write(part)
                        await writer.drain()
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                    pass
                finally:
                    self._mjpeg_subs.pop(queue, None)
                    with contextlib.suppress(Exception):
                        writer.close()
                return
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
        except Exception:
            logger.exception("http handler crashed")
            with contextlib.suppress(Exception):
                writer.close()

    async def _handle_touch(self, body: bytes) -> tuple[int, bytes]:
        try:
            data = json.loads(body)
            op = str(data["type"])
            x = int(data["x"])
            y = int(data["y"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return 400, f"invalid: {exc}".encode()
        await self._ensure_hid()
        assert self._uhs is not None
        if op == "contact":
            await self._uhs.send_touchscreen(
                TOUCHSCREEN_STATE_CONTACT, x, y, service_id=DIGITIZER_SURFACE_MAIN_TOUCHSCREEN
            )
        elif op == "release":
            await self._uhs.send_touchscreen(
                TOUCHSCREEN_STATE_RELEASE, x, y, service_id=DIGITIZER_SURFACE_MAIN_TOUCHSCREEN
            )
        else:
            return 400, f"unknown type {op!r}".encode()
        return 200, b"ok"

    async def _handle_button(self, body: bytes) -> tuple[int, bytes]:
        try:
            data = json.loads(body)
            name = str(data["name"])
            state = str(data.get("state", "press"))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return 400, f"invalid: {exc}".encode()
        if name not in _NAMED_BUTTONS:
            return 400, f"unknown button {name!r}".encode()
        usage_page, usage_code = _NAMED_BUTTONS[name]
        await self._ensure_hid()
        assert self._indigo is not None
        if state == "press":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_DOWN)
            await asyncio.sleep(0.05)
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_UP)
        elif state == "down":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_DOWN)
        elif state == "up":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_UP)
        else:
            return 400, f"unknown state {state!r}".encode()
        return 200, b"ok"

    # ----- top-level orchestration ------------------------------------------
    async def serve(self) -> None:
        # 1) Set up UDP socket for RTP/HEVC.
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind(("::", 0))
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        port = sock.getsockname()[1]

        # 2) Start device-side video stream.
        svc = DisplayService(self._rsd)
        await svc.connect()
        local_ip = svc.service.local_address[0]
        answer = await svc.start_video_stream(
            receiver_ip=local_ip,
            receiver_port=port,
            sender_ip=self._sender_ip,
            display_id=self._display_id,
        )
        sid = answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
        if not isinstance(sid, uuid.UUID):
            sid = uuid.UUID(sid)
        cfg = answer["connection"].get("streamConfig", {})
        logger.info(
            "video stream up: %dx%d, codec=HEVC, sender_port=%s",
            int(cfg.get("CustomWidth", 0)),
            int(cfg.get("CustomHeight", 0)),
            cfg.get("SourcePort"),
        )

        # 3) Background tasks. The VT transcoder is built lazily inside
        # the recv loop once we have VPS/SPS/PPS.
        loop = asyncio.get_running_loop()
        self._loop = loop
        feed_task = asyncio.create_task(self._udp_recv_and_pipe(sock))

        # 5) HTTP server.
        http_server = await asyncio.start_server(self._handle_http, self._bind, self._http_port)
        stop_event = asyncio.Event()

        def _request_stop() -> None:
            if not stop_event.is_set():
                logger.info("shutting down...")
                stop_event.set()

        import signal as _signal

        for signame in ("SIGINT", "SIGTERM"):
            with contextlib.suppress(NotImplementedError, AttributeError):
                loop.add_signal_handler(getattr(_signal, signame), _request_stop)

        serve_task = asyncio.create_task(http_server.serve_forever())
        try:
            logger.info(f"Open http://{self._bind}:{self._http_port}/ in any browser. Ctrl-C to stop.")
            await stop_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            if not serve_task.done():
                serve_task.cancel()
            logger.info("shutdown: closing HTTP server")
            http_server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(http_server.wait_closed(), timeout=2.0)
            logger.info("shutdown: stopping HID")
            await self._stop_hid()
            logger.info("shutdown: stopping VT transcoder")
            feed_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await feed_task
            if self._transcoder is not None:
                with contextlib.suppress(Exception):
                    self._transcoder.close()
                self._transcoder = None
            with contextlib.suppress(Exception):
                sock.close()
            logger.info("shutdown: stopping video stream")
            with contextlib.suppress(Exception):
                await asyncio.wait_for(svc.stop_media_stream(sid), timeout=3.0)
            with contextlib.suppress(Exception):
                await svc.close()
            # Cancel any straggler connection handlers.
            current = asyncio.current_task()
            stragglers = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
            if stragglers:
                for t in stragglers:
                    t.cancel()
                with contextlib.suppress(Exception):
                    await asyncio.wait(stragglers, timeout=2.0)
            logger.info("shutdown complete")
