"""
Live screen-stream server and helpers, sitting on top of :class:`DisplayService`.

Layering::

    DisplayService.start_video_stream()   ← device interaction (see display_service.py)
              ↓ produces UDP RTP/HEVC packets
    ─────────────────────────────────────  ← this module starts here
    asyncio UDP receive → RFC 7798 RTP/HEVC depacketize → access units
    cache initial VPS/SPS/PPS+IDR + parse SPS for WebCodecs codec string
    HTTP chunked broadcast to subscribers
    Built-in HTML viewer page using WebCodecs (OS hardware decoder)
"""

import asyncio
import contextlib
import json
import logging
import socket
import uuid
from pathlib import Path
from typing import Optional

from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.hid_service import (
    DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
    HID_BUTTON_STATE_DOWN,
    HID_BUTTON_STATE_UP,
    TOUCHSCREEN_STATE_CONTACT,
    TOUCHSCREEN_STATE_RELEASE,
    IndigoHIDService,
    UniversalHIDServiceService,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

# Named iOS hardware buttons → (usage_page, usage_code). Mirrors the table in
# cli/developer/core_device.py so the browser viewer can offer a friendly UI.
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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HEVC NAL helpers (RFC 7798 RTP/HEVC + ISO/IEC 14496-15 §A.3.3.1)
# ---------------------------------------------------------------------------
_HEVC_NAL_IDR_W_RADL = 19
_HEVC_NAL_IDR_N_LP = 20
_HEVC_NAL_CRA = 21
_HEVC_NAL_VPS = 32
_HEVC_NAL_SPS = 33
_HEVC_NAL_PPS = 34
_HEVC_NAL_AP = 48  # Aggregation Packet
_HEVC_NAL_FU = 49  # Fragmentation Unit


def _is_key_nal(nal_type: int) -> bool:
    return nal_type in (_HEVC_NAL_IDR_W_RADL, _HEVC_NAL_IDR_N_LP, _HEVC_NAL_CRA)


def depacketize_hevc(payload: bytes, fu_buffer: bytearray, nal_out: list[bytes]) -> None:
    """Process one RTP/HEVC payload (RFC 7798) — emit complete NAL units."""
    if len(payload) < 2:
        return
    nal_type = (payload[0] >> 1) & 0x3F
    if nal_type == _HEVC_NAL_AP:
        i = 2
        while i + 2 <= len(payload):
            size = int.from_bytes(payload[i : i + 2], "big")
            i += 2
            nal_out.append(payload[i : i + size])
            i += size
    elif nal_type == _HEVC_NAL_FU:
        fu_header = payload[2]
        start = fu_header & 0x80
        end = fu_header & 0x40
        original_nal_type = fu_header & 0x3F
        if start:
            orig_byte0 = (payload[0] & 0x81) | (original_nal_type << 1)
            orig_byte1 = payload[1]
            fu_buffer[:] = bytes([orig_byte0, orig_byte1]) + payload[3:]
        else:
            fu_buffer.extend(payload[3:])
        if end and fu_buffer:
            nal_out.append(bytes(fu_buffer))
            fu_buffer.clear()
    else:
        nal_out.append(payload)


def hevc_codec_string_from_sps(sps_nal: bytes) -> str:
    """Parse the HEVC SPS NAL unit and return the WebCodecs codec string.

    Format: ``hev1.<profile_space><profile_idc>.<reversed_pcf>.<tier><level>.<constraint_indicator>``
    per ISO/IEC 14496-15 §A.3.3.1.
    """
    # remove emulation prevention bytes (00 00 03 → 00 00)
    rb = bytearray()
    i = 2  # skip 2-byte NAL header
    while i < len(sps_nal):
        if i + 2 < len(sps_nal) and sps_nal[i] == 0 and sps_nal[i + 1] == 0 and sps_nal[i + 2] == 3:
            rb.extend(sps_nal[i : i + 2])
            i += 3
        else:
            rb.append(sps_nal[i])
            i += 1

    pos = 0

    def read_bits(n: int) -> int:
        nonlocal pos
        v = 0
        for _ in range(n):
            v = (v << 1) | ((rb[pos >> 3] >> (7 - (pos & 7))) & 1)
            pos += 1
        return v

    read_bits(4)  # sps_video_parameter_set_id
    read_bits(3)  # sps_max_sub_layers_minus1
    read_bits(1)  # sps_temporal_id_nesting_flag
    profile_space = read_bits(2)
    tier_flag = read_bits(1)
    profile_idc = read_bits(5)
    pcf = read_bits(32)
    cif = read_bits(48)
    level_idc = read_bits(8)

    rev = 0
    x = pcf
    for _ in range(32):
        rev = (rev << 1) | (x & 1)
        x >>= 1
    ps_char = "ABCD"[profile_space] if profile_space else ""
    tier_char = "H" if tier_flag else "L"
    cif_hex = f"{cif:012X}"
    while len(cif_hex) > 2 and cif_hex.endswith("00"):
        cif_hex = cif_hex[:-2]
    return f"hev1.{ps_char}{profile_idc}.{rev:X}.{tier_char}{level_idc}.{cif_hex}"


# ---------------------------------------------------------------------------
# Built-in HTML viewer (Canvas + WebCodecs decoder)
# ---------------------------------------------------------------------------
# WebCodecs uses the OS hardware HEVC decoder (VideoToolbox on macOS / Media
# Foundation on Windows) so playback latency is minimal and there's no external
# ffmpeg/ffplay/VLC needed.
VIEWER_HTML = rb"""<!doctype html>
<html><head><meta charset="utf-8"><title>iPhone screen</title>
<style>
 body{margin:0;background:#111;color:#ccc;font-family:system-ui;
      display:flex;flex-direction:column;align-items:center;justify-content:flex-start;
      min-height:100vh;gap:8px;padding:8px;box-sizing:border-box}
 canvas{max-width:100vw;max-height:calc(100vh - 80px);image-rendering:auto;
        touch-action:none;cursor:crosshair;background:#000}
 #buttons{display:flex;flex-wrap:wrap;gap:6px;justify-content:center}
 #buttons button{background:#222;color:#ddd;border:1px solid #444;border-radius:6px;
                 padding:8px 14px;font-size:13px;cursor:pointer}
 #buttons button:hover{background:#333}
 #buttons button:active{background:#4a4a4a}
 #status{position:fixed;top:8px;left:12px;font-size:12px;opacity:.8;
         background:#0008;padding:4px 8px;border-radius:4px;white-space:pre;
         max-width:90vw;overflow:hidden;pointer-events:none}
</style></head>
<body>
<canvas id="c"></canvas>
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
<div id="status">connecting...</div>
<script>
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');
const statusEl = document.getElementById('status');
let frameCount = 0;
const lines = ['connecting...'];
function log(msg) { lines.push(msg); if (lines.length > 8) lines.shift(); render(); }
function render() { statusEl.textContent = `frames: ${frameCount}\n` + lines.join('\n'); }
setInterval(render, 250);

function hex(u8, n=24) {
    let s = '';
    for (let i = 0; i < Math.min(u8.length, n); i++) s += u8[i].toString(16).padStart(2,'0');
    return s;
}

// ----- input: pointer -> /touch, hardware-buttons -> /button -----
// HID coords are UInt16 (0..65535) normalised across the device screen.
// We project from the canvas's CSS bounding box, NOT canvas.width/.height,
// because the canvas is auto-scaled by max-width/max-height.
function touchCoords(e) {
    const rect = canvas.getBoundingClientRect();
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
            keepalive: true,
        });
    } catch (e) { log(path + ' err: ' + e.message); }
}

let activePointer = null;
canvas.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;   // primary button only
    e.preventDefault();
    canvas.setPointerCapture(e.pointerId);
    activePointer = e.pointerId;
    const c = touchCoords(e);
    postJson('/touch', {type: 'contact', x: c.x, y: c.y});
});
canvas.addEventListener('pointermove', (e) => {
    if (e.pointerId !== activePointer) return;
    e.preventDefault();
    const c = touchCoords(e);
    postJson('/touch', {type: 'contact', x: c.x, y: c.y});
});
function endContact(e) {
    if (e.pointerId !== activePointer) return;
    e.preventDefault();
    activePointer = null;
    const c = touchCoords(e);
    postJson('/touch', {type: 'release', x: c.x, y: c.y});
}
canvas.addEventListener('pointerup', endContact);
canvas.addEventListener('pointercancel', endContact);
canvas.addEventListener('contextmenu', (e) => e.preventDefault());

document.querySelectorAll('#buttons button').forEach(btn => {
    btn.addEventListener('click', () => {
        const name = btn.dataset.btn;
        postJson('/button', {name, state: 'press'}).then(() => log('button: ' + name));
    });
});

async function run() {
    log('userAgent: ' + navigator.userAgent.slice(0, 80));
    // /codec blocks server-side until the device stream has emitted its SPS.
    const codecResp = await fetch('/codec', { cache: 'no-store' });
    const codec = (await codecResp.text()).trim();
    if (!codec) { log('FAIL: no SPS arrived'); return; }
    log('codec: ' + codec);

    let support;
    try {
        support = await VideoDecoder.isConfigSupported({ codec });
    } catch (e) {
        log('isConfigSupported threw: ' + e.message); return;
    }
    log('isConfigSupported: ' + JSON.stringify(support));
    if (!support.supported) { log('FAIL: codec not supported'); return; }

    const decoder = new VideoDecoder({
        output: (frame) => {
            if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
                canvas.width = frame.displayWidth;
                canvas.height = frame.displayHeight;
                log('first frame: ' + frame.displayWidth + 'x' + frame.displayHeight);
            }
            ctx.drawImage(frame, 0, 0);
            frame.close();
            frameCount++;
        },
        error: (e) => { log('error cb: ' + e.message); },
    });
    decoder.configure({ codec });
    log('state after configure: ' + decoder.state);

    const resp = await fetch('/stream.bin');
    const reader = resp.body.getReader();
    let buf = new Uint8Array(0);
    let timestamp = 0;
    let gotKey = false;
    let sentCount = 0;
    while (true) {
        const { value, done } = await reader.read();
        if (done) { log('stream ended'); break; }
        const merged = new Uint8Array(buf.length + value.length);
        merged.set(buf); merged.set(value, buf.length);
        buf = merged;
        while (buf.length >= 4) {
            const len = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
            if (buf.length < 4 + len) break;
            const type = buf[4];
            const data = buf.slice(5, 4 + len);  // .slice copies the backing buffer
            buf = buf.subarray(4 + len);
            if (type === 0) {
                gotKey = true;
                log('key AU #' + sentCount + ' len=' + data.length + ' head=' + hex(data));
            }
            if (!gotKey) continue;
            if (decoder.state !== 'configured') {
                log('decoder ' + decoder.state + ' after ' + sentCount + ' chunks');
                return;
            }
            try {
                decoder.decode(new EncodedVideoChunk({
                    type: type === 0 ? 'key' : 'delta',
                    timestamp: timestamp,
                    data: data,
                }));
                timestamp += 16666;
                sentCount++;
            } catch (e) {
                log('sync decode err @' + sentCount + ': ' + e.message);
                return;
            }
        }
    }
}
run().catch(e => log('fatal: ' + e.message));
</script>
</body></html>
"""


# ---------------------------------------------------------------------------
# Live RTP/HEVC capture (no transcoding) — used by ``start-video-stream``
# ---------------------------------------------------------------------------
async def capture_rtp_to_file(
    rsd: RemoteServiceDiscoveryService,
    output_path: Path,
    *,
    display_id: int = 1,
    duration: float = 5.0,
    receiver_port: int = 0,
) -> int:
    """Capture raw RTP packets from the device's screen-stream into a file.

    Each packet is written as ``[4-byte BE length][packet bytes]``. Returns the
    number of captured packets.
    """
    sender_ip = rsd.service.address[0]
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(("::", receiver_port))
    bound_port = sock.getsockname()[1]
    logger.info(f"Listening for RTP on [{sender_ip}] → ::{bound_port}")

    captured = 0
    async with DisplayService(rsd) as service:
        local_ip = service.service.local_address[0]
        answer = await service.start_video_stream(
            receiver_ip=local_ip,
            receiver_port=bound_port,
            sender_ip=sender_ip,
            display_id=display_id,
        )
        logger.info("Stream started; dumping RTP for %.1fs", duration)
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        with open(output_path, "wb") as fp:
            deadline = loop.time() + duration
            while loop.time() < deadline:
                remaining = deadline - loop.time()
                try:
                    data = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                fp.write(len(data).to_bytes(4, "big") + data)
                captured += 1
        logger.info(f"Captured {captured} packets to {output_path}")
        client_session_id = answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
        if not isinstance(client_session_id, uuid.UUID):
            client_session_id = uuid.UUID(client_session_id)
        with contextlib.suppress(Exception):
            await service.stop_media_stream(client_session_id)
    sock.close()
    return captured


# ---------------------------------------------------------------------------
# HTTP webserver that decodes in-browser via WebCodecs
# ---------------------------------------------------------------------------
class ScreenStreamServer:
    """Pure-stdlib HTTP server that broadcasts the device's screen stream to
    browsers using WebCodecs for in-browser HEVC decode.

    Pipeline::

        device → DisplayService.start_video_stream() → UDP RTP packets
        → asyncio.sock_recv → RFC 7798 RTP/HEVC depacketize
        → cache VPS/SPS/PPS+IDR as init sequence
        → parse SPS for WebCodecs codec string (``hev1.*``)
        → HTTP chunked stream of framed access units
        → browser fetch().getReader() → VideoDecoder → canvas
    """

    def __init__(
        self,
        rsd: RemoteServiceDiscoveryService,
        *,
        bind: str = "127.0.0.1",
        http_port: int = 8080,
        display_id: int = 1,
    ) -> None:
        self._rsd = rsd
        self._bind = bind
        self._http_port = http_port
        self._display_id = display_id
        self._sender_ip = rsd.service.address[0]

        # Broadcast state — each subscriber gets framed access units written as:
        #   [4-byte BE length] [1-byte type: 0=key, 1=delta] [Annex-B HEVC bytes]
        self._subscribers: set[asyncio.Queue[bytes]] = set()
        self._init_sequence: Optional[bytes] = None
        self._codec_string: Optional[str] = None
        self._saw_first_key = False
        self._stream_ready = asyncio.Event()

        # Active device-stream session.
        self._active_service: Optional[DisplayService] = None
        self._active_session_id: Optional[uuid.UUID] = None
        self._active_sock: Optional[socket.socket] = None
        self._active_recv_task: Optional[asyncio.Task] = None
        self._stream_lock = asyncio.Lock()
        self._stream_dirty = True  # True → next request must restart the stream

        # Lazy-opened HID services for browser-driven touch / buttons. The
        # auth gate is already held open by the active media stream above,
        # so we don't need :func:`hid_service.touch_session`.
        self._uhs: Optional[UniversalHIDServiceService] = None
        self._indigo: Optional[IndigoHIDService] = None
        self._hid_lock = asyncio.Lock()

    # ----- per-session UDP receiver -----------------------------------------
    async def _udp_recv_and_depacketize(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        fu_buffer = bytearray()
        current_au: list[bytes] = []
        au_is_key = False
        nals: list[bytes] = []
        while True:
            try:
                data = await loop.sock_recv(sock, 65535)
            except (OSError, asyncio.CancelledError):
                return
            except Exception:
                logger.exception("recv task crashed")
                return
            if len(data) < 12:
                continue
            pt = data[1] & 0x7F
            if 64 <= pt <= 95:  # RTCP
                continue
            marker = (data[1] >> 7) & 1
            cc = data[0] & 0x0F
            header_len = 12 + cc * 4
            if data[0] & 0x10:  # extension
                ext_len = int.from_bytes(data[header_len + 2 : header_len + 4], "big")
                header_len += 4 + ext_len * 4
            payload = data[header_len:]

            nals.clear()
            depacketize_hevc(payload, fu_buffer, nals)
            for nal in nals:
                if not nal:
                    continue
                nt = (nal[0] >> 1) & 0x3F
                if nt == _HEVC_NAL_SPS and self._codec_string is None:
                    try:
                        self._codec_string = hevc_codec_string_from_sps(nal)
                        logger.info(f"WebCodecs codec string: {self._codec_string}")
                    except Exception as exc:
                        logger.warning(f"failed to parse SPS: {exc}")
                if _is_key_nal(nt):
                    au_is_key = True
                current_au.append(nal)

            if marker:
                if current_au:
                    annexb = b"".join(b"\x00\x00\x00\x01" + nal for nal in current_au)
                    type_byte = b"\x00" if au_is_key else b"\x01"
                    msg = (len(annexb) + 1).to_bytes(4, "big") + type_byte + annexb
                    if au_is_key:
                        self._init_sequence = msg
                        self._saw_first_key = True
                        if self._codec_string is not None:
                            self._stream_ready.set()
                    if self._saw_first_key:
                        for q in list(self._subscribers):
                            if q.full():
                                with contextlib.suppress(asyncio.QueueEmpty):
                                    q.get_nowait()
                            q.put_nowait(msg)
                current_au = []
                au_is_key = False

    # ----- device-stream lifecycle ------------------------------------------
    async def _stop_active_stream(self) -> None:
        svc = self._active_service
        sid = self._active_session_id
        sock_to_close = self._active_sock
        task_to_cancel = self._active_recv_task
        self._active_service = None
        self._active_session_id = None
        self._active_sock = None
        self._active_recv_task = None
        if task_to_cancel is not None:
            task_to_cancel.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task_to_cancel
        if sock_to_close is not None:
            with contextlib.suppress(Exception):
                sock_to_close.close()
        if svc is not None:
            with contextlib.suppress(Exception):
                if sid is not None:
                    await svc.stop_media_stream(sid)
            with contextlib.suppress(Exception):
                await svc.close()

    async def _ensure_fresh_stream(self, force: bool = False) -> None:
        async with self._stream_lock:
            if self._active_service is not None and not self._stream_dirty and not force:
                return
            await self._stop_active_stream()
            self._init_sequence = None
            self._codec_string = None
            self._saw_first_key = False
            self._stream_ready.clear()
            self._subscribers.clear()

            # Fresh socket — no buffered packets from a previous session can
            # corrupt the new session's FU reassembly.
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.bind(("::", 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            port = sock.getsockname()[1]

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
            self._active_service = svc
            self._active_session_id = sid
            self._active_sock = sock
            self._active_recv_task = asyncio.create_task(self._udp_recv_and_depacketize(sock))
            self._stream_dirty = False

    # ----- HID (touch + buttons) -------------------------------------------
    async def _ensure_hid(self) -> None:
        """Lazily open the HID services on first input event."""
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
        async with self._hid_lock:
            if self._uhs is not None:
                with contextlib.suppress(Exception):
                    await self._uhs.close()
                self._uhs = None
            if self._indigo is not None:
                with contextlib.suppress(Exception):
                    await self._indigo.close()
                self._indigo = None

    async def _handle_touch(self, body: bytes) -> tuple[int, bytes]:
        """POST /touch — JSON ``{type, x, y}``.

        ``type`` is one of:
          - ``"contact"``  → CONTACT (in-contact sample at x, y)
          - ``"release"``  → RELEASE (lift the touch at x, y)
          - ``"tap"``      → CONTACT + brief sleep + RELEASE at the same point

        Drags are just a stream of ``"contact"`` updates ending in ``"release"``
        — the browser fires them straight from pointerdown / pointermove /
        pointerup, so the device sees the same shape as a real Xcode drag.
        """
        try:
            data = json.loads(body)
            op = str(data["type"])
            x = int(data["x"])
            y = int(data["y"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return 400, f"invalid touch request: {exc}".encode()
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
        elif op == "tap":
            await self._uhs.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, x, y)
            await asyncio.sleep(0.05)
            await self._uhs.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, x, y)
        else:
            return 400, f"unknown touch type {op!r}".encode()
        return 200, b"ok"

    async def _handle_button(self, body: bytes) -> tuple[int, bytes]:
        """POST /button — JSON ``{name, state}``.

        ``name`` is one of the keys in :data:`_NAMED_BUTTONS` (home, power,
        lock, sleep, volume-up, volume-down, mute, siri). ``state`` is one of
        ``"press"`` (default — fires down then up), ``"down"``, ``"up"``.
        """
        try:
            data = json.loads(body)
            name = str(data["name"])
            state = str(data.get("state", "press"))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return 400, f"invalid button request: {exc}".encode()
        if name not in _NAMED_BUTTONS:
            return 400, f"unknown button {name!r}".encode()
        usage_page, usage_code = _NAMED_BUTTONS[name]
        await self._ensure_hid()
        assert self._indigo is not None
        if state == "press":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_DOWN)
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_UP)
        elif state == "down":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_DOWN)
        elif state == "up":
            await self._indigo.send_button(usage_page, usage_code, HID_BUTTON_STATE_UP)
        else:
            return 400, f"unknown button state {state!r}".encode()
        return 200, b"ok"

    @staticmethod
    async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        # Cap the body to a sane size — touch/button POSTs are tens of bytes.
        return await reader.readexactly(min(length, 65536))

    # ----- HTTP request handler ---------------------------------------------
    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await reader.readline()
        if not request_line:
            writer.close()
            return
        headers: dict[str, str] = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b""):
                break
            try:
                name, _, value = line.decode("latin-1").partition(":")
                headers[name.strip().lower()] = value.strip()
            except UnicodeDecodeError:
                pass
        parts = request_line.split()
        method = parts[0].decode() if parts else "GET"
        path = parts[1].decode() if len(parts) >= 2 else "/"

        if method == "POST" and path in ("/touch", "/button"):
            body = await self._read_body(reader, headers)
            try:
                handler = self._handle_touch if path == "/touch" else self._handle_button
                code, msg = await handler(body)
            except Exception as exc:
                logger.exception("input handler crashed")
                code, msg = 500, f"internal error: {exc}".encode()
            status_line = {200: b"200 OK", 400: b"400 Bad Request", 500: b"500 Internal"}.get(code, b"500 Internal")
            writer.write(
                b"HTTP/1.1 " + status_line + b"\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(msg)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + msg
            )
            await writer.drain()
            writer.close()
            return

        if path in ("/", "/index.html"):
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(VIEWER_HTML)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + VIEWER_HTML
            )
            await writer.drain()
            writer.close()
            return
        if path == "/codec":
            try:
                await self._ensure_fresh_stream(force=False)
            except Exception:
                logger.exception("failed to start device stream")
                writer.write(b"HTTP/1.1 500 Internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stream_ready.wait(), timeout=8.0)
            body = (self._codec_string or "").encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Cache-Control: no-store\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
            writer.close()
            return
        if path != "/stream.bin":
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        await self._ensure_fresh_stream()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._stream_ready.wait(), timeout=3.0)

        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Cache-Control: no-cache\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=8)
        # Send the cached init sequence (VPS/SPS/PPS+IDR) so the decoder has a keyframe.
        if self._init_sequence is not None:
            queue.put_nowait(self._init_sequence)
        self._subscribers.add(queue)
        try:
            while True:
                msg = await queue.get()
                writer.write(f"{len(msg):x}\r\n".encode() + msg + b"\r\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        finally:
            self._subscribers.discard(queue)
            with contextlib.suppress(Exception):
                writer.close()

    async def serve(self) -> None:
        """Run the HTTP server until cancelled / Ctrl-C."""
        http_server = await asyncio.start_server(self._handle_http, self._bind, self._http_port)
        try:
            logger.info(f"Open http://{self._bind}:{self._http_port}/ in Safari/Chrome. Ctrl-C to stop.")
            await http_server.serve_forever()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await self._stop_hid()
            async with self._stream_lock:
                await self._stop_active_stream()
            http_server.close()
            await http_server.wait_closed()
