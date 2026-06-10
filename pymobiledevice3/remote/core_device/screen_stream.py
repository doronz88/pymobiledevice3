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
    // Note: do NOT pass {keepalive: true} -- that triggers fetch's
    // "send during page unload" path which has body-size limits and
    // queues requests differently; we want plain HTTP/1.1 keep-alive
    // (the default) so pointer events stream over one TCP.
    try {
        await fetch(path, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
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

    let decodeErrCount = 0;
    let needsResync = false;     // skip deltas until we see the next key after an error
    const buildDecoder = () => new VideoDecoder({
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
        // Decoder errors propagate asynchronously via this callback. After one,
        // the decoder transitions to 'closed' -- we re-create it and wait for
        // the next keyframe before feeding it again.
        error: (e) => {
            decodeErrCount++;
            log('decode err #' + decodeErrCount + ': ' + e.message);
            needsResync = true;
        },
    });
    let decoder = buildDecoder();
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
            // type:
            //   0 = key (IDR) -- decode normally
            //   1 = delta
            //   2 = key WITH RESET -- server detected an upstream drop; the
            //       decoder's reference state may be silently stale, so
            //       rebuild before decoding this IDR. (VideoToolbox often
            //       renders torn frames without firing the error callback.)
            if (type === 2) {
                decoder = buildDecoder();
                decoder.configure({ codec });
                needsResync = false;
                gotKey = true;
                log('forced reset @ key after upstream drop');
            } else if (type === 0) {
                gotKey = true;
                if (needsResync) {
                    decoder = buildDecoder();
                    decoder.configure({ codec });
                    needsResync = false;
                    log('resynced @ key after ' + decodeErrCount + ' decode err(s)');
                }
            }
            if (!gotKey) continue;
            if (needsResync) continue;
            if (decoder.state !== 'configured') {
                log('decoder ' + decoder.state + ' @' + sentCount + ' - rebuilding');
                decoder = buildDecoder();
                decoder.configure({ codec });
                needsResync = true;
                continue;
            }
            try {
                decoder.decode(new EncodedVideoChunk({
                    type: (type === 0 || type === 2) ? 'key' : 'delta',
                    timestamp: timestamp,
                    data: data,
                }));
                timestamp += 16666;
                sentCount++;
            } catch (e) {
                log('sync decode err @' + sentCount + ': ' + e.message);
                needsResync = true;
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
class _SubState:
    """Per-subscriber broadcast state — set ``needs_key`` after a queue drop
    so we don't feed the decoder a delta without its reference keyframe.
    """

    __slots__ = ("needs_key",)

    def __init__(self) -> None:
        self.needs_key = False


# Watchdog tuning. We learned the hard way that restarts are expensive --
# they churn the device's coredeviced and, if fired too frequently, wedge it
# into a state where new RemoteXPC handshakes time out and only a reboot
# recovers. So we err on the side of patience:
#
# - ``_STALL_RESTART_SECS``: only restart after a sustained gap, not a blip.
# - ``_STALL_RESTART_COOLDOWN_SECS``: long enough that legitimate idles
#   (locked device, no on-screen activity) don't loop us into a hot restart.
# - ``_MAX_STALL_RESTARTS``: an absolute backstop -- if this many restarts
#   in a row don't fix things, the device daemon is wedged and another
#   restart will just make it worse. Bail and require a manual page reload.
_STALL_RESTART_SECS = 5.0
_STALL_RESTART_COOLDOWN_SECS = 15.0
_MAX_STALL_RESTARTS = 3


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
        # A subscriber that falls behind has its queue cleared and its
        # ``needs_key`` flag set; we then hold further frames until the next
        # keyframe arrives so the decoder never sees a delta without a key.
        self._subscribers: dict[asyncio.Queue[bytes], _SubState] = {}
        self._init_sequence: Optional[bytes] = None
        self._codec_string: Optional[str] = None
        self._saw_first_key = False
        self._stream_ready = asyncio.Event()

        # Active device-stream session.
        self._active_service: Optional[DisplayService] = None
        self._active_session_id: Optional[uuid.UUID] = None
        self._active_sock: Optional[socket.socket] = None
        self._active_recv_task: Optional[asyncio.Task] = None
        self._active_rtcp_task: Optional[asyncio.Task] = None
        self._stream_lock = asyncio.Lock()
        self._stream_dirty = True  # True → next request must restart the stream

        # RTCP feedback bookkeeping. The streamConfig the device returns sets
        # ``RTCPTimeoutEnabled=True`` -- without periodic Receiver Reports the
        # encoder stalls after a few tens of seconds. Filled in when the
        # stream starts; the RTCP task reads them.
        self._rtcp_dest: Optional[tuple[str, int]] = None  # (ipv6, port)
        self._local_ssrc: int = 0
        self._remote_ssrc: int = 0
        self._rtp_highest_seq: int = 0  # extended (cycles<<16 | seq16)
        self._rtp_packets_received: int = 0
        # PLI tasks in flight -- keep a reference so the GC doesn't drop
        # them while awaiting the sendto (and ruff is happy with create_task).
        self._pli_tasks: set[asyncio.Task] = set()

        # Lazy-opened HID services for browser-driven touch / buttons. The
        # auth gate is already held open by the active media stream above,
        # so we don't need :func:`hid_service.touch_session`.
        self._uhs: Optional[UniversalHIDServiceService] = None
        self._indigo: Optional[IndigoHIDService] = None
        self._hid_lock = asyncio.Lock()

        # HID input queue. We accept /touch and /button POSTs into this
        # queue and return 200 immediately, then a single worker task
        # dispatches them via the XPC connection. This decouples HTTP
        # handling latency from device-write latency so a touch flood
        # can't starve the stream-broadcast loop.
        self._hid_queue: asyncio.Queue[tuple[str, bytes]] = asyncio.Queue()
        self._hid_worker_task: Optional[asyncio.Task] = None

        # Stall-detection bookkeeping. Updated whenever an AU is forwarded;
        # the watchdog restarts the stream (forcing a fresh IDR) if no AU
        # has progressed within :data:`_STALL_RESTART_SECS` while we have
        # at least one subscriber attached.
        self._last_good_au_t: float = 0.0
        self._last_restart_t: float = 0.0
        self._consecutive_restarts: int = 0

    # ----- per-session UDP receiver -----------------------------------------
    async def _udp_recv_and_depacketize(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        fu_buffer = bytearray()
        current_au: list[bytes] = []
        au_is_key = False
        nals: list[bytes] = []
        # Track RTP sequence numbers and drop the entire AU on any gap. We
        # learned the hard way that Apple's VideoToolbox is lenient about
        # missing slices — it renders the partial frame as a visible artifact
        # rather than throwing, so the browser-side resync never fires and
        # the corruption propagates through every subsequent delta until the
        # encoder happens to send a fresh IDR (which, on a busy stream, may
        # never happen).
        #
        # Dropping AUs means a brief picture freeze on each loss, recovered
        # at the encoder's next IDR. To bound the freeze when the encoder
        # is slow to emit a fresh key (or stops entirely), the dispatch loop
        # also restarts the whole media stream once we've held the picture
        # for more than ``_STALL_RESTART_SECS`` — see ``_stall_watchdog``.
        last_seq: Optional[int] = None
        au_corrupt = False
        # Stats for diagnosing the corruption pattern. Sampled into the log
        # every ~5 s — if forward_gaps >> reorders, it's true UDP loss; if
        # they're comparable, the QUIC carrier is reordering packets and we
        # need a small jitter buffer to recover them.
        stats_packets = 0
        stats_forward_gaps = 0
        stats_reorders = 0
        stats_corrupt_aus = 0
        stats_last_log = asyncio.get_running_loop().time()
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

            # Any RTP gap → discard the in-flight FU buffer (don't stitch
            # non-contiguous payloads into a single NAL) AND mark the whole
            # AU corrupt so we drop it at the next marker.
            seq = int.from_bytes(data[2:4], "big")
            stats_packets += 1
            # Maintain the extended highest-seq counter for RTCP RR.
            self._rtp_packets_received += 1
            cur_ext = self._rtp_highest_seq
            cycles = (cur_ext >> 16) & 0xFFFF
            last_seq16 = cur_ext & 0xFFFF
            if seq < last_seq16 and (last_seq16 - seq) > 0x8000:
                cycles = (cycles + 1) & 0xFFFF  # seq number wrapped
            new_ext = (cycles << 16) | seq
            if cur_ext == 0 or ((new_ext - cur_ext) & 0xFFFFFFFF) < 0x80000000:
                self._rtp_highest_seq = new_ext
            if last_seq is not None and seq != ((last_seq + 1) & 0xFFFF):
                forward = ((seq - last_seq) & 0xFFFF) < 0x8000  # heuristic for "ahead"
                if forward:
                    stats_forward_gaps += 1
                else:
                    stats_reorders += 1
                logger.debug(
                    "RTP %s: expected %d, got %d",
                    "gap" if forward else "reorder",
                    (last_seq + 1) & 0xFFFF,
                    seq,
                )
                fu_buffer.clear()
                au_corrupt = True
            # Only advance last_seq forward (drop late stragglers) so a single
            # out-of-order packet doesn't reset our notion of "newest seen".
            if last_seq is None or ((seq - last_seq) & 0xFFFF) < 0x8000:
                last_seq = seq

            now = loop.time()
            if now - stats_last_log > 5.0:
                if stats_forward_gaps or stats_reorders or stats_corrupt_aus:
                    logger.info(
                        "RTP stats (last %.1fs): packets=%d forward_gaps=%d reorders=%d dropped_AUs=%d",
                        now - stats_last_log,
                        stats_packets,
                        stats_forward_gaps,
                        stats_reorders,
                        stats_corrupt_aus,
                    )
                stats_packets = 0
                stats_forward_gaps = 0
                stats_reorders = 0
                stats_corrupt_aus = 0
                stats_last_log = now

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
                if au_corrupt:
                    stats_corrupt_aus += 1
                    # Ask the device's encoder to emit a fresh IDR. Without
                    # this, every subsequent delta references slices we
                    # never delivered, the browser decoder errors and gets
                    # stuck waiting for a keyframe that on a long-GOP
                    # stream may never come naturally.
                    pli_task = asyncio.create_task(self._send_rtcp_pli())
                    self._pli_tasks.add(pli_task)
                    pli_task.add_done_callback(self._pli_tasks.discard)
                    # Also force every connected subscriber to wait for the
                    # next IDR before feeding the decoder again. VideoToolbox
                    # often *doesn't* throw on a broken-reference delta -- it
                    # renders visible tearing without firing the error
                    # callback -- so we can't rely on the browser to notice
                    # on its own. Marking needs_key here means: skip frames
                    # until our PLI-induced IDR arrives, then full reset.
                    for state in self._subscribers.values():
                        state.needs_key = True
                if current_au and not au_corrupt:
                    annexb = b"".join(b"\x00\x00\x00\x01" + nal for nal in current_au)
                    # Three framing types:
                    #   0 = key (IDR) - decode normally
                    #   1 = delta
                    #   2 = key WITH RESET - browser must rebuild the decoder
                    #       before decoding this AU. Used when a prior drop
                    #       left the decoder's reference state stale.
                    type_byte = b"\x00" if au_is_key else b"\x01"
                    msg = (len(annexb) + 1).to_bytes(4, "big") + type_byte + annexb
                    msg_reset = (len(annexb) + 1).to_bytes(4, "big") + b"\x02" + annexb if au_is_key else msg
                    if au_is_key:
                        self._init_sequence = msg
                        self._saw_first_key = True
                        if self._codec_string is not None:
                            self._stream_ready.set()
                    self._last_good_au_t = loop.time()
                    if self._saw_first_key:
                        for q, state in list(self._subscribers.items()):
                            if q.full():
                                # Subscriber falling behind — flush everything
                                # and wait for the next keyframe before feeding
                                # again, so we never deliver a delta without
                                # its reference key.
                                while not q.empty():
                                    with contextlib.suppress(asyncio.QueueEmpty):
                                        q.get_nowait()
                                state.needs_key = True
                            if state.needs_key:
                                if not au_is_key:
                                    continue
                                state.needs_key = False
                                # Use the reset variant so the browser
                                # rebuilds its decoder before this key --
                                # the prior decoder may have absorbed a
                                # broken delta without erroring and now
                                # holds stale reference frames.
                                q.put_nowait(msg_reset)
                                continue
                            q.put_nowait(msg)
                current_au = []
                au_is_key = False
                au_corrupt = False

    # ----- RTCP feedback ----------------------------------------------------
    def _build_rtcp_pli(self) -> bytes:
        """Build an RTCP Picture Loss Indication (RFC 4585 §6.3.1).

        Sent when we detect dropped AUs so the device-side encoder emits a
        fresh IDR. Without this the browser's decoder gets stuck waiting
        for a keyframe that, on a long-GOP stream, may never come.

        Format (12 bytes total)::

            byte 0  : V=2 P=0 FMT=1   (0x81)
            byte 1  : PT=206 PSFB     (0xCE)
            bytes 2-3: length=2 (3 words)
            bytes 4-7: sender SSRC (ours)
            bytes 8-11: media source SSRC (device's)
        """
        import struct as _struct

        return _struct.pack(
            "!BBHII",
            0x81,
            0xCE,
            2,
            self._local_ssrc & 0xFFFFFFFF,
            self._remote_ssrc & 0xFFFFFFFF,
        )

    async def _send_rtcp_pli(self) -> None:
        sock = self._active_sock
        if sock is None or self._rtcp_dest is None:
            return
        if not (self._local_ssrc and self._remote_ssrc):
            return
        try:
            loop = asyncio.get_running_loop()
            await loop.sock_sendto(sock, self._build_rtcp_pli(), (*self._rtcp_dest, 0, 0))
            logger.info("sent RTCP PLI (requested fresh keyframe)")
        except OSError as exc:
            logger.debug("PLI send failed (%s)", exc)

    def _build_rtcp_rr(self) -> bytes:
        """Build a minimal RTCP Receiver Report for the active stream.

        The device's ``streamConfig`` says ``RTCPTimeoutEnabled=True`` -- if we
        never send RTs the encoder stalls within ~25 s. A single Receiver
        Report (32 bytes) every second is enough to keep it producing frames.

        Format (RFC 3550 §6.4.2): one RR with one report block::

            byte 0  : V=2 P=0 RC=1     (0x81)
            byte 1  : PT=201 (RR)      (0xC9)
            bytes 2-3: length=7 (8 words total)
            bytes 4-7: sender SSRC      (our LocalSSRC)
            bytes 8-11: SSRC_1          (device's SSRC = RemoteSSRC)
            byte 12 : fraction lost (0)
            13-15   : cumulative packets lost (0)
            16-19   : extended highest seq received
            20-23   : interarrival jitter (0)
            24-27   : last SR timestamp (0 -- we never received SR)
            28-31   : delay since last SR (0)
        """
        import struct as _struct

        return _struct.pack(
            "!BBHII BBBB IIII",
            0x81,
            0xC9,
            7,
            self._local_ssrc & 0xFFFFFFFF,
            self._remote_ssrc & 0xFFFFFFFF,
            0,  # fraction lost
            0,
            0,
            0,  # cumulative loss (3 bytes — packed as 3x B)
            self._rtp_highest_seq & 0xFFFFFFFF,
            0,
            0,
            0,
        )

    async def _rtcp_send_loop(self, sock: socket.socket) -> None:
        """Periodically send RTCP RR to the device so the encoder doesn't time out."""
        loop = asyncio.get_running_loop()
        while True:
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return
            if self._rtcp_dest is None or self._rtp_packets_received == 0:
                continue
            packet = self._build_rtcp_rr()
            try:
                await loop.sock_sendto(sock, packet, (*self._rtcp_dest, 0, 0))
            except OSError as exc:
                logger.debug("RTCP send failed (%s); the socket may be torn down", exc)
                return

    # ----- device-stream lifecycle ------------------------------------------
    async def _stop_active_stream(self) -> None:
        svc = self._active_service
        sid = self._active_session_id
        sock_to_close = self._active_sock
        task_to_cancel = self._active_recv_task
        rtcp_task = self._active_rtcp_task
        self._active_service = None
        self._active_session_id = None
        self._active_sock = None
        self._active_recv_task = None
        self._active_rtcp_task = None
        if rtcp_task is not None:
            rtcp_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await rtcp_task
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
            had_active_stream = self._active_service is not None
            await self._stop_active_stream()
            if had_active_stream:
                # The new device-side media stream re-publishes its
                # IOHIDService surfaces under fresh IDs; backboardd
                # re-matches the auth flags only for surfaces attached
                # AFTER the new stream is up. Drop our HID handles so the
                # next /touch or /button opens fresh ones against the new
                # context. On a *cold* first start we skip this so the
                # worker we just spawned in serve() isn't killed before it
                # processes its first request.
                await self._stop_hid()
            self._init_sequence = None
            self._codec_string = None
            self._saw_first_key = False
            self._stream_ready.clear()
            # Preserve any connected subscribers across the restart — flush
            # their queues and flag them needs_key so they'll lock onto the
            # first IDR from the new stream instead of seeing the connection
            # break. (On a fresh /stream.bin request there are no subscribers
            # yet, so this is a no-op for cold starts.)
            for q, state in self._subscribers.items():
                while not q.empty():
                    with contextlib.suppress(asyncio.QueueEmpty):
                        q.get_nowait()
                state.needs_key = True

            # Fresh socket — no buffered packets from a previous session can
            # corrupt the new session's FU reassembly.
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.bind(("::", 0))
            # Pump SO_RCVBUF as high as the kernel will allow (capped by
            # kern.ipc.maxsockbuf, typically 8 MB on macOS). Larger buffer =
            # tolerates longer event-loop stalls without kernel-level UDP drops.
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except OSError:
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
            # Extract RTCP destination + SSRCs from the streamConfig the device
            # returned. Without this the encoder stalls every ~25 s waiting
            # for Receiver Reports (RTCPTimeoutEnabled=True in the config).
            # The names in streamConfig are from the device's perspective, so
            # ``LocalSSRC`` is the device's SSRC and ``RemoteSSRC`` is ours.
            # In an RR we send, the sender SSRC is OURS (RemoteSSRC) and the
            # SSRC being reported on is the device's (LocalSSRC).
            stream_cfg = answer["connection"].get("streamConfig", {})
            source_port = int(stream_cfg.get("SourcePort", 0))
            self._local_ssrc = int(stream_cfg.get("RemoteSSRC", 0))  # ours
            self._remote_ssrc = int(stream_cfg.get("LocalSSRC", 0))  # device's
            self._rtp_highest_seq = 0
            self._rtp_packets_received = 0
            self._rtcp_dest = (self._sender_ip, source_port) if source_port else None
            self._active_service = svc
            self._active_session_id = sid
            self._active_sock = sock
            self._active_recv_task = asyncio.create_task(self._udp_recv_and_depacketize(sock))
            if self._rtcp_dest is not None and self._local_ssrc and self._remote_ssrc:
                self._active_rtcp_task = asyncio.create_task(self._rtcp_send_loop(sock))
            else:
                logger.warning(
                    "RTCP feedback disabled (missing fields in streamConfig: SourcePort=%s LocalSSRC=%s RemoteSSRC=%s)",
                    source_port,
                    self._local_ssrc,
                    self._remote_ssrc,
                )
            # Seed the stall timer to "now" so the watchdog gives the new
            # stream ``_STALL_RESTART_SECS`` to produce its first AU instead
            # of firing immediately on its zero-initialised value.
            self._last_good_au_t = asyncio.get_running_loop().time()
            self._stream_dirty = False

    # ----- HID (touch + buttons) -------------------------------------------
    async def _ensure_hid(self) -> None:
        """Lazily open the HID services + worker on first input event."""
        async with self._hid_lock:
            if self._uhs is None:
                uhs = UniversalHIDServiceService(self._rsd)
                await uhs.connect()
                self._uhs = uhs
            if self._indigo is None:
                indigo = IndigoHIDService(self._rsd)
                await indigo.connect()
                self._indigo = indigo
            if self._hid_worker_task is None or self._hid_worker_task.done():
                self._hid_worker_task = asyncio.create_task(self._hid_worker())

    async def _stop_hid(self) -> None:
        # Drain pending requests so the new stream context doesn't get
        # POSTs queued against the old one. We keep the worker task ALIVE
        # though -- on the next /touch it will lazily re-open UHS/Indigo
        # against the fresh stream via _ensure_hid. Cancelling the worker
        # here would leave us with no consumer of _hid_queue after a
        # forced restart and touches would silently stall.
        while not self._hid_queue.empty():
            with contextlib.suppress(asyncio.QueueEmpty):
                self._hid_queue.get_nowait()
        async with self._hid_lock:
            if self._uhs is not None:
                with contextlib.suppress(Exception):
                    await self._uhs.close()
                self._uhs = None
            if self._indigo is not None:
                with contextlib.suppress(Exception):
                    await self._indigo.close()
                self._indigo = None

    async def _hid_worker(self) -> None:
        """Single consumer that serially dispatches queued HID requests so
        order is preserved and HTTP handlers can return 200 immediately.
        Lazily opens the HID services on the first queued request."""
        logger.info("hid worker started")
        try:
            while True:
                path, body = await self._hid_queue.get()
                try:
                    if self._uhs is None or self._indigo is None:
                        await self._ensure_hid()
                    handler = self._handle_touch if path == "/touch" else self._handle_button
                    code, msg = await handler(body)
                    if code != 200:
                        logger.warning("queued %s -> %d %s", path, code, msg.decode("utf-8", "replace"))
                except Exception:
                    logger.exception("queued HID dispatch failed: %s body=%r", path, body[:200])
        except asyncio.CancelledError:
            logger.info("hid worker cancelled")
            raise
        except Exception:
            logger.exception("hid worker crashed")
            raise

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
        # POSTs to /touch and /button support keep-alive: one TCP carries
        # many requests, which is what the browser uses for pointermove.
        # Everything else (/, /codec, /stream.bin) is one-and-done.
        while True:
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
                logger.info("enqueue %s body=%r conn=%s", path, body[:80], headers.get("connection", "?"))
                # Fire-and-forget: drop into the queue and answer 200 NOW.
                # The single HID worker will dispatch in order without
                # blocking the HTTP-server loop or starving the stream
                # broadcast.
                self._hid_queue.put_nowait((path, body))
                keep_alive = headers.get("connection", "").lower() != "close"
                conn_hdr = b"keep-alive" if keep_alive else b"close"
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: " + conn_hdr + b"\r\n\r\nok"
                )
                await writer.drain()
                if not keep_alive:
                    writer.close()
                    return
                continue
            # Anything else falls through to the single-shot handlers below.
            break

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

        # Force a fresh stream on every /stream.bin connect. Replaying a
        # cached _init_sequence is only safe immediately after the IDR was
        # received -- on a long-GOP stream the cached IDR may be minutes
        # old, and the live deltas we'd push next reference frames the
        # new subscriber never saw. ffmpeg flags this as "Could not find
        # ref with POC <N>" for every post-connect AU; VideoToolbox /
        # WebCodecs often render it as silent tearing without firing
        # decoder.error -- so we'd never resync.
        #
        # PLI alone doesn't reliably make this device's encoder emit a
        # fresh IDR. A full stream restart always begins with one. Costs
        # ~500ms per browser-tab refresh but it's the only correct path.
        await self._ensure_fresh_stream(force=True)
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
        # Bumped from 8 to 32: gives the browser more headroom during bursty
        # arrival (e.g. when the JS event loop is busy posting input events)
        # before we have to flush and resync from the next keyframe.
        queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=32)
        if self._init_sequence is not None:
            queue.put_nowait(self._init_sequence)
        self._subscribers[queue] = _SubState()
        try:
            while True:
                msg = await queue.get()
                writer.write(f"{len(msg):x}\r\n".encode() + msg + b"\r\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        finally:
            self._subscribers.pop(queue, None)
            with contextlib.suppress(Exception):
                writer.close()

    async def _stall_watchdog(self) -> None:
        """Restart the media stream if AU progress stalls — typically when
        persistent UDP loss causes us to drop every AU and the encoder
        hasn't sent a fresh IDR. Restarting forces a new IDR from the device.

        Honours :data:`_STALL_RESTART_COOLDOWN_SECS` so a legitimate idle
        (e.g. the device is locked) doesn't loop us into a hot restart cycle.
        """
        loop = asyncio.get_running_loop()
        check_interval = max(_STALL_RESTART_SECS / 4, 0.25)
        while True:
            try:
                await asyncio.sleep(check_interval)
            except asyncio.CancelledError:
                return
            if not self._subscribers:
                continue
            if self._active_service is None:
                continue
            now = loop.time()
            if now - self._last_good_au_t <= _STALL_RESTART_SECS:
                # Stream is making progress -- any prior restarts are forgiven.
                self._consecutive_restarts = 0
                continue
            if now - self._last_restart_t < _STALL_RESTART_COOLDOWN_SECS:
                continue
            if self._consecutive_restarts >= _MAX_STALL_RESTARTS:
                # Further restarts aren't fixing things. Stop pummelling the
                # device daemon -- next time the user reloads the page the
                # cold /codec path will attempt a fresh start anyway.
                continue
            self._consecutive_restarts += 1
            logger.warning(
                "no AU progress in %.1fs (subscribers=%d, attempt %d/%d) - restarting stream",
                now - self._last_good_au_t,
                len(self._subscribers),
                self._consecutive_restarts,
                _MAX_STALL_RESTARTS,
            )
            self._last_restart_t = now
            with contextlib.suppress(Exception):
                await self._ensure_fresh_stream(force=True)

    async def serve(self) -> None:
        """Run the HTTP server until cancelled / Ctrl-C."""
        http_server = await asyncio.start_server(self._handle_http, self._bind, self._http_port)
        watchdog = asyncio.create_task(self._stall_watchdog())
        # Eagerly start the HID worker so queued /touch requests are
        # processed even before the device-stream is fully up.
        self._hid_worker_task = asyncio.create_task(self._hid_worker())
        try:
            logger.info(f"Open http://{self._bind}:{self._http_port}/ in Safari/Chrome. Ctrl-C to stop.")
            await http_server.serve_forever()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            watchdog.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await watchdog
            await self._stop_hid()
            # _stop_hid no longer cancels the worker (it stays alive across
            # in-session stream restarts) -- so on real shutdown we cancel
            # it explicitly here.
            task = self._hid_worker_task
            self._hid_worker_task = None
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            async with self._stream_lock:
                await self._stop_active_stream()
            http_server.close()
            await http_server.wait_closed()
