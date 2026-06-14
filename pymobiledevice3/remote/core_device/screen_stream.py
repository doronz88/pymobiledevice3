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
from collections import deque
from pathlib import Path
from typing import Optional

from pymobiledevice3.remote.core_device.aac_eld import AAC_ELD_ASC_48K_STEREO_480, AACELDDecoder
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
# Non-ASCII glyphs (← / → arrows on the swipe buttons, plus em-dashes
# in JS comments) require a str literal -- bytes literals are
# ASCII-only. Encoded to UTF-8 at the end of the template so the rest
# of the file's .replace() / len() byte ops keep working as-is.
VIEWER_HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>iPhone screen</title>
<style>
 body{margin:0;background:#111;color:#ccc;font-family:system-ui;
      display:flex;flex-direction:column;align-items:center;justify-content:flex-start;
      min-height:100vh;gap:8px;padding:8px;box-sizing:border-box}
 /* Stage: device-side-mounted buttons flanking the canvas, matching
    where they live on an iPhone. Vol/Mute on the left side, Power/
    Siri on the right side. Home + utility actions sit below. */
 #stage{display:flex;align-items:stretch;justify-content:center;gap:8px;
        max-width:100vw}
 .side{display:flex;flex-direction:column;gap:6px;padding-top:18%}
 #side-left{align-items:flex-end}
 #side-right{align-items:flex-start}
 canvas{max-width:calc(100vw - 160px);max-height:calc(100vh - 120px);
        image-rendering:auto;touch-action:none;cursor:crosshair;background:#000}
 #bottom-row{display:flex;flex-wrap:wrap;gap:6px;justify-content:center;
             max-width:100vw}
 button.btn{background:#222;color:#ddd;border:1px solid #444;border-radius:6px;
            padding:8px 14px;font-size:13px;cursor:pointer;white-space:nowrap}
 button.btn:hover{background:#333}
 button.btn:active{background:#4a4a4a}
 /* Utility tray pinned to top-right: sound-toggle / forced-reset /
    force-restart -- low-frequency controls, kept out of the main
    button areas so the bottom row can stay device-only (Home). */
 #util-tray{position:fixed;top:8px;right:8px;display:flex;gap:6px;z-index:10}
 /* On narrow viewports give up the side-mounted layout and let the
    buttons wrap below the canvas like before. */
 @media (max-width: 700px){
  #stage{flex-direction:column;align-items:center}
  .side{flex-direction:row;flex-wrap:wrap;justify-content:center;padding-top:0}
  canvas{max-width:100vw;max-height:calc(100vh - 200px)}
 }
 /* Status / log overlay: pinned to top-left and capped at 220 px
    so it stays clear of the left-flank Vol / Mute buttons. */
 #status{position:fixed;top:8px;left:12px;font-size:12px;opacity:.8;
         background:#0008;padding:4px 8px;border-radius:4px;white-space:pre;
         width:220px;max-width:40vw;overflow:hidden;user-select:text;
         -webkit-user-select:text;cursor:text;pointer-events:auto;
         z-index:10}
</style></head>
<body>
<div id="stage">
 <!-- Left side of the device: mute switch + volume rocker -->
 <div id="side-left" class="side">
  <button class="btn" data-btn="mute" title="Ctrl+\">Mute</button>
  <button class="btn" data-btn="volume-up" title="Ctrl+]">Vol +</button>
  <button class="btn" data-btn="volume-down" title="Ctrl+[">Vol -</button>
 </div>
 <canvas id="c"></canvas>
 <!-- Right side of the device: side / power button (and Siri lives here too) -->
 <div id="side-right" class="side">
  <button class="btn" data-btn="power">Power</button>
  <button class="btn" data-btn="lock" title="Ctrl+L">Lock</button>
  <button class="btn" data-btn="sleep">Sleep</button>
  <button class="btn" data-btn="siri" title="Ctrl+S">Siri</button>
 </div>
</div>
<div id="bottom-row">
 <button class="btn" data-swipe="left" title="Swipe left across the middle of the screen">Swipe ←</button>
 <button class="btn" data-btn="home" title="Ctrl+H">Home</button>
 <button class="btn" data-swipe="right" title="Swipe right across the middle of the screen">Swipe →</button>
</div>
<div id="util-tray">
 <button class="btn" id="sound-toggle" type="button">Enable Sound</button>
 <button class="btn" id="forced-reset" type="button" title="rebuild decoder + new IDR">Forced Reset</button>
 <button class="btn" id="restart" type="button" title="full DisplayService restart">Force Restart</button>
</div>
<div id="status">connecting...</div>
<script>
window.AUDIO_DEFAULT_ON = __AUDIO_DEFAULT_ON__;
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

document.querySelectorAll('button[data-btn]').forEach(btn => {
    btn.addEventListener('click', () => {
        const name = btn.dataset.btn;
        postJson('/button', {name, state: 'press'}).then(() => log('button: ' + name));
    });
});

// Swipe synthesis: contact at the start edge, 10 intermediate
// contacts along the path, release at the end edge. ~200 ms total
// is in the same ballpark as a finger swipe, so iOS recognises it
// as a real gesture (faster gets misread as a flick + page snap,
// slower as a drag). Y stays at the vertical midpoint; X sweeps
// nearly edge-to-edge.
async function swipe(direction) {
    const yMid = 32768;
    const xStart = direction === 'left' ? 60000 : 5000;
    const xEnd   = direction === 'left' ? 5000  : 60000;
    const steps = 10;
    const dt = 20;  // ms between samples
    await postJson('/touch', {type: 'contact', x: xStart, y: yMid});
    for (let i = 1; i <= steps; i++) {
        const x = Math.round(xStart + (xEnd - xStart) * (i / steps));
        await new Promise(r => setTimeout(r, dt));
        await postJson('/touch', {type: 'contact', x, y: yMid});
    }
    await postJson('/touch', {type: 'release', x: xEnd, y: yMid});
    log('swipe ' + direction);
}
document.querySelectorAll('button[data-swipe]').forEach(btn => {
    btn.addEventListener('click', () => swipe(btn.dataset.swipe));
});

// Ctrl-hotkeys mirroring serve-vnc's _CTRL_COMBO_TO_HID:
//   Ctrl+H = Home, Ctrl+L = Lock, Ctrl+[ = Vol Down, Ctrl+] = Vol Up,
//   Ctrl+\ = Mute, Ctrl+S = Siri.
// Tooltips on the buttons advertise these. We use ctrlKey on every
// platform (Cmd is intercepted by browser shortcuts on macOS), match
// case-insensitively for letters, and preventDefault so we don't
// trigger the browser's own bindings (Ctrl+S = save, Ctrl+L = focus
// address bar in some browsers, etc.).
const CTRL_HOTKEYS = {
    'h': 'home',
    'l': 'lock',
    '[': 'volume-down',
    ']': 'volume-up',
    '\\': 'mute',
    's': 'siri',
};
window.addEventListener('keydown', (e) => {
    if (!e.ctrlKey || e.altKey || e.metaKey) return;
    const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
    const name = CTRL_HOTKEYS[key];
    if (!name) return;
    e.preventDefault();
    postJson('/button', {name, state: 'press'}).then(() => log('hotkey: ' + name));
});

// ----- Forced Reset: tell the server to spin up a fresh video stream
// (new IDR will reach this still-open /stream.bin connection via the
// type=2 reset path -- no page reload, audio context preserved).
// Fire-and-forget: the server's /restart endpoint responds 202 right
// away and runs the actual restart in the background, so the click
// feels instant.
document.getElementById('forced-reset').addEventListener('click', () => {
    log('forced reset');
    fetch('/restart', {method: 'POST', cache: 'no-store'})
        .then(r => log('forced reset: HTTP ' + r.status))
        .catch(e => log('forced reset err: ' + (e.message || e)));
});

// ----- Force Restart: drop the current video stream + reload the page.
// Heavier hammer than Forced Reset -- wipes all client-side state too.
document.getElementById('restart').addEventListener('click', async () => {
    log('forcing restart + reload...');
    try {
        await fetch('/restart', {method: 'POST', cache: 'no-store'});
    } catch (e) { log('restart err: ' + e.message); }
    setTimeout(() => location.reload(), 100);
});

// ----- Sound toggle: connect to /audio.bin which streams PRE-DECODED
// PCM (s16le, 48 kHz, stereo interleaved). The server uses pyav's
// aac_at codec (macOS AudioToolbox, hardware-backed) to decode AAC-ELD
// because Chrome's WebCodecs doesn't recognise mp4a.40.39 -- AAC-ELD
// isn't in its supported AAC object types. Decoding host-side is
// trivially cheap and adds ~1.5 Mbps over localhost.
let audioCtx = null;
let audioAbort = null;
let audioActive = false;
let audioReconnectPending = false;
const soundBtn = document.getElementById('sound-toggle');

async function startAudio() {
    if (audioActive) return;
    audioActive = true;
    soundBtn.textContent = 'Disable Sound';
    audioAbort = new AbortController();
    try {
        audioCtx = new AudioContext({ sampleRate: 48000, latencyHint: 'interactive' });
        await audioCtx.resume();
    } catch (e) { log('audioCtx err: ' + e.message); stopAudio(); return; }
    let nextStart = audioCtx.currentTime + 0.1; // 100 ms initial buffer
    let totalSamples = 0;

    const playPcm = (pcmBytes) => {
        // pcmBytes is interleaved int16 little-endian, stereo, 48 kHz.
        const i16 = new Int16Array(pcmBytes.buffer, pcmBytes.byteOffset,
                                   pcmBytes.byteLength >> 1);
        const frames = i16.length >> 1; // 2 channels
        if (frames === 0) return;
        const buf = audioCtx.createBuffer(2, frames, 48000);
        const left = buf.getChannelData(0);
        const right = buf.getChannelData(1);
        const INV = 1 / 32768;
        for (let i = 0, j = 0; i < frames; i++, j += 2) {
            left[i] = i16[j] * INV;
            right[i] = i16[j + 1] * INV;
        }
        const src = audioCtx.createBufferSource();
        src.buffer = buf;
        src.connect(audioCtx.destination);
        if (nextStart < audioCtx.currentTime) {
            // Schedule fell behind (UI stall) -- jump forward to keep latency bounded.
            nextStart = audioCtx.currentTime + 0.05;
        }
        src.start(nextStart);
        nextStart += buf.duration;
        totalSamples += frames;
    };

    try {
        const resp = await fetch('/audio.bin', { signal: audioAbort.signal });
        if (!resp.ok) {
            const body = await resp.text();
            log('audio HTTP ' + resp.status + ': ' + body.trim());
            stopAudio();
            return;
        }
        const reader = resp.body.getReader();
        let buf = new Uint8Array(0);
        log('audio stream open');
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            const merged = new Uint8Array(buf.length + value.length);
            merged.set(buf); merged.set(value, buf.length);
            buf = merged;
            while (buf.length >= 4) {
                const len = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
                if (buf.length < 4 + len) break;
                const pcmBytes = buf.slice(4, 4 + len);
                buf = buf.subarray(4 + len);
                if (!pcmBytes.length) continue;
                try { playPcm(pcmBytes); }
                catch (e) { log('audio play err: ' + e.message); }
            }
        }
    } catch (e) {
        if (e.name !== 'AbortError') log('audio fetch err: ' + e.message);
    }
    log('audio stream closed (' + totalSamples + ' samples)');
    // If we didn't stop voluntarily (e.g. server tore down audio after a
    // /restart), auto-reconnect after a short delay -- iOS needs ~1 s
    // between sessions to come back cleanly. The reconnect is cancelled
    // if the user clicks Disable Sound in the interim.
    const wasActive = audioActive;
    audioActive = false;
    soundBtn.textContent = 'Enable Sound';
    if (audioCtx) { try { audioCtx.close(); } catch (_) {} audioCtx = null; }
    audioAbort = null;
    if (wasActive) {
        audioReconnectPending = true;
        log('audio: auto-reconnecting in 1 s');
        setTimeout(() => {
            if (audioReconnectPending) {
                audioReconnectPending = false;
                startAudio();
            }
        }, 1000);
    }
}

function stopAudio() {
    audioActive = false;
    audioReconnectPending = false;
    soundBtn.textContent = 'Enable Sound';
    if (audioAbort) { try { audioAbort.abort(); } catch (_) {} audioAbort = null; }
    if (audioCtx) { try { audioCtx.close(); } catch (_) {} audioCtx = null; }
}

soundBtn.addEventListener('click', () => {
    if (audioActive) stopAudio(); else startAudio();
});

// AUDIO_DEFAULT_ON is templated by the server at request time (replaced
// in the HTML body by the /index.html handler). When true, we start the
// audio pipeline immediately so the browser is already buffering PCM by
// the time the user does something -- their first gesture resumes the
// suspended AudioContext and they hear audio with no extra clicks.
if (window.AUDIO_DEFAULT_ON) {
    startAudio();
    function resumeAudioOnGesture() {
        if (audioCtx && audioCtx.state === 'suspended') {
            audioCtx.resume().then(() => log('audio resumed (state=' + audioCtx.state + ')'));
        }
    }
    ['pointerdown', 'click', 'keydown', 'touchstart'].forEach(ev => {
        document.addEventListener(ev, resumeAudioOnGesture, { capture: true });
    });
}

async function fetchCodecWithRetry() {
    // /codec triggers a device-side stream restart on first call -- on a
    // cold daemon that can take 6-10 s, and sometimes the RemoteXPC
    // handshake just fails outright. Retry with backoff so a transient
    // failure doesn't leave the viewer permanently dead.
    const delays = [200, 500, 1000, 2000, 3000, 4000];
    let lastErr = '';
    for (let attempt = 0; attempt <= delays.length; attempt++) {
        if (attempt > 0) {
            log('codec retry #' + attempt + ' in ' + delays[attempt - 1] + 'ms (' + lastErr + ')');
            await new Promise(r => setTimeout(r, delays[attempt - 1]));
        }
        try {
            const resp = await fetch('/codec', { cache: 'no-store' });
            if (!resp.ok) { lastErr = 'HTTP ' + resp.status; continue; }
            const codec = (await resp.text()).trim();
            if (!codec) { lastErr = 'empty body (SPS not yet seen)'; continue; }
            return codec;
        } catch (e) {
            lastErr = e.message || String(e);
        }
    }
    throw new Error('codec unreachable after retries: ' + lastErr);
}

async function run() {
    log('userAgent: ' + navigator.userAgent.slice(0, 80));
    const codec = await fetchCodecWithRetry();
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
    let autoRestartUsed = false; // self-heal once if the bootstrap path errors
    const buildDecoder = () => new VideoDecoder({
        output: (frame) => {
            // Apple's encoder signals slightly different displayWidth/Height
            // across frames (we've measured 1264x2752 oscillating with
            // 1264x2736 mid-stream as the iOS home indicator toggles). If
            // we resize the canvas on every change the entire <canvas>
            // visibly shrinks/expands -- that's the "screen changing size"
            // pattern the user sees. Lock the canvas to the largest size
            // we've seen so frames just draw into the existing surface.
            // Resize the canvas buffer to match each frame's exact
            // dimensions. We used to lock the canvas to the largest size
            // ever seen (to keep the page layout from jittering when iOS
            // toggles the home-indicator between 2752/2736 pixels mid-
            // stream), but that left the canvas buffer at max-ever size
            // forever -- and even with drawImage-stretch fillout, the
            // browser still carries stale GPU-side state from prior
            // frames that shows up as torn strips during motion.
            // Reassigning canvas.width/.height resets the entire buffer
            // and reattaches a fresh GPU texture, mirroring what a full
            // page reload does. Page layout stability comes from the
            // canvas CSS (max-width/max-height + aspect-ratio if you want
            // to lock that explicitly).
            if (frame.displayWidth !== canvas.width || frame.displayHeight !== canvas.height) {
                canvas.width = frame.displayWidth;
                canvas.height = frame.displayHeight;
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
            // Bootstrap-failure self-heal: if we error out before we've
            // shown even a handful of frames, Apple's encoder almost
            // certainly emitted a POC chain WebCodecs can't follow (the
            // server-side phantom synthesis didn't bridge it cleanly for
            // this device's encoder). Asking the server for a fresh
            // stream often produces a sequential POC chain that decodes
            // cleanly. Do it at most once -- if it errors again the
            // problem isn't transient and the user can click "Forced
            // Reset" manually.
            if (!autoRestartUsed && frameCount < 5) {
                autoRestartUsed = true;
                log('auto /restart (bootstrap decode err)');
                fetch('/restart', {method: 'POST', cache: 'no-store'})
                    .then(r => log('auto restart: HTTP ' + r.status))
                    .catch(err => log('auto restart err: ' + err.message));
            } else {
                // Post-bootstrap decode error: kick the device for a
                // fresh IDR via the lightweight /pli path (no full
                // session restart). The next IDR triggers the
                // `needsResync` rebuild below in the data loop.
                fetch('/pli', {method: 'POST', cache: 'no-store'})
                    .catch(err => log('/pli err: ' + err.message));
            }
        },
    });
    let decoder = buildDecoder();
    decoder.configure({ codec, optimizeForLatency: true });
    log('state after configure: ' + decoder.state);

    // /stream.bin can return 503 if the force-restart on the server failed
    // (e.g. RemoteXPC handshake stuck) -- retry with backoff so a flaky
    // device daemon doesn't leave the viewer permanently dead.
    let resp = null;
    const streamDelays = [200, 500, 1000, 2000, 3000, 5000];
    for (let a = 0; a <= streamDelays.length; a++) {
        if (a > 0) {
            log('stream retry #' + a + ' in ' + streamDelays[a - 1] + 'ms');
            await new Promise(r => setTimeout(r, streamDelays[a - 1]));
        }
        try {
            const r = await fetch('/stream.bin', { cache: 'no-store' });
            if (r.ok) { resp = r; break; }
            const body = await r.text();
            log('stream HTTP ' + r.status + ': ' + body.slice(0, 80));
        } catch (e) {
            log('stream fetch err: ' + (e.message || e));
        }
    }
    if (!resp) { log('FAIL: /stream.bin unreachable'); return; }
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
                try { decoder.close(); } catch (e) {}
                decoder = buildDecoder();
                decoder.configure({ codec, optimizeForLatency: true });
                needsResync = false;
                gotKey = true;
                log('forced reset @ key after upstream drop');
            } else if (type === 0) {
                gotKey = true;
                if (needsResync) {
                    try { decoder.close(); } catch (e) {}
                    decoder = buildDecoder();
                    decoder.configure({ codec, optimizeForLatency: true });
                    needsResync = false;
                    log('resynced @ key after ' + decodeErrCount + ' decode err(s)');
                }
            }
            if (!gotKey) continue;
            if (needsResync) continue;
            if (decoder.state !== 'configured') {
                log('decoder ' + decoder.state + ' @' + sentCount + ' - rebuilding');
                try { decoder.close(); } catch (e) {}
                decoder = buildDecoder();
                decoder.configure({ codec, optimizeForLatency: true });
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
""".encode()


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


async def capture_audio_rtp_to_file(
    rsd: RemoteServiceDiscoveryService,
    output_path: Path,
    *,
    duration: float = 10.0,
    receiver_port: int = 0,
) -> int:
    """Audio counterpart of :func:`capture_rtp_to_file`. Saves the raw RTP
    packets (length-prefixed) the device pushes for ``type='audio'``.

    The streamConfig the device returns advertises ``RxPayloadType=101`` and
    ``AudioStreamMode=8`` -- Apple AAC-ELD at 48 kHz stereo, 480 samples/frame
    (10 ms). Used by ``pymobiledevice3 ... display start-audio-stream``.
    """
    sender_ip = rsd.service.address[0]
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(("::", receiver_port))
    bound_port = sock.getsockname()[1]
    logger.info(f"Listening for AUDIO RTP on [{sender_ip}] → ::{bound_port}")

    captured = 0
    async with DisplayService(rsd) as service:
        local_ip = service.service.local_address[0]
        answer = await service.start_audio_stream(
            receiver_ip=local_ip,
            receiver_port=bound_port,
            sender_ip=sender_ip,
        )
        cfg = answer["connection"].get("streamConfig", {})
        logger.info(
            "Audio stream started: PT=%s mode=%s sender_port=%s",
            cfg.get("RxPayloadType"),
            cfg.get("AudioStreamMode"),
            cfg.get("SourcePort"),
        )
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
        logger.info(f"Captured {captured} audio packets to {output_path}")
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
        audio_default_on: bool = True,
    ) -> None:
        self._rsd = rsd
        self._bind = bind
        self._http_port = http_port
        self._display_id = display_id
        self._audio_default_on = audio_default_on
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
        # Raw parameter-set / IDR NALs cached for phantom synthesis. The
        # phantom NAL block bridges the bootstrap POC gap (Apple's encoder
        # emits IDR=POC0 then jumps the first delta to POC=~163 with refs
        # to a sparse set the decoder never received). Synthesising
        # phantoms at the needed POCs lets WebCodecs decode the chain.
        self._cached_vps_nal: Optional[bytes] = None
        self._cached_sps_nal: Optional[bytes] = None
        self._cached_pps_nal: Optional[bytes] = None
        self._cached_idr_nal: Optional[bytes] = None
        self._phantoms_built = False

        # Active device-stream session.
        self._active_service: Optional[DisplayService] = None
        self._active_session_id: Optional[uuid.UUID] = None
        self._active_sock: Optional[socket.socket] = None
        self._active_recv_task: Optional[asyncio.Task] = None
        self._active_rtcp_task: Optional[asyncio.Task] = None
        self._stream_lock = asyncio.Lock()
        self._stream_dirty = True  # True → next request must restart the stream

        # Audio stream session (parallel to video, started lazily when a
        # browser tab subscribes to /audio.bin). Each AAC-ELD AU is
        # broadcast as a length-prefixed chunk.
        self._audio_service: Optional[DisplayService] = None
        self._audio_session_id: Optional[uuid.UUID] = None
        self._audio_sock: Optional[socket.socket] = None
        self._audio_recv_task: Optional[asyncio.Task] = None
        self._audio_subscribers: dict[asyncio.Queue[bytes], None] = {}
        self._audio_lock = asyncio.Lock()
        # Audio RTCP bookkeeping -- parallel to the video fields below.
        # The device's audio streamConfig has the same RTCPTimeoutEnabled
        # + RTCPTimeoutInterval=20s as video; without a periodic RR the
        # audio session gets reaped after ~20 s (the encoder stops
        # emitting RTP audio and mediastreamstatus drops the session).
        self._audio_rtcp_dest: Optional[tuple[str, int]] = None
        self._audio_local_ssrc: int = 0
        self._audio_remote_ssrc: int = 0
        self._audio_rtp_highest_seq: int = 0
        self._audio_rtp_packets_received: int = 0
        self._audio_rtcp_task: Optional[asyncio.Task] = None
        # Xcode's Mirror uses ONE client_session_id for both the audio
        # and video mediastreamstart calls (confirmed verbatim in the
        # remotexpc-sniff4 capture: same UUID in both 'CoreDevice.input'
        # payloads). Pairing them on the device's media-session manager
        # is what marks us as a real Mirror client rather than two
        # unrelated callers; without it iOS may treat the lone video
        # session as a second-class consumer and throttle the encoder.
        self._shared_session_id: uuid.UUID = uuid.uuid4()

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
        # Last decoder-refresh timestamp + the byte-rate motion window
        # the refresh loop uses to detect "motion just ended" -- the
        # moment when tears accumulate and a fresh-IDR rebuild is most
        # useful. Catches device-side touches too (real finger on the
        # device) because they drive the encoder's byte rate up just
        # like browser-driven /touch.
        self._last_refresh_t: float = 0.0
        # (timestamp, AU bytes) entries pruned to the last 1 s.
        self._au_byte_window: deque = deque()
        # True while AU byte rate is above the motion threshold.
        self._motion_active: bool = False
        # When the active->idle transition happened (0 = never / since reset).
        self._motion_ended_t: float = 0.0

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
                # Cache the parameter sets + IDR slice as raw NALs so we
                # can synthesise phantoms later from the captured IDR body.
                if nt == _HEVC_NAL_VPS:
                    self._cached_vps_nal = bytes(nal)
                elif nt == _HEVC_NAL_SPS:
                    self._cached_sps_nal = bytes(nal)
                elif nt == _HEVC_NAL_PPS:
                    self._cached_pps_nal = bytes(nal)
                elif _is_key_nal(nt):
                    self._cached_idr_nal = bytes(nal)
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
                    # Feed the motion-detection window. The refresh loop
                    # reads this to know when motion settles.
                    self._au_byte_window.append((self._last_good_au_t, len(annexb)))
                    if self._saw_first_key:
                        # First non-key AU after the IDR is the moment we
                        # can synthesise phantoms (we need the delta's
                        # slice header to know which POCs are referenced).
                        phantom_msgs: list[bytes] = []
                        if (
                            not au_is_key
                            and not self._phantoms_built
                            and self._cached_vps_nal is not None
                            and self._cached_sps_nal is not None
                            and self._cached_pps_nal is not None
                            and self._cached_idr_nal is not None
                        ):
                            try:
                                first_delta_nal = current_au[0]
                                phantoms = build_phantoms_for_bootstrap(
                                    self._cached_vps_nal,
                                    self._cached_sps_nal,
                                    self._cached_pps_nal,
                                    self._cached_idr_nal,
                                    first_delta_nal,
                                )
                                logger.info(
                                    "Phantom synthesis: first delta NAL %d B (type=%d), produced %d phantoms",
                                    len(first_delta_nal),
                                    (first_delta_nal[0] >> 1) & 0x3F,
                                    len(phantoms),
                                )
                            except Exception:
                                logger.exception("phantom synthesis failed")
                                phantoms = []
                            if phantoms:
                                logger.info(
                                    "Synthesised %d phantom NALs for bootstrap",
                                    len(phantoms),
                                )
                                for ph in phantoms:
                                    ph_annexb = b"\x00\x00\x00\x01" + ph
                                    ph_msg = (len(ph_annexb) + 1).to_bytes(4, "big") + b"\x00" + ph_annexb
                                    phantom_msgs.append(ph_msg)
                                # Bake into init_sequence so late-joining
                                # subscribers also get them.
                                if self._init_sequence is not None:
                                    self._init_sequence = self._init_sequence + b"".join(phantom_msgs)
                            self._phantoms_built = True

                        for q, state in list(self._subscribers.items()):
                            if q.full():
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
                            for pm in phantom_msgs:
                                q.put_nowait(pm)
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

    def _build_audio_rtcp_rr(self) -> bytes:
        """Audio-side counterpart of :meth:`_build_rtcp_rr` (RFC 3550 §6.4.2).
        Identical packet shape; just uses the audio session's SSRCs and
        extended-highest-seq counter."""
        import struct as _struct

        return _struct.pack(
            "!BBHII BBBB IIII",
            0x81,
            0xC9,
            7,
            self._audio_local_ssrc & 0xFFFFFFFF,
            self._audio_remote_ssrc & 0xFFFFFFFF,
            0,
            0,
            0,
            0,
            self._audio_rtp_highest_seq & 0xFFFFFFFF,
            0,
            0,
            0,
        )

    async def _audio_rtcp_send_loop(self, sock: socket.socket) -> None:
        """Periodically send RTCP RR for the audio stream. Without this
        the device reaps the audio session after ~20 s (RTCPTimeoutInterval)
        and the encoder silently stops emitting RTP audio packets --
        mediastreamstatus confirmed the audio session disappears from the
        sessions list when we don't RR."""
        loop = asyncio.get_running_loop()
        while True:
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return
            if self._audio_rtcp_dest is None or self._audio_rtp_packets_received == 0:
                continue
            packet = self._build_audio_rtcp_rr()
            try:
                await loop.sock_sendto(sock, packet, (*self._audio_rtcp_dest, 0, 0))
            except OSError as exc:
                logger.debug("audio RTCP send failed (%s); the socket may be torn down", exc)
                return

    @staticmethod
    def _missing_audio_deps() -> list[str]:
        """Audio decode uses macOS's AudioToolbox via ctypes -- no pip
        dependencies required. Kept as a method so /audio.bin can return
        a clear error on non-macOS hosts."""
        import sys

        return [] if sys.platform == "darwin" else ["macOS (AudioToolbox)"]

    # ----- audio-stream lifecycle (parallel to video) ----------------------
    # AAC-ELD decode lives in :mod:`aac_eld`; see that module for the
    # AudioToolbox-via-ctypes plumbing. Output here is s16le 48 kHz
    # stereo interleaved PCM, broadcast in length-prefixed chunks to
    # /audio.bin subscribers (~192 KB/s).
    async def _audio_udp_recv(self, sock: socket.socket) -> None:
        """Receive RTP audio packets, strip the RTP header, decode the
        AAC-ELD AU via AudioToolbox, and broadcast the interleaved s16le
        PCM to /audio.bin subscribers."""
        try:
            decoder = AACELDDecoder(AAC_ELD_ASC_48K_STEREO_480)
        except Exception:
            logger.exception("AudioToolbox AAC-ELD decoder failed to open")
            return
        logger.info("audio decoder ready: AudioToolbox AAC-ELD -> s16le 48k stereo")

        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        # Volume changes on the device side can land us with a packet
        # the decoder rejects -- and once AudioConverter has errored, all
        # subsequent FillComplexBuffer calls fail too. Track consecutive
        # failures and recreate the decoder from scratch when we cross
        # the threshold so a single hiccup doesn't permanently kill the
        # audio stream.
        consecutive_errors = 0
        _ERR_RECREATE_THRESHOLD = 5

        while True:
            try:
                data = await loop.sock_recv(sock, 65535)
            except (OSError, asyncio.CancelledError):
                return
            except Exception:
                logger.exception("audio recv task crashed")
                return
            if len(data) < 12:
                continue
            pt = data[1] & 0x7F
            if 64 <= pt <= 95:  # RTCP -- ignore
                continue
            # Track sequence + receive count so our RR reports a sensible
            # extended-highest-seq field. Without this the encoder reaps
            # the audio session after 20 s (RTCPTimeoutInterval).
            self._audio_rtp_packets_received += 1
            seq = int.from_bytes(data[2:4], "big")
            cur_ext = self._audio_rtp_highest_seq
            cycles = (cur_ext >> 16) & 0xFFFF
            last_seq16 = cur_ext & 0xFFFF
            if seq < last_seq16 and (last_seq16 - seq) > 0x8000:
                cycles = (cycles + 1) & 0xFFFF
            new_ext = (cycles << 16) | seq
            if cur_ext == 0 or ((new_ext - cur_ext) & 0xFFFFFFFF) < 0x80000000:
                self._audio_rtp_highest_seq = new_ext
            cc = data[0] & 0x0F
            header_len = 12 + cc * 4
            if data[0] & 0x10:  # extension
                if header_len + 4 > len(data):
                    continue
                ext_len = int.from_bytes(data[header_len + 2 : header_len + 4], "big")
                header_len += 4 + ext_len * 4
            payload = data[header_len:]
            if not payload:
                continue
            try:
                pcm = decoder.decode(payload)
                consecutive_errors = 0
            except Exception as exc:
                consecutive_errors += 1
                logger.debug("audio decode failed (%s) -- dropping packet", exc)
                if consecutive_errors >= _ERR_RECREATE_THRESHOLD:
                    logger.warning(
                        "audio decoder stuck after %d consecutive errors -- recreating",
                        consecutive_errors,
                    )
                    try:
                        decoder = AACELDDecoder(AAC_ELD_ASC_48K_STEREO_480)
                        consecutive_errors = 0
                    except Exception:
                        logger.exception("audio decoder recreation failed")
                continue
            if not pcm:
                continue
            msg = len(pcm).to_bytes(4, "big") + pcm
            for q in list(self._audio_subscribers.keys()):
                if q.full():
                    with contextlib.suppress(asyncio.QueueEmpty):
                        q.get_nowait()
                q.put_nowait(msg)

    async def _stop_audio_stream(self) -> None:
        svc = self._audio_service
        sid = self._audio_session_id
        sock = self._audio_sock
        task = self._audio_recv_task
        rtcp_task = self._audio_rtcp_task
        self._audio_service = None
        self._audio_session_id = None
        self._audio_sock = None
        self._audio_recv_task = None
        self._audio_rtcp_task = None
        self._audio_rtcp_dest = None
        if rtcp_task is not None:
            rtcp_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await rtcp_task
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if sock is not None:
            with contextlib.suppress(Exception):
                sock.close()
        if svc is not None:
            with contextlib.suppress(Exception):
                if sid is not None:
                    await svc.stop_media_stream(sid)
            with contextlib.suppress(Exception):
                await svc.close()

    async def _ensure_audio_stream(self) -> None:
        async with self._audio_lock:
            if (
                self._audio_service is not None
                and self._audio_recv_task is not None
                and not self._audio_recv_task.done()
            ):
                return
            await self._stop_audio_stream()
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.bind(("::", 0))
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 * 1024 * 1024)
            port = sock.getsockname()[1]
            svc = DisplayService(self._rsd)
            await svc.connect()
            local_ip = svc.service.local_address[0]
            # Same shared client_session_id as the video stream so the
            # device pairs them on its media-session manager (Xcode's
            # Mirror does this -- confirmed in the remotexpc sniff).
            answer = await svc.start_audio_stream(
                receiver_ip=local_ip,
                receiver_port=port,
                sender_ip=self._sender_ip,
                client_session_id=self._shared_session_id,
            )
            sid = answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
            if not isinstance(sid, uuid.UUID):
                sid = uuid.UUID(sid)
            cfg = answer["connection"].get("streamConfig", {})
            logger.info(
                "audio stream started: PT=%s mode=%s sender_port=%s",
                cfg.get("RxPayloadType"),
                cfg.get("AudioStreamMode"),
                cfg.get("SourcePort"),
            )
            # Same SSRC-naming convention as video: device's streamConfig
            # uses its perspective, so LocalSSRC is the device's, RemoteSSRC
            # is ours. Source-port + sender-IP is where we send RTCP.
            source_port = int(cfg.get("SourcePort", 0))
            self._audio_local_ssrc = int(cfg.get("RemoteSSRC", 0))  # ours
            self._audio_remote_ssrc = int(cfg.get("LocalSSRC", 0))  # device's
            self._audio_rtp_highest_seq = 0
            self._audio_rtp_packets_received = 0
            self._audio_rtcp_dest = (self._sender_ip, source_port) if source_port else None
            self._audio_service = svc
            self._audio_session_id = sid
            self._audio_sock = sock
            self._audio_recv_task = asyncio.create_task(self._audio_udp_recv(sock))
            # Keep the audio session alive by RR'ing every second.
            # RTCPTimeoutInterval=20 s by default; without this the
            # device reaps the audio session, mediastreamstatus drops it,
            # and the encoder stops emitting (silently).
            if self._audio_rtcp_dest is not None and self._audio_local_ssrc and self._audio_remote_ssrc:
                self._audio_rtcp_task = asyncio.create_task(self._audio_rtcp_send_loop(sock))
            else:
                logger.warning(
                    "audio RTCP disabled (missing fields: SourcePort=%s LocalSSRC=%s RemoteSSRC=%s)",
                    source_port,
                    self._audio_local_ssrc,
                    self._audio_remote_ssrc,
                )

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
            self._cached_vps_nal = None
            self._cached_sps_nal = None
            self._cached_pps_nal = None
            self._cached_idr_nal = None
            self._phantoms_built = False
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
            # Pass the shared client_session_id so the device sees us as
            # one Mirror client across audio + video, matching Xcode.
            answer = await svc.start_video_stream(
                receiver_ip=local_ip,
                receiver_port=port,
                sender_ip=self._sender_ip,
                display_id=self._display_id,
                client_session_id=self._shared_session_id,
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
            body = VIEWER_HTML.replace(
                b"__AUDIO_DEFAULT_ON__",
                b"true" if self._audio_default_on else b"false",
            )
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
            writer.close()
            return
        if path == "/codec":
            # Bounded path so the browser never sees a fetch hang: cap the
            # whole thing at ~7 s. If the device-stream isn't up by then
            # return 503 -- the JS retries with backoff, and meanwhile
            # the in-flight ensure_fresh_stream keeps running so a later
            # /codec usually succeeds. Without this bound the cold path
            # can stall for ~30 s on a stuck CoreDevice daemon and the
            # browser surfaces it as "failed to fetch".
            try:
                await asyncio.wait_for(self._ensure_fresh_stream(force=False), timeout=5.0)
            except asyncio.TimeoutError:
                writer.write(b"HTTP/1.1 503 Stream Starting\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            except Exception:
                logger.exception("failed to start device stream")
                writer.write(b"HTTP/1.1 500 Internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stream_ready.wait(), timeout=2.0)
            body = (self._codec_string or "").encode()
            status = b"200 OK" if body else b"503 Stream Starting"
            writer.write(
                b"HTTP/1.1 " + status + b"\r\n"
                b"Content-Type: text/plain\r\n"
                b"Cache-Control: no-store\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
            writer.close()
            return
        if path == "/restart":
            # Respond 202 immediately and run the actual restart in the
            # background. The video restart + audio teardown takes
            # several seconds (device-side start_video_stream RPC), and
            # the caller doesn't need to wait for it -- the new IDR
            # reaches their /stream.bin connection via the type=2 reset
            # path whenever the device gets around to emitting it, and
            # the audio JS auto-reconnects /audio.bin on its own. (Also
            # avoids the "button feels slow" effect that comes from JS
            # awaiting a slow round-trip.)
            async def _restart_bg():
                # Just restart video. Leave audio alone -- audio shares
                # the client_session_id with video (Xcode-style pairing),
                # so tearing audio down between video restart and the
                # browser's /audio.bin reconnect leaves the device with
                # an unpaired lone video session, which iOS treats as a
                # second-class client and throttles. Symptom was the
                # browser sticking on "frames: 1" after a Forced Reset
                # until the user reloaded and re-attached /audio.bin.
                with contextlib.suppress(Exception):
                    await self._ensure_fresh_stream(force=True)

            bg = asyncio.create_task(_restart_bg())
            self._pli_tasks.add(bg)  # piggy-back on the existing keep-alive set
            bg.add_done_callback(self._pli_tasks.discard)
            writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()
            return
        if path == "/pli":
            # Lightweight recovery: ask the device for a fresh IDR via
            # RTCP PLI and mark all subscribers as needing a key, but
            # DO NOT restart the DisplayService session. ``/restart``
            # tears down + re-RPCs the whole pipeline (~several
            # seconds, several-MB IDR burst); ``/pli`` is a single
            # RTCP packet and the new IDR arrives in ~100-300 ms.
            # The browser's decode-error handler hits this when
            # WebCodecs throws post-bootstrap, instead of waiting for
            # the next ``_decoder_refresh_loop`` tick.
            loop = asyncio.get_running_loop()
            if self._active_service is not None and self._rtcp_dest is not None:
                self._fire_decoder_refresh(loop.time(), reason="browser-pli")
            writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()
            return
        if path == "/audio.bin":
            # Up-front dep check so the browser doesn't silently see "0
            # samples" when av/numpy aren't installed (the old failure
            # mode -- the audio recv task would crash on the first
            # frame.to_ndarray() and /audio.bin would just hang).
            missing = self._missing_audio_deps()
            if missing:
                body = (
                    f"audio disabled: missing python package(s): {', '.join(missing)}.\n"
                    f"reinstall pymobiledevice3 (uv tool install ... --reinstall) or pip install {' '.join(missing)}."
                ).encode()
                writer.write(
                    b"HTTP/1.1 503 Audio Unavailable\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                await writer.drain()
                writer.close()
                return
            try:
                await self._ensure_audio_stream()
            except Exception:
                logger.exception("failed to start audio stream")
                writer.write(b"HTTP/1.1 500 Internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Cache-Control: no-cache\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            # ~64 packets at 10 ms each = 640 ms of headroom. Enough to
            # absorb a JS hiccup without dropping audio in the kernel.
            queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=64)
            self._audio_subscribers[queue] = None
            try:
                while True:
                    msg = await queue.get()
                    writer.write(f"{len(msg):x}\r\n".encode() + msg + b"\r\n")
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            finally:
                self._audio_subscribers.pop(queue, None)
                with contextlib.suppress(Exception):
                    writer.close()
                # We DON'T tear down the iOS audio session when the last
                # subscriber leaves. Empirically iOS refuses to deliver
                # packets after a few session restarts in the same server
                # process -- start_audio_stream returns success but the
                # device sends nothing. Once started, we keep the session
                # alive for the rest of the server's lifetime so subsequent
                # /audio.bin connects always reuse the working session.
                # (Cleaned up at shutdown by serve()'s finally block.)
            return
        if path != "/stream.bin":
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Bring the stream up if it isn't already, but don't force a
        # restart when it's already running. The previous behaviour
        # (force=True on every subscriber connect) tore the device-side
        # session down and back up for every new tab; under stress that
        # left the device's DisplayService XPC channel wedged (handshake
        # timeouts) and matched nothing Xcode does in the sniff. Instead
        # we send a PLI below and mark this subscriber as ``needs_key``
        # so it sees the live stream cleanly from the next IDR onward.
        if self._active_service is None or self._init_sequence is None:
            try:
                await asyncio.wait_for(self._ensure_fresh_stream(force=False), timeout=10.0)
            except (asyncio.TimeoutError, Exception):
                logger.exception("/stream.bin: stream start failed -- replying 503")
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._stream_ready.wait(), timeout=3.0)

        # Ask the device to emit a fresh IDR for this new subscriber.
        # Combined with the ``needs_key=True`` state on the subscriber
        # below, the broadcast loop will skip live deltas until the
        # IDR arrives and then send it as a RESET keyframe so the
        # browser rebuilds its decoder cleanly.
        if self._active_service is not None and self._rtcp_dest is not None:
            pli_task = asyncio.create_task(self._send_rtcp_pli())
            self._pli_tasks.add(pli_task)
            pli_task.add_done_callback(self._pli_tasks.discard)

        if self._init_sequence is None or self._active_service is None:
            body = b"stream not ready -- retry in a moment"
            writer.write(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
            writer.close()
            return

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
        # New subscribers start with needs_key=True so the broadcast
        # loop holds live deltas until the PLI-induced IDR arrives
        # (deltas reference frames this subscriber never saw, otherwise
        # WebCodecs renders them as silent tears). The IDR will land as
        # a RESET keyframe, prompting the browser to rebuild its decoder.
        state = _SubState()
        state.needs_key = True
        self._subscribers[queue] = state
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

    async def _decoder_refresh_loop(self) -> None:
        """Force connected browsers to rebuild their video decoders
        WHEN it's likely to help, not on a fixed timer.

        VideoToolbox (and Safari's WebCodecs wrapper around it) silently
        accumulates stale long-term-reference-picture state under heavy
        motion -- decode reports success on every frame but the rendered
        pixels are torn. There's no error callback; the only known
        recovery is to rebuild the decoder around a fresh IDR (what a
        manual page reload achieves).

        Each rebuild has a small cost: a ~30 ms frame gap while we wait
        for the IDR + the new decoder's first output. At high cadences
        (e.g. 2 refreshes/sec) the gap becomes visible "chop". The
        smoothest experience is one rebuild per motion event, fired
        right after motion settles -- the same UX pattern as a manual
        reload after the user finishes interacting.

        We use the device's RTP byte rate as the motion signal (works
        for ANY motion source -- browser /touch, finger on the device,
        a system animation). Idle is ~30-60 KB/s, motion is 150+ KB/s.

        Triggers:
        1. Active: motion is currently happening and ``active_interval``
           has passed since the last refresh. Without this, tears
           accumulate the entire time the user is interacting; the next
           refresh wouldn't come until motion ends + settle_delay or
           the heartbeat fires (up to 10 s later).
        2. Motion settled: AU byte rate dropped below the threshold
           AFTER having been above it, and ``settle_delay`` has passed.
        3. Heartbeat: max ``heartbeat`` seconds between refreshes as a
           safety net for slow-creeping tears that don't correlate with
           our motion signal.

        ``min_interval`` caps back-to-back refreshes regardless of
        trigger.
        """
        loop = asyncio.get_running_loop()
        motion_threshold_bps = 100_000  # 100 KB/s = motion
        active_interval = 1.5  # fire this often during sustained motion
        settle_delay = 0.4  # wait after motion ends before refresh
        heartbeat = 10.0  # max between refreshes when idle
        min_interval = 1.0  # don't fire more often than this
        while True:
            try:
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                return
            if not self._subscribers:
                continue
            if self._active_service is None or self._rtcp_dest is None:
                continue
            now = loop.time()
            # Prune the byte window to the last 1 s.
            while self._au_byte_window and self._au_byte_window[0][0] < now - 1.0:
                self._au_byte_window.popleft()
            window_bytes = sum(s for _, s in self._au_byte_window)
            currently_active = window_bytes >= motion_threshold_bps
            # Detect active->idle transition (motion just ended).
            if self._motion_active and not currently_active:
                self._motion_ended_t = now
            self._motion_active = currently_active
            since_refresh = now - self._last_refresh_t
            if since_refresh < min_interval:
                continue
            active = currently_active and since_refresh >= active_interval
            settled = self._motion_ended_t > self._last_refresh_t and (now - self._motion_ended_t) >= settle_delay
            heartbeat_due = since_refresh >= heartbeat
            if not (active or settled or heartbeat_due):
                continue
            reason = "active" if active else ("settled" if settled else "heartbeat")
            self._fire_decoder_refresh(now, reason=reason)

    def _fire_decoder_refresh(self, now: float, *, reason: str) -> None:
        for q, state in self._subscribers.items():
            while not q.empty():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            state.needs_key = True
        pli_task = asyncio.create_task(self._send_rtcp_pli())
        self._pli_tasks.add(pli_task)
        pli_task.add_done_callback(self._pli_tasks.discard)
        self._last_refresh_t = now
        # Window-bytes here are just the current 1 s sum; useful when
        # tuning the motion threshold against real byte-rates from the
        # device's encoder under various activity levels.
        window_bps = sum(s for _, s in self._au_byte_window)
        logger.info(
            "decoder-refresh (%s): %d subscriber(s), %d B/s window",
            reason,
            len(self._subscribers),
            window_bps,
        )

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

    async def _eager_stream_start(self) -> None:
        """Bring the device-side streams up at server boot.

        Two reasons to start eagerly:
        1. The video codec string is cached by the time the browser
           opens, avoiding the ~6-10 s cold-start "failed to fetch"
           on the first /codec request.
        2. Xcode's Mirror always brings up BOTH audio and video at
           session start with a shared client_session_id (sniff4
           confirms). Without the paired audio session, iOS's media
           manager treats us as a lone video client and may throttle
           the encoder. Audio runs from boot regardless of whether a
           /audio.bin subscriber is attached -- it's a session
           liveness signal, not just a feature for the user.

        Sequence matches Xcode verbatim: audio first, then video.
        Failures in either branch are logged but don't block the HTTP
        server -- /codec and /stream.bin retry on their own."""
        try:
            await self._ensure_audio_stream()
        except Exception:
            logger.warning("eager audio start failed (will retry on /audio.bin connect)", exc_info=True)
        try:
            await self._ensure_fresh_stream(force=False)
        except Exception:
            logger.warning("eager video start failed (will retry on first /codec)", exc_info=True)

    async def serve(self) -> None:
        """Run the HTTP server until cancelled / Ctrl-C."""
        http_server = await asyncio.start_server(self._handle_http, self._bind, self._http_port)
        watchdog = asyncio.create_task(self._stall_watchdog())
        decoder_refresh = asyncio.create_task(self._decoder_refresh_loop())
        # Eagerly start the HID worker so queued /touch requests are
        # processed even before the device-stream is fully up.
        self._hid_worker_task = asyncio.create_task(self._hid_worker())
        # Kick off the video stream in the background. We don't await it
        # here -- the HTTP server should accept connections immediately
        # so the user sees a working /index.html even if the device-side
        # handshake is slow.
        eager_start = asyncio.create_task(self._eager_stream_start())

        # Install signal handlers so Ctrl-C / SIGTERM trigger an
        # orderly, fast shutdown instead of waiting for blocked RPCs.
        # On Windows add_signal_handler isn't supported -- fall back to
        # the default KeyboardInterrupt-raising behaviour.
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _request_stop():
            if not stop_event.is_set():
                logger.info("shutting down...")
                stop_event.set()

        for signame in ("SIGINT", "SIGTERM"):
            with contextlib.suppress(NotImplementedError, AttributeError):
                import signal

                loop.add_signal_handler(getattr(signal, signame), _request_stop)

        async def _bounded(coro, label, timeout=3.0):
            """Run an async cleanup step with a hard timeout so a hung
            RPC can't keep us alive at shutdown."""
            try:
                await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("shutdown: %s timed out after %.1fs", label, timeout)
            except Exception:
                logger.exception("shutdown: %s raised", label)

        # Run the server until stop_event fires. Spawn serve_forever() as a
        # background task so we can cancel it cheaply from the signal path
        # without awaiting it -- awaiting a cancelled serve_forever() with
        # active connection handlers can wedge the shutdown indefinitely
        # (the straggler cancel at the end of this function mops it up).
        serve_task = asyncio.create_task(http_server.serve_forever(), name="serve_forever")
        try:
            logger.info(f"Open http://{self._bind}:{self._http_port}/ in Safari/Chrome. Ctrl-C to stop.")
            await stop_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            if not serve_task.done():
                serve_task.cancel()
            logger.info("shutdown: cancelling watchdog")
            watchdog.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await watchdog
            decoder_refresh.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await decoder_refresh
            logger.info("shutdown: cancelling eager_start")
            eager_start.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await eager_start
            # Close the HTTP listener first so no new connections come in
            # while we tear the device-side streams down.
            logger.info("shutdown: closing HTTP server")
            http_server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(http_server.wait_closed(), timeout=2.0)
            logger.info("shutdown: stopping HID")
            await _bounded(self._stop_hid(), "_stop_hid")
            task = self._hid_worker_task
            self._hid_worker_task = None
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

            # _stop_active_stream / _stop_audio_stream issue
            # stop_media_stream RPCs to the device daemon -- if the
            # daemon is hung, these would block forever without a bound.
            async def _stop_video():
                async with self._stream_lock:
                    await self._stop_active_stream()

            async def _stop_audio():
                async with self._audio_lock:
                    await self._stop_audio_stream()

            logger.info("shutdown: stopping video stream")
            await _bounded(_stop_video(), "_stop_active_stream")
            logger.info("shutdown: stopping audio stream")
            await _bounded(_stop_audio(), "_stop_audio_stream")
            # Cancel any lingering connection-handler tasks that the
            # HTTP server's wait_closed couldn't drain (e.g. a
            # /stream.bin or /audio.bin handler blocked in queue.get()
            # because the listener was closed before they finished
            # writing). Without this they hold the asyncio loop alive
            # and the process never exits.
            current = asyncio.current_task()
            stragglers = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
            if stragglers:
                logger.info("shutdown: cancelling %d straggler task(s)", len(stragglers))
                for t in stragglers:
                    t.cancel()
                with contextlib.suppress(Exception):
                    await asyncio.wait(stragglers, timeout=2.0)
            logger.info("shutdown complete")
