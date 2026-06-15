window.AUDIO_DEFAULT_ON = __AUDIO_DEFAULT_ON__;
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');

// Size the canvas in CSS pixels so its display dimensions divide
// cleanly by devicePixelRatio -- on a 2x screen each backing-store
// pixel lands on one device pixel, giving the 1:1 native-resolution
// look while still fitting inside the viewport. When the viewport
// can't even fit the DPR-divided size we fall back to a further
// proportional shrink (still anchored to integer-ish device pixels
// where possible); image-rendering:high-quality keeps that fallback
// path from going visibly blocky.
function fitCanvasToViewport() {
    if (!canvas.width || !canvas.height) return;
    const dpr = window.devicePixelRatio || 1;
    const naturalW = canvas.width / dpr;
    const naturalH = canvas.height / dpr;
    // Reserve room for the flanking side buttons + bottom row + util
    // tray; ~30 px extra when the cosmetic bezel is on (14 px padding
    // either side of the canvas).
    const frameSlack = document.body.classList.contains('frame-on') ? 32 : 0;
    const availW = Math.max(100, window.innerWidth - 160 - frameSlack);
    const availH = Math.max(100, window.innerHeight - 120 - frameSlack);
    const scale = Math.min(1, availW / naturalW, availH / naturalH);
    canvas.style.width  = (naturalW * scale) + 'px';
    canvas.style.height = (naturalH * scale) + 'px';
}
window.addEventListener('resize', fitCanvasToViewport);
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
//
// `visualRotation` is how much the captured device buffer is rotated
// when drawn into the canvas (signed multiples of 90, CSS convention:
// positive = CW). The rotation lives INSIDE the canvas — i.e. we
// resize the canvas to the rotated footprint and call ctx.rotate before
// drawImage — so the canvas's CSS box already matches what the user
// sees and the surrounding flex layout / cosmetic bezel wrap it
// correctly even when the device is in landscape. touchCoords()
// therefore has to inverse-rotate clicks back into the device buffer's
// own coordinate system before normalising to HID 0..65535.
let visualRotation = 0;
function touchCoords(e) {
    const rect = canvas.getBoundingClientRect();
    // Click in canvas backing-store pixel space.
    const sx = (e.clientX - rect.left) * canvas.width  / rect.width;
    const sy = (e.clientY - rect.top)  * canvas.height / rect.height;
    const cw = canvas.width, ch = canvas.height;
    const sideways = Math.abs(visualRotation % 180) === 90;
    // Device buffer dims (un-rotated); canvas dims = rotated buffer dims.
    const dw = sideways ? ch : cw;
    const dh = sideways ? cw : ch;
    const dx = sx - cw / 2;
    const dy = sy - ch / 2;
    // Inverse of ctx.rotate(visualRotation): rotate the click by -visualRotation.
    const rad = -visualRotation * Math.PI / 180;
    const cos = Math.cos(rad), sin = Math.sin(rad);
    const bx = dx * cos - dy * sin + dw / 2;
    const by = dx * sin + dy * cos + dh / 2;
    return {
        x: Math.max(0, Math.min(65535, Math.round(bx / dw * 65535))),
        y: Math.max(0, Math.min(65535, Math.round(by / dh * 65535))),
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
let lastCoords = {x: 0, y: 0};
// Drag-outside-then-release leaves the device-side contact stuck if we
// only listen on the canvas: pointer capture is silently dropped on
// window blur / Cmd-Tab / right-click menus / OS-level interruptions,
// and the eventual pointerup then dispatches to whatever element the
// cursor is over (often nothing). Mirror up / cancel / lostcapture
// listeners onto `window` so we always see the release.
function releaseActive() {
    if (activePointer === null) return;
    activePointer = null;
    postJson('/touch', {type: 'release', x: lastCoords.x, y: lastCoords.y});
}
canvas.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;   // primary button only
    e.preventDefault();
    try { canvas.setPointerCapture(e.pointerId); } catch (err) {}
    activePointer = e.pointerId;
    lastCoords = touchCoords(e);
    postJson('/touch', {type: 'contact', x: lastCoords.x, y: lastCoords.y});
});
function onMove(e) {
    if (e.pointerId !== activePointer) return;
    e.preventDefault();
    lastCoords = touchCoords(e);
    postJson('/touch', {type: 'contact', x: lastCoords.x, y: lastCoords.y});
}
function onUp(e) {
    if (e.pointerId !== activePointer) return;
    e.preventDefault();
    lastCoords = touchCoords(e);
    releaseActive();
}
canvas.addEventListener('pointermove', onMove);
window.addEventListener('pointermove', onMove);
canvas.addEventListener('pointerup', onUp);
window.addEventListener('pointerup', onUp);
canvas.addEventListener('pointercancel', onUp);
window.addEventListener('pointercancel', onUp);
// `lostpointercapture` fires whenever capture is released for ANY
// reason (including the browser dropping it silently); use it as a
// final backstop so the contact never gets pinned indefinitely.
canvas.addEventListener('lostpointercapture', (e) => {
    if (e.pointerId === activePointer) releaseActive();
});
// Tab switch / window blur kills capture without firing up. Treat
// either as an implicit release so a stuck contact doesn't survive
// the user looking away.
window.addEventListener('blur', releaseActive);
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') releaseActive();
});
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

// ----- input: physical key -> HID Keyboard usage -> /key -----
// KeyboardEvent.code is layout-independent (the physical key, not the
// typed character), which matches the HID usage table exactly. Anything
// not in this map is ignored.
const CODE_TO_HID = (() => {
    const m = {};
    for (let i = 0; i < 26; i++) m['Key' + String.fromCharCode(65 + i)] = 0x04 + i;
    // Digits: KeyboardEvent uses Digit1..Digit9, Digit0; HID uses 0x1E..0x26, then 0x27.
    for (let i = 1; i <= 9; i++) m['Digit' + i] = 0x1D + i;
    m['Digit0'] = 0x27;
    Object.assign(m, {
        Enter: 0x28, Escape: 0x29, Backspace: 0x2A, Tab: 0x2B, Space: 0x2C,
        Minus: 0x2D, Equal: 0x2E, BracketLeft: 0x2F, BracketRight: 0x30,
        Backslash: 0x31, Semicolon: 0x33, Quote: 0x34, Backquote: 0x35,
        Comma: 0x36, Period: 0x37, Slash: 0x38, CapsLock: 0x39,
        ArrowRight: 0x4F, ArrowLeft: 0x50, ArrowDown: 0x51, ArrowUp: 0x52,
        ShiftLeft: 0xE1, ShiftRight: 0xE5,
        ControlLeft: 0xE0, ControlRight: 0xE4,
        AltLeft: 0xE2, AltRight: 0xE6,
        MetaLeft: 0xE3, MetaRight: 0xE7,
    });
    for (let i = 1; i <= 12; i++) m['F' + i] = 0x39 + i;
    return m;
})();

const pressedUsages = new Set();
let lastKeyPost = Promise.resolve();
function postKeys() {
    // Serialize POSTs so the device sees them in order even when the
    // browser fires keydown bursts faster than the HTTP round-trip.
    const snapshot = [...pressedUsages];
    lastKeyPost = lastKeyPost.then(() => postJson('/key', {usages: snapshot}));
}

// Toggle for whether host keystrokes get forwarded to the device.
// When off, all keydown/keyup events bypass our handlers so the
// browser receives them normally (Cmd-L to focus the URL bar, Cmd-W
// to close the tab, devtools shortcuts, etc.). Persisted across page
// loads via localStorage so the user doesn't have to flip it every
// reload.
const kbBtn = document.getElementById('keyboard-toggle');
let keyboardCaptureOn = true;
try {
    if (localStorage.getItem('keyboardCapture') === 'false') keyboardCaptureOn = false;
} catch (e) {}
function setKbLabel() {
    kbBtn.textContent = 'Keyboard: ' + (keyboardCaptureOn ? 'on' : 'off');
}
setKbLabel();
function releaseAllKeys() {
    if (pressedUsages.size) {
        pressedUsages.clear();
        postKeys();
    }
}
kbBtn.addEventListener('click', () => {
    keyboardCaptureOn = !keyboardCaptureOn;
    setKbLabel();
    try { localStorage.setItem('keyboardCapture', keyboardCaptureOn ? 'true' : 'false'); } catch (e) {}
});

window.addEventListener('keydown', (e) => {
    if (!keyboardCaptureOn) return;
    // Ctrl-hotkey path consumes the event; don't also type it.
    if (e.ctrlKey && !e.altKey && !e.metaKey) {
        const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
        const name = CTRL_HOTKEYS[key];
        if (name) {
            e.preventDefault();
            postJson('/button', {name, state: 'press'}).then(() => log('hotkey: ' + name));
            return;
        }
    }
    const usage = CODE_TO_HID[e.code];
    if (usage === undefined) return;
    e.preventDefault();
    if (e.repeat) return;            // host autorepeat -- the device does its own
    if (!pressedUsages.has(usage)) {
        pressedUsages.add(usage);
        postKeys();
    }
});
window.addEventListener('keyup', (e) => {
    if (!keyboardCaptureOn) return;
    const usage = CODE_TO_HID[e.code];
    if (usage === undefined) return;
    e.preventDefault();
    if (pressedUsages.delete(usage)) postKeys();
});
window.addEventListener('blur', () => {
    // Window-blur means we won't see keyup; flush the bitmap so no
    // key ends up stuck-down on the device.
    releaseAllKeys();
});

// ----- Orientation: POST /rotate with {direction: 'left'|'right'} and
// keep the canvas in sync with the device's reported state.
// Updating `visualRotation` triggers an immediate redraw of the most-
// recent video frame at the new orientation (no wait for the next
// decoded frame). If iOS subsequently re-renders the buffer in the
// new orientation (its aspect ratio flips between portrait and
// landscape), drawPending() auto-resets the rotation to 0 to avoid
// double-rotating the now-natively-oriented content.
function setVisualRotation(deg) {
    deg = ((deg % 360) + 540) % 360 - 180;  // normalise to (-180, 180]
    if (deg === visualRotation) return;
    visualRotation = deg;
    redrawWithCurrentRotation();
}
// Device-reported orientation -> in-canvas rotation that mirrors how
// the user is physically holding the device. landscapeLeft means the
// device is tilted 90° CCW (home button on the right), so the captured
// buffer content rotates CCW in the canvas (-90) — the device's top
// edge ends up on the left of the canvas just like in the user's view.
const ORIENTATION_DEGREES = {
    portrait: 0,
    landscapeLeft: -90,
    portraitUpsideDown: 180,
    landscapeRight: 90,
};
async function postRotate(direction) {
    setVisualRotation(visualRotation + (direction === 'left' ? -90 : 90));
    try {
        const r = await fetch('/rotate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({direction}),
        });
        if (!r.ok) { log('rotate HTTP ' + r.status); return; }
        const j = await r.json();
        const target = ORIENTATION_DEGREES[j.currentDeviceOrientation];
        if (typeof target === 'number') setVisualRotation(target);
        log('rotate: ' + j.currentDeviceOrientation);
    } catch (e) { log('rotate err: ' + (e.message || e)); }
}
document.getElementById('rotate-left').addEventListener('click', () => postRotate('left'));
document.getElementById('rotate-right').addEventListener('click', () => postRotate('right'));

// ----- Force Restart: drop the current video stream + reload the page.
// Wipes all client-side state and pulls a fresh IDR from a new stream.
document.getElementById('restart').addEventListener('click', async () => {
    log('forcing restart + reload...');
    try {
        await fetch('/restart', {method: 'POST', cache: 'no-store'});
    } catch (e) { log('restart err: ' + e.message); }
    setTimeout(() => location.reload(), 100);
});

// ----- Dark / light toggle: GET /style reads the current style,
// POST /style with {"style":"dark"|"light"} flips it. Button label
// shows the CURRENT style so the click reads as "toggle to the other".
const styleBtn = document.getElementById('style-toggle');
function setStyleLabel(s) { styleBtn.textContent = 'Style: ' + s; }
async function refreshStyle() {
    try {
        const r = await fetch('/style', {cache: 'no-store'});
        if (!r.ok) return;
        const j = await r.json();
        if (j && j.style) setStyleLabel(j.style);
    } catch (e) { log('style get err: ' + (e.message || e)); }
}
styleBtn.addEventListener('click', async () => {
    const cur = styleBtn.textContent.replace('Style: ', '').trim();
    const next = cur === 'dark' ? 'light' : 'dark';
    try {
        const r = await fetch('/style', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({style: next}),
        });
        if (r.ok) { setStyleLabel(next); log('style: ' + next); }
        else { log('style set HTTP ' + r.status); }
    } catch (e) { log('style set err: ' + (e.message || e)); }
});
refreshStyle();

// ----- Frame toggle: pure-cosmetic CSS bezel around the canvas.
// Persisted in localStorage so a reload keeps the user's choice.
const frameBtn = document.getElementById('frame-toggle');
function setFrameLabel() {
    frameBtn.textContent = 'Frame: ' + (document.body.classList.contains('frame-on') ? 'on' : 'off');
}
try {
    if (localStorage.getItem('frameOn') === 'false') document.body.classList.remove('frame-on');
} catch (e) {}
setFrameLabel();
frameBtn.addEventListener('click', () => {
    const on = document.body.classList.toggle('frame-on');
    setFrameLabel();
    fitCanvasToViewport();
    try { localStorage.setItem('frameOn', on ? 'true' : 'false'); } catch (e) {}
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

// vsync-aligned draw: the decoder's output callback only stores the
// latest frame; the actual ctx.drawImage call lives in a
// requestAnimationFrame loop so the compositor never reads the canvas
// mid-update. Older queued frames are .close()'d so we don't leak GPU
// memory — we always show the most recent decoded frame.
let pendingFrame = null;
let rafScheduled = false;
// The most recent decoded VideoFrame, kept alive so we can redraw it
// at a new rotation without waiting for the next decode. Closed when
// it's replaced or when the page is unloaded.
let lastFrame = null;
// Last frame's buffer-aspect orientation (true = landscape, false =
// portrait). When iOS re-renders after a rotation the buffer aspect
// flips — that signals the content is now natively oriented in the
// buffer, so we drop our in-canvas rotation to avoid double-rotating.
let lastFrameLandscape = null;
function drawFrame(f) {
    const sideways = Math.abs(visualRotation % 180) === 90;
    const targetW = sideways ? f.displayHeight : f.displayWidth;
    const targetH = sideways ? f.displayWidth  : f.displayHeight;
    if (targetW !== canvas.width || targetH !== canvas.height) {
        canvas.width = targetW;
        canvas.height = targetH;
        fitCanvasToViewport();
    }
    ctx.save();
    ctx.translate(targetW / 2, targetH / 2);
    if (visualRotation) ctx.rotate(visualRotation * Math.PI / 180);
    ctx.drawImage(f, -f.displayWidth / 2, -f.displayHeight / 2);
    ctx.restore();
}
function redrawWithCurrentRotation() {
    if (lastFrame) drawFrame(lastFrame);
}
function drawPending() {
    rafScheduled = false;
    const f = pendingFrame;
    pendingFrame = null;
    if (!f) return;
    const landscape = f.displayWidth > f.displayHeight;
    if (lastFrameLandscape !== null && landscape !== lastFrameLandscape && visualRotation !== 0) {
        // iOS rerendered the buffer in the new orientation — content is
        // now natively upright, so drop our in-canvas rotation.
        visualRotation = 0;
    }
    lastFrameLandscape = landscape;
    try {
        drawFrame(f);
    } catch (e) {
        log('draw err: ' + (e.message || e));
    }
    if (lastFrame && lastFrame !== f) {
        try { lastFrame.close(); } catch (_) {}
    }
    lastFrame = f;
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
            // Don't drawImage straight from this callback — that runs at
            // the decoder's output cadence (typically irregular: 0..multiple
            // frames per ms during bursts) and races the compositor's
            // vsync read, which is what gets seen as visible horizontal
            // tear bands during quick-swipe motion. Instead, replace the
            // pending frame slot and let requestAnimationFrame draw the
            // latest one in lockstep with the display refresh. Released
            // frames must be .close()'d to free GPU resources.
            if (pendingFrame) {
                try { pendingFrame.close(); } catch (e) {}
            }
            pendingFrame = frame;
            if (!rafScheduled) {
                rafScheduled = true;
                requestAnimationFrame(drawPending);
            }
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
            // shown even a handful of frames, Apple's encoder may have
            // emitted a POC chain WebCodecs can't follow. Asking the
            // server for a fresh stream often produces a sequential POC
            // chain that decodes cleanly. Do it at most once -- if it
            // errors again the problem isn't transient and the user can
            // click Force Restart manually.
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
                log('force-restart @ key after upstream drop');
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
