window.AUDIO_DEFAULT_ON = __AUDIO_DEFAULT_ON__;
// Resolution-collapse compensation default (server --compensate flag), with a
// per-load URL override for research: append ?compensate=0 / ?compensate=1.
window.COMPENSATE = (function () {
    const q = new URLSearchParams(location.search).get('compensate');
    if (q === '0' || q === 'false') return false;
    if (q === '1' || q === 'true') return true;
    return __COMPENSATE_DEFAULT__;
})();
// Lock the canvas buffer to the largest footprint seen and scale every frame
// to fill it, instead of resizing the canvas per frame. The device encoder
// oscillates displayHeight (2752<->2736) as the home indicator shows/hides;
// resizing on each toggle makes the whole <canvas> visibly shrink/expand --
// the "screen changing size" the user reports. Filling a fixed surface removes
// that (the <=0.6% scale is imperceptible), and a full-cover drawImage every
// frame leaves no stale GPU pixels (the old motion "tears" were really
// userspace-tunnel packet loss, gone on the kernel tunnel). Toggle: ?lockcanvas=0.
window.LOCKCANVAS = (function () {
    const q = new URLSearchParams(location.search).get('lockcanvas');
    if (q === '0' || q === 'false') return false;
    if (q === '1' || q === 'true') return true;
    return true;
})();
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
    // Reserve room for the flanking trays + side buttons + bottom row.
    // We MEASURE the actual edge widths so collapse/uncollapse of either
    // tray immediately reclaims space for the canvas. ~30 px extra when
    // the cosmetic bezel is on (14 px padding either side).
    const trayW = (id) => {
        const el = document.getElementById(id);
        return el ? el.getBoundingClientRect().width : 0;
    };
    const sideButtonsW = 80 + 80;  // side-left + side-right rough widths
    const frameSlack = document.body.classList.contains('frame-on') ? 32 : 0;
    const reservedW = trayW('left-tray') + trayW('right-tray') + sideButtonsW + frameSlack + 40;
    const availW = Math.max(100, window.innerWidth - reservedW);
    const availH = Math.max(100, window.innerHeight - 120 - frameSlack);
    const scale = Math.min(1, availW / naturalW, availH / naturalH);
    canvas.style.width  = (naturalW * scale) + 'px';
    canvas.style.height = (naturalH * scale) + 'px';
}
window.addEventListener('resize', fitCanvasToViewport);
const statusEl = document.getElementById('status');
const fpsEl = document.getElementById('fps');
let frameCount = 0;
const lines = ['connecting...'];
function log(msg) {
    // Mirror to devtools so long lines aren't truncated by the
    // bottom-left status panel (which is intentionally compact).
    try { console.log('[serve-web]', msg); } catch (_) {}
    lines.push(msg); if (lines.length > 8) lines.shift(); render();
}
function render() { statusEl.textContent = `frames: ${frameCount}\n` + lines.join('\n'); }
setInterval(render, 250);

// FPS readout. Sample frameCount once per second; the displayed number
// is the frame delta over the last 1 s. A stall shows up immediately
// as "0 fps" while the stream is still nominally "connected", which is
// what the status panel's `frames: N` counter doesn't make obvious.
let _fpsLastFc = 0;
let _fpsLastT = (typeof performance !== 'undefined') ? performance.now() : Date.now();
setInterval(() => {
    const now = (typeof performance !== 'undefined') ? performance.now() : Date.now();
    const dtSec = (now - _fpsLastT) / 1000;
    const dFrames = frameCount - _fpsLastFc;
    _fpsLastT = now;
    _fpsLastFc = frameCount;
    if (fpsEl) fpsEl.textContent = (dtSec > 0 ? (dFrames / dtSec) : 0).toFixed(1) + ' fps';
}, 1000);

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
    // preventDefault on pointerdown also suppresses the implicit
    // focus shift onto our tabindex=0 canvas; focus it explicitly so
    // a click on the canvas always (re)starts keyboard capture.
    canvas.focus({preventScroll: true});
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

// Gate host-keystroke forwarding on canvas focus: keys flow to the
// device whenever the canvas owns the focus, and stop the moment the
// user clicks a button, the clipboard textarea, or anything else on
// the page chrome. No persisted toggle to flip — the focus is the
// state, and the #kb-indicator badge mirrors it visually.
const kbIndicator = document.getElementById('kb-indicator');
function keyboardCaptureOn() { return document.activeElement === canvas; }
function releaseAllKeys() {
    if (pressedUsages.size) {
        pressedUsages.clear();
        postKeys();
    }
}
function updateKbIndicator() {
    kbIndicator.classList.toggle('hidden', !keyboardCaptureOn());
}
canvas.addEventListener('focus', updateKbIndicator);
canvas.addEventListener('blur', () => {
    // Dropping focus must release any held keys immediately — we
    // won't see the keyup once events stop being forwarded.
    releaseAllKeys();
    updateKbIndicator();
});
updateKbIndicator();

// Help modal: opened by '?' (or the '?' button), dismissed by Esc /
// click outside / close-X. The shortcut works regardless of the
// keyboard-capture toggle so the user can always reach it; while the
// modal is open we gate all forwarding to the device so typing into
// the page doesn't leak through.
const helpOverlay = document.getElementById('help-overlay');
function setHelpOpen(open) {
    helpOverlay.classList.toggle('hidden', !open);
    helpOverlay.setAttribute('aria-hidden', open ? 'false' : 'true');
}
function helpIsOpen() { return !helpOverlay.classList.contains('hidden'); }
document.getElementById('help-toggle').addEventListener('click', () => setHelpOpen(true));
document.getElementById('help-close').addEventListener('click', () => setHelpOpen(false));
helpOverlay.addEventListener('click', (e) => {
    // Click on the dimmed backdrop (outside the modal card) closes.
    if (e.target === helpOverlay) setHelpOpen(false);
});

window.addEventListener('keydown', (e) => {
    // '?' always opens help; Esc closes it. Both pre-empt the
    // keyboard-capture gate so they work even when capture is off
    // (and when on, we don't also forward shift+/ to the device).
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        setHelpOpen(true);
        return;
    }
    if (e.key === 'Escape' && helpIsOpen()) {
        e.preventDefault();
        setHelpOpen(false);
        return;
    }
    // While help is open the device shouldn't see any keystrokes.
    if (helpIsOpen()) { e.preventDefault(); return; }
    // Local hotkeys (handled in the browser, never forwarded to the
    // device) -- run BEFORE the keyboard-capture gate so they work
    // regardless of whether forwarding is on.
    if (e.ctrlKey && !e.altKey && !e.metaKey && e.key.length === 1) {
        const k = e.key.toLowerCase();
        if (k === 'p') { e.preventDefault(); takeScreenshot(); return; }
    }
    if (!keyboardCaptureOn()) return;
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
    if (helpIsOpen() || !keyboardCaptureOn()) return;
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
const deviceFrameEl = document.getElementById('device-frame');
function setVisualRotation(deg) {
    deg = ((deg % 360) + 540) % 360 - 180;  // normalise to (-180, 180]
    if (deg === visualRotation) return;
    // Pick the shortest signed delta around the circle so a 180 ->
    // -180 transition doesn't sweep the long way around.
    let delta = deg - visualRotation;
    if (delta > 180) delta -= 360;
    if (delta < -180) delta += 360;
    visualRotation = deg;
    // Canvas-internal rotation snaps immediately (so dim swap + layout
    // reflow happen now), then the device-frame's CSS transform is
    // set to -delta degrees so the *visual* position matches where
    // the canvas was a moment ago. We then animate the transform
    // back to identity, giving a smooth perceived rotation while the
    // surrounding layout has already moved.
    redrawWithCurrentRotation();
    deviceFrameEl.style.transition = 'none';
    deviceFrameEl.style.transform = `rotate(${-delta}deg)`;
    // Two RAFs to make sure the no-transition initial transform paints
    // before we install the animating transition; one RAF is usually
    // enough but two is safer across browsers.
    requestAnimationFrame(() => requestAnimationFrame(() => {
        deviceFrameEl.style.transition = 'transform 0.3s cubic-bezier(.4,0,.2,1)';
        deviceFrameEl.style.transform = '';
    }));
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

// ----- Screenshot: save what's drawn into the canvas as a PNG.
// Reads the existing backing store (including any in-canvas rotation),
// so the file matches what the user sees -- no extra server round-trip.
function tsStamp() {
    const d = new Date();
    const z = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${z(d.getMonth()+1)}${z(d.getDate())}-${z(d.getHours())}${z(d.getMinutes())}${z(d.getSeconds())}`;
}
function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function takeScreenshot() {
    if (!canvas.width || !canvas.height) { log('screenshot: canvas empty'); return; }
    canvas.toBlob((blob) => {
        if (!blob) { log('screenshot: toBlob returned null'); return; }
        const name = `screenshot-${tsStamp()}.png`;
        downloadBlob(blob, name);
        log('saved ' + name);
    }, 'image/png');
}
document.getElementById('screenshot').addEventListener('click', takeScreenshot);

// ----- Reload window: full page reload. Useful when something is stuck
// and Force Restart (which only restarts the device-side stream) isn't
// enough.
document.getElementById('reload-window').addEventListener('click', () => {
    log('reloading page…');
    setTimeout(() => location.reload(), 50);
});

// ----- Collapsible side trays. Persist the open/closed state per tray
// so the layout survives a reload. Each tray button has data-tray=
// {"left","right"}.
function applyTrayState(side) {
    const el = document.getElementById(side + '-tray');
    if (!el) return;
    let collapsed = false;
    try { collapsed = localStorage.getItem('tray-' + side) === 'collapsed'; } catch (e) {}
    el.classList.toggle('collapsed', collapsed);
}
function toggleTray(side) {
    const el = document.getElementById(side + '-tray');
    if (!el) return;
    const collapsed = !el.classList.contains('collapsed');
    el.classList.toggle('collapsed', collapsed);
    try { localStorage.setItem('tray-' + side, collapsed ? 'collapsed' : 'open'); } catch (e) {}
    fitCanvasToViewport();
}
applyTrayState('left'); applyTrayState('right');
document.querySelectorAll('.tray-toggle').forEach(btn => {
    btn.addEventListener('click', () => toggleTray(btn.dataset.tray));
});

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
            // /codec returns JSON: {codec, description} where description is a
            // base64 hvcC record (HEVCDecoderConfigurationRecord). Passing it
            // as the decoder `description` selects hvcC-mode decoding (matching
            // the length-prefixed NALU framing on /stream.bin), which avoids
            // Chrome's Annex-B path that tears under motion.
            const info = await resp.json();
            if (!info.codec || !info.description) { lastErr = 'incomplete codec info (params not yet seen)'; continue; }
            const description = Uint8Array.from(atob(info.description), c => c.charCodeAt(0));
            return { codec: info.codec.trim(), description };
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

// ----- Resolution-collapse compensation. Under rapid motion the device
// encoder drops to a smaller capture resolution (observed 720x1280 for a
// 1264x2752 panel) rendered into the TOP-LEFT of the fixed buffer with the
// rest flat gray (Y=Cb=Cr=128) padding -- the "screen shrinks to a corner
// while swiping" tear. It's in the bitstream (device-side, under the ~6 Mbps
// cap) and can't be prevented from our side. But the shrunk region is the
// whole screen, just stretched into fewer pixels -- so we detect that content
// rectangle and stretch it back to fill the canvas. The collapse then reads
// as a momentary softness dip in a correctly-placed full-frame image instead
// of a jarring corner shrink.
//
// Detection runs on the RAW decoded frame (never the already-compensated
// canvas -- that would feed back and oscillate), throttled and cached. The
// content is top-left anchored so the crop origin is always (0,0); we find
// the right/bottom padding boundary. Validated offline against real collapsed
// captures: full-size on clean frames, ~720x1280 on collapsed ones.
const _detCanvas = document.createElement('canvas');
const _detCtx = _detCanvas.getContext('2d', {willReadFrequently: true});
let _cropSrcW = 0, _cropSrcH = 0;   // 0 => draw the full frame (not collapsed)
let _lockW = 0, _lockH = 0;         // locked canvas footprint (max seen); see window.LOCKCANVAS
const DET_H = 344;                  // downsample height for detection
function detectContentCrop(f) {
    const fw = f.displayWidth, fh = f.displayHeight;
    if (!fw || !fh) return;
    const DW = Math.max(8, Math.round(DET_H * fw / fh));
    _detCanvas.width = DW; _detCanvas.height = DET_H;
    try {
        _detCtx.drawImage(f, 0, 0, DW, DET_H);
        const d = _detCtx.getImageData(0, 0, DW, DET_H).data;
        const isGray = (x, y) => { const i = (y * DW + x) * 4;
            return Math.abs(d[i] - 128) < 6 && Math.abs(d[i + 1] - 128) < 6 && Math.abs(d[i + 2] - 128) < 6; };
        // Last column / row that still holds content (<60% gray padding).
        let cr = 0;
        for (let x = 0; x < DW; x++) { let g = 0, n = 0;
            for (let y = 0; y < DET_H; y += 4) { n++; if (isGray(x, y)) g++; }
            if (g / n < 0.6) cr = x; }
        let cb = 0;
        for (let y = 0; y < DET_H; y++) { let g = 0, n = 0;
            for (let x = 0; x < DW; x += 4) { n++; if (isGray(x, y)) g++; }
            if (g / n < 0.6) cb = y; }
        // Map back to source px, biasing one cell inward so a boundary cell
        // that straddles content+padding doesn't leave a gray sliver.
        const cw = Math.round((cr / DW) * fw);
        const ch = Math.round((cb / DET_H) * fh);
        // Compensate only on a clear collapse (both dims well under full and
        // not degenerate); otherwise draw the full frame untouched.
        if (cw > fw * 0.2 && cw < fw * 0.92 && ch > fh * 0.2 && ch < fh * 0.92) {
            _cropSrcW = cw; _cropSrcH = ch;
        } else {
            _cropSrcW = 0; _cropSrcH = 0;
        }
    } catch (_) { /* transient readback failure -- keep previous crop */ }
}

function drawFrame(f) {
    const sideways = Math.abs(visualRotation % 180) === 90;
    const fw = f.displayWidth, fh = f.displayHeight;
    const targetW = sideways ? fh : fw;
    const targetH = sideways ? fw : fh;
    if (window.LOCKCANVAS) {
        // Grow-only: keep the canvas at the largest footprint seen so the
        // encoder's 2752<->2736 oscillation never resizes it (no shrink).
        if (targetW > _lockW || targetH > _lockH) {
            _lockW = Math.max(_lockW, targetW);
            _lockH = Math.max(_lockH, targetH);
            canvas.width = _lockW;
            canvas.height = _lockH;
            fitCanvasToViewport();
        }
    } else if (targetW !== canvas.width || targetH !== canvas.height) {
        canvas.width = targetW;
        canvas.height = targetH;
        fitCanvasToViewport();
    }
    // Source rect: the detected content region on collapse, else the whole
    // frame. Stretched to fill the canvas footprint (un-doing any device
    // shrink AND the 16px height oscillation) inside the rotation transform.
    const dstW = canvas.width, dstH = canvas.height;
    const srcW = _cropSrcW || fw;
    const srcH = _cropSrcH || fh;
    const fpW = sideways ? dstH : dstW;   // unrotated footprint that fills the
    const fpH = sideways ? dstW : dstH;   // canvas after the rotation transform
    ctx.save();
    ctx.translate(dstW / 2, dstH / 2);
    if (visualRotation) ctx.rotate(visualRotation * Math.PI / 180);
    ctx.drawImage(f, 0, 0, srcW, srcH, -fpW / 2, -fpH / 2, fpW, fpH);
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
    // Detect the collapse-crop rectangle from THIS raw frame, every frame:
    // the stream flips between collapsed and full-res frames faster than any
    // throttle, so a cached crop applied to a mismatched frame zooms a full
    // frame into its top-left (the "smaller screen over the old full screen"
    // artifact). Per-frame detection keeps the crop matched to the frame.
    if (window.COMPENSATE) detectContentCrop(f); else { _cropSrcW = 0; _cropSrcH = 0; }
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

// ----- Offline overlay + auto-recovery: show a banner if frames stop
// flowing for ~3 s, then nudge the server back to life on a tiered
// schedule so the viewer resumes "automatically" when the device wakes
// or its daemon comes back. We sample frameCount once a second; if it
// hasn't moved for OFFLINE_GRACE_SECS AND the stream has actually
// started (>=1 drawn frame), reveal the overlay. The moment a new
// frame lands, hide it again and reset the recovery timers.
//
// Recovery ladder, measured in seconds without frames once the
// overlay is showing:
//   +PLI_AFTER_SECS -- POST /pli (one RTCP packet, ~100-300 ms IDR)
//   then every PLI_REPEAT_SECS -- another /pli
//   +RESTART_AFTER_SECS -- POST /restart (no page reload). The server
//     preserves the live /stream.bin subscriber across the restart and
//     emits a type=2 (key-with-reset) IDR onto the existing connection;
//     the in-page decoder rebuild path picks it up. Crucially we do NOT
//     location.reload() here -- a reload would resuspend the
//     AudioContext (browsers require a user gesture to play audio after
//     navigation) and the user would silently lose sound.
const offlineOverlay = document.getElementById('offline-overlay');
const OFFLINE_GRACE_SECS = 3;
const PLI_AFTER_SECS = 8;        // first PLI nudge once we've been offline this long
const PLI_REPEAT_SECS = 6;       // keep pinging while still offline
const RESTART_AFTER_SECS = 25;   // give up on PLI; full session restart (no reload)
const RESTART_REPEAT_SECS = 30;  // if still offline after this much more, restart again
let _lastFc = -1, _stableSec = 0, _nextPliSec = 0, _nextRestartSec = 0;
setInterval(() => {
    if (frameCount === 0) {
        offlineOverlay.classList.add('hidden');
        _lastFc = 0; _stableSec = 0; _nextPliSec = 0; _nextRestartSec = 0;
        return;
    }
    if (frameCount === _lastFc) {
        _stableSec += 1;
        if (_stableSec >= OFFLINE_GRACE_SECS) {
            offlineOverlay.classList.remove('hidden');
            if (_stableSec >= RESTART_AFTER_SECS && _stableSec >= _nextRestartSec) {
                _nextRestartSec = _stableSec + RESTART_REPEAT_SECS;
                log('auto-recover: /restart (offline ' + _stableSec + 's, no reload — audio stays attached)');
                fetch('/restart', {method: 'POST', cache: 'no-store'})
                    .catch(err => log('auto restart err: ' + (err.message || err)));
            } else if (_stableSec >= PLI_AFTER_SECS && _stableSec >= _nextPliSec) {
                _nextPliSec = _stableSec + PLI_REPEAT_SECS;
                log('auto-recover: /pli (offline ' + _stableSec + 's)');
                fetch('/pli', {method: 'POST', cache: 'no-store'})
                    .catch(err => log('auto pli err: ' + (err.message || err)));
            }
        }
    } else {
        if (_stableSec >= OFFLINE_GRACE_SECS) log('stream resumed after ' + _stableSec + 's');
        _stableSec = 0;
        _nextPliSec = 0;
        _nextRestartSec = 0;
        offlineOverlay.classList.add('hidden');
    }
    _lastFc = frameCount;
}, 1000);

// ----- Collapse recovery is SERVER-side, not here.
// Recovery from the collapse (the device re-emitting a full-res IDR) is driven
// SERVER-side by the motion-triggered decoder-refresh (--motion-idr): it fires
// preemptively the moment motion starts, so it's structurally faster than any
// client-side detect-then-POST-/pli loop (which is always a collapse-cycle
// behind). The viewer's job is just to hide the shrink until that IDR lands,
// which detectContentCrop above does. No client-side keyframe requests here.

// ----- Accessibility panel: GET /accessibility lists current settings,
// POST /accessibility/set with {key, value} updates one, POST
// /accessibility/reset wipes everything back to defaults. Values can
// be bool (checkbox) or float (slider 0..1) -- the device's
// DYNAMIC_TYPE setting is a float; everything else we've observed is
// a bool.
const axList = document.getElementById('accessibility-list');
function renderAxRow(setting) {
    const row = document.createElement('div');
    row.className = 'axrow';
    const id = 'ax-' + setting.key;
    const label = document.createElement('label');
    label.setAttribute('for', id);
    label.textContent = setting.key.replace(/_/g, ' ').toLowerCase();
    label.title = setting.key;
    row.appendChild(label);
    const type = setting.type || (typeof setting.value === 'boolean' ? 'bool' : 'float');
    if (type === 'bool') {
        const cb = document.createElement('input');
        cb.type = 'checkbox'; cb.id = id; cb.checked = !!setting.value;
        cb.addEventListener('change', () => postAxSet(setting.key, cb.checked));
        row.appendChild(cb);
    } else if (type === 'enum') {
        const sel = document.createElement('select');
        sel.id = id;
        for (const opt of (setting.options || [])) {
            const o = document.createElement('option');
            o.value = opt; o.textContent = opt;
            if (opt === setting.value) o.selected = true;
            sel.appendChild(o);
        }
        sel.addEventListener('change', () => postAxSet(setting.key, sel.value));
        row.appendChild(sel);
    } else {
        const sl = document.createElement('input');
        sl.type = 'range'; sl.id = id; sl.min = '0'; sl.max = '1'; sl.step = '0.05';
        sl.value = String(setting.value);
        const v = document.createElement('span');
        v.className = 'axvalue'; v.textContent = Number(setting.value).toFixed(2);
        sl.addEventListener('input', () => { v.textContent = Number(sl.value).toFixed(2); });
        sl.addEventListener('change', () => postAxSet(setting.key, Number(sl.value)));
        row.appendChild(sl); row.appendChild(v);
    }
    return row;
}
async function reloadAccessibility() {
    try {
        const r = await fetch('/accessibility', { cache: 'no-store' });
        if (!r.ok) { axList.textContent = 'load failed: HTTP ' + r.status; return; }
        const j = await r.json();
        axList.innerHTML = '';
        for (const s of j.settings || []) axList.appendChild(renderAxRow(s));
    } catch (e) { axList.textContent = 'load err: ' + (e.message || e); }
}
async function postAxSet(key, value) {
    try {
        const r = await fetch('/accessibility/set', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({key, value}),
        });
        if (!r.ok) log('ax set ' + key + ': HTTP ' + r.status);
        else log('ax: ' + key + ' = ' + value);
    } catch (e) { log('ax set err: ' + (e.message || e)); }
}
document.getElementById('accessibility-reset').addEventListener('click', async () => {
    try {
        const r = await fetch('/accessibility/reset', {method: 'POST'});
        if (!r.ok) { log('ax reset HTTP ' + r.status); return; }
        log('accessibility reset');
        reloadAccessibility();
    } catch (e) { log('ax reset err: ' + (e.message || e)); }
});
reloadAccessibility();

// ----- Clipboard panel: bidirectional text bridge to the device pasteboard.
// "→ Send to device" pushes the textarea contents via POST /clipboard.
// "← Get from device" pulls via GET /clipboard, fills the textarea, and (on a
// secure context) also pushes to navigator.clipboard so the user can paste
// directly into a host app. The header toggle ("on"/"off") gates the whole
// panel -- when off the panel dims and the buttons are inert, matching the
// pattern the user asked for ("toggle-able").
const clipboardTextEl = document.getElementById('clipboard-text');
const clipboardPanel = document.getElementById('clipboard-panel');
const clipboardSendBtn = document.getElementById('clipboard-send');
const clipboardGetBtn = document.getElementById('clipboard-get');
const clipboardToggleBtn = document.getElementById('clipboard-toggle');
let clipboardEnabled = true;
function setClipboardEnabled(on) {
    clipboardEnabled = on;
    clipboardToggleBtn.textContent = on ? 'on' : 'off';
    clipboardPanel.classList.toggle('disabled', !on);
}
clipboardToggleBtn.addEventListener('click', () => setClipboardEnabled(!clipboardEnabled));

clipboardSendBtn.addEventListener('click', async () => {
    if (!clipboardEnabled) return;
    const text = clipboardTextEl.value;
    try {
        const r = await fetch('/clipboard', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text}),
        });
        if (!r.ok) { log('clipboard send: HTTP ' + r.status); return; }
        log('clipboard → device (' + text.length + ' chars)');
    } catch (e) { log('clipboard send err: ' + (e.message || e)); }
});

clipboardGetBtn.addEventListener('click', async () => {
    if (!clipboardEnabled) return;
    try {
        const r = await fetch('/clipboard', {cache: 'no-store'});
        if (!r.ok) { log('clipboard get: HTTP ' + r.status); return; }
        const j = await r.json();
        const text = j.text == null ? '' : String(j.text);
        clipboardTextEl.value = text;
        // Best-effort push to the browser clipboard. navigator.clipboard
        // requires a secure context (https:// or localhost) AND a user
        // gesture, which the button click satisfies. Failure is non-fatal
        // since the user can still copy from the textarea by hand.
        if (text && navigator.clipboard && navigator.clipboard.writeText) {
            try {
                await navigator.clipboard.writeText(text);
                log('clipboard ← device (' + text.length + ' chars, also in browser clipboard)');
                return;
            } catch (e) { /* fall through to plain log */ }
        }
        log('clipboard ← device (' + text.length + ' chars)');
    } catch (e) { log('clipboard get err: ' + (e.message || e)); }
});

async function run() {
    log('userAgent: ' + navigator.userAgent.slice(0, 80));
    const { codec, description } = await fetchCodecWithRetry();
    log('codec: ' + codec + ' (hvcC ' + description.length + 'B)');
    // Shared hvcC decoder config: the `description` (HEVCDecoderConfigurationRecord)
    // selects VideoToolbox's native hvcC path; chunks carry 4-byte-length-prefixed
    // NALUs (the /stream.bin framing) rather than Annex-B start codes.
    const decoderConfig = { codec, description, optimizeForLatency: true };

    let support;
    try {
        support = await VideoDecoder.isConfigSupported({ codec, description });
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
    decoder.configure(decoderConfig);
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
                decoder.configure(decoderConfig);
                needsResync = false;
                gotKey = true;
                log('force-restart @ key after upstream drop');
            } else if (type === 0) {
                gotKey = true;
                if (needsResync) {
                    try { decoder.close(); } catch (e) {}
                    decoder = buildDecoder();
                    decoder.configure(decoderConfig);
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
                decoder.configure(decoderConfig);
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
