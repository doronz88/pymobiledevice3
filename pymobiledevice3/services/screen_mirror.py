"""
pymobiledevice3/services/screen_mirror.py

Browser-based screen mirror for iOS devices.

Consumes the unified :mod:`pymobiledevice3.services.valeria` capture service
(which selects between CoreMediaIO on macOS and libusb elsewhere) and forwards
the device's native H.264 stream to the browser via WebSocket. The browser
decodes with hardware (WebCodecs), so the server never decodes or re-encodes —
~3 MB/s pass-through, no CPU bottleneck, every modern browser handles 60 fps.

Requirements
------------
- Device paired and trusted
- ``pip install pymobiledevice3[screen-mirror]`` (pulls aiohttp; nothing else)
- Browser with WebCodecs support: Chrome/Edge 94+, Safari 16.4+, Firefox 130+
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import platform
import re
import sys
from typing import Optional

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.power_assertion import PowerAssertionService
from pymobiledevice3.services.valeria import (
    BackendUnavailableError,
    DeviceNotFoundError,
    IOSScreenCapture,
    MultipleDevicesError,
    ScreenRecordingPermissionError,
)

logger = logging.getLogger(__name__)

_JPEG_QUALITY = 60


def _pkg_version(module_name: str, dist_name: Optional[str] = None) -> Optional[str]:
    """Return the version of *module_name*, importing it to verify presence."""
    try:
        mod = importlib.import_module(module_name)
    except ImportError:
        return None
    v = getattr(mod, "__version__", None)
    if v:
        return v
    if dist_name:
        try:
            from importlib.metadata import version
            return version(dist_name)
        except Exception:
            pass
    return "?"


# ---------------------------------------------------------------------------
# Optional log redaction (opt-in via ``--redact``)
#
# When testers want to share a log publicly we install a logging.Filter on
# every root handler. The filter mutates each record so its formatted output
# loses the typical PII shapes — hostname, full UDIDs, per-boot AVFoundation
# UUIDs, and user-set device names like "Alice's iPad". Default behaviour
# (no flag) leaves logs untouched.
# ---------------------------------------------------------------------------


class _PiiRedactionFilter(logging.Filter):
    """Strip hostnames, UDIDs, AVFoundation UUIDs and user-set device names
    from log records before formatting."""

    # 16-40 contiguous hex chars (full UDIDs / long serials).
    _HEX_ID_RE = re.compile(r"\b[a-fA-F0-9]{16,40}\b")
    # Pre-truncated UDIDs like ``c10c41d5…869c`` or trailing-only ``c10c41d5…``
    # — replace the prefix with its first 4 chars so only that remains visible.
    _TRUNC_HEX_RE = re.compile(r"\b([a-fA-F0-9]{4,12})…(?:[a-fA-F0-9]{2,12}\b)?")
    # AVFoundation per-boot uniqueIDs
    _UUID_RE = re.compile(
        r"\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-"
        r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\b"
    )
    # Possessive device names — "<name>'s iPad", "<name>'s iPhone Pro",
    # using ASCII or Unicode curly apostrophe.
    _POSSESSIVE_DEVICE_RE = re.compile(
        r"\w+['’]s\s+(?:iPad|iPhone|iPod)(?:\s+\w+)?",
        flags=re.UNICODE,
    )
    # Fallback: bare quoted iOS device-class word with surrounding name junk.
    _QUOTED_DEVICE_RE = re.compile(r"'[^']*(?:iPad|iPhone|iPod)[^']*'")
    # Short USB serials reported as ``(serial: 7423J07)`` etc. Avoids false
    # matches on the word "serial" elsewhere by requiring the ``: <token>``
    # shape immediately after.
    _SERIAL_RE = re.compile(r"(serial:?\s+)([^\s)\]]+)", flags=re.IGNORECASE)
    # Banner ``Device:`` line — model + version + UDID parenthetical together
    # form a strong fingerprint. Replace the whole right-hand side so testers
    # still see that *a* device was identified, without leaking which one.
    _DEVICE_INFO_RE = re.compile(
        r"(Device:)\s+(?:iPad|iPhone|iPod)\S*\s+\S+\s+\(UDID\s+[^)]*\)"
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, "hostname"):
            record.hostname = "<host>"
        msg = record.getMessage()
        msg = self._UUID_RE.sub("<uuid>", msg)
        msg = self._HEX_ID_RE.sub(lambda m: m.group(0)[:4] + "…", msg)
        msg = self._TRUNC_HEX_RE.sub(lambda m: m.group(1)[:4] + "…", msg)
        msg = self._POSSESSIVE_DEVICE_RE.sub("<device>", msg)
        msg = self._QUOTED_DEVICE_RE.sub("'<device>'", msg)
        msg = self._SERIAL_RE.sub(lambda m: m.group(1) + "<serial>", msg)
        msg = self._DEVICE_INFO_RE.sub(r"\1 <redacted>", msg)
        record.msg = msg
        record.args = ()
        return True


def install_pii_log_filter() -> None:
    """Attach the PII-redaction filter to every handler on the root logger.

    Safe to call more than once; duplicate filters are skipped. Should be
    called *after* CLI logging setup so the filter sits on top of the
    coloredlogs stack and gets the last word on hostname / message content.
    """
    f = _PiiRedactionFilter()
    for handler in logging.getLogger().handlers:
        if not any(isinstance(existing, _PiiRedactionFilter)
                   for existing in handler.filters):
            handler.addFilter(f)


class ScreenMirrorService:
    """
    Captures iOS screen frames and serves them over WebSocket or as a raw stream.

    Built-in browser viewer::

        async with ScreenMirrorService(lockdown) as svc:
            await svc.serve()   # blocks; open http://localhost:8080

    Raw frame stream for integration with other projects::

        async with ScreenMirrorService(lockdown) as svc:
            async for jpeg_bytes in svc.frames():
                await my_transport.send(jpeg_bytes)
    """

    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        host: str = "127.0.0.1",
        port: int = 8080,
        fps_cap: float = 60.0,
        jpeg_quality: int = _JPEG_QUALITY,
        backend: str = "auto",
    ) -> None:
        self._lockdown = lockdown
        self._host = host
        self._port = port
        self._min_interval = 1.0 / fps_cap
        self._jpeg_quality = jpeg_quality
        # Passed through to IOSScreenCapture.create() — one of
        # "auto" (default), "cmio" (macOS), "libusb" (Linux/Win).
        self._prefer_backend = backend

        self._client_queues: set[asyncio.Queue] = set()
        # H.264 passthrough: cache the codec config (sent on client connect)
        # and the most recent keyframe (so newly-connected decoders have an
        # IDR + parameter sets to initialise from before live frames arrive).
        self._stream_config: Optional[str] = None
        self._latest_keyframe: Optional[bytes] = None
        self._display_width: int = 0
        self._display_height: int = 0
        self._backend: str = ""
        self._capture_task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None

        # Per-second stats accumulators (reset by _stats_loop). Only relevant
        # at DEBUG level — a per-second log line surfaces fps / queue / drop
        # metrics so testers running ``-v`` capture enough to diagnose
        # throughput or stutter issues without a packet capture.
        self._stats_frames = 0
        self._stats_bytes = 0
        self._stats_dropped = 0
        self._stats_max_queue = 0

    @property
    def backend(self) -> str:
        """Name of the active capture backend (empty string until first frame)."""
        return self._backend

    @property
    def display_size(self) -> tuple[int, int]:
        """Logical display size ``(width, height)`` in points, or ``(0, 0)`` if unknown."""
        return self._display_width, self._display_height

    async def __aenter__(self) -> "ScreenMirrorService":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop_capture()

    def _set_backend(self, name: str) -> None:
        """Update the active backend name, log it, and notify connected browsers."""
        self._backend = name
        logger.info("Capture backend: %s", name)
        for q in list(self._client_queues):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(f"backend:{name}")

    @staticmethod
    def _quiet_noisy_loggers() -> None:
        """Suppress per-frame transport chatter that drowns out useful output.

        At ``-v`` (DEBUG) the DTX connection logger dumps every screenshot
        frame's full binary payload (tens of KB per frame, at multiple fps).
        That noise is never useful for diagnosing screen-mirror itself. We
        clamp these loggers to INFO regardless of the global verbosity so
        testers can keep ``-v`` for our own DEBUG output (banner, stats,
        backend selection) without flooding the terminal.

        If a tester ever needs the raw transport trace, they can re-enable
        it after this call:

            logging.getLogger("pymobiledevice3.dtx").setLevel(logging.DEBUG)
        """
        for name in (
            # pymobiledevice3 transport: DTX dumps full PNG payloads at DEBUG.
            "pymobiledevice3.dtx",
            "pymobiledevice3.service_connection",
            "pymobiledevice3.tcp_forwarder",
            # Pillow's PNG/JPEG plugins emit per-chunk parse traces — multiple
            # lines per frame, fires at every screenshot.
            "PIL",
            # asyncio/aiohttp DEBUG is also chatty (selectors, websocket pings).
            "asyncio",
            "aiohttp.access",
        ):
            logging.getLogger(name).setLevel(logging.INFO)

    def _log_startup_banner(self) -> None:
        """Emit a one-shot environment banner. Fires at INFO so it appears in
        any bug-report capture; package versions are DEBUG."""
        logger.info("Screen-mirror starting on %s %s (%s), Python %s",
                    platform.system(), platform.release(), platform.machine(),
                    sys.version.split()[0])
        logger.debug(
            "Packages: aiohttp=%s pyusb=%s av=%s Pillow=%s",
            _pkg_version("aiohttp") or "missing",
            _pkg_version("usb") or "missing",
            _pkg_version("av") or "missing",
            _pkg_version("PIL", "Pillow") or "missing",
        )
        try:
            udid = getattr(self._lockdown, "identifier", None)
            ptype = getattr(self._lockdown, "product_type", None)
            pver = getattr(self._lockdown, "product_version", None)
            if udid:
                logger.info("Device: %s %s (UDID %s…%s)",
                            ptype or "?", pver or "?",
                            udid[:8], udid[-4:])
        except Exception:
            pass

    async def _stats_loop(self) -> None:
        """Log per-second capture/broadcast stats at DEBUG.

        Emits one line per second when frames are flowing. Useful to diagnose
        throughput problems (low fps), websocket back-pressure (queue grows,
        drops climb), and large frame sizes (encode quality vs. bandwidth).
        Skipped when no frames arrived in the window so idle output stays
        quiet.
        """
        last = time.monotonic()
        while True:
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return
            now = time.monotonic()
            dt = now - last
            last = now
            frames = self._stats_frames
            bytes_total = self._stats_bytes
            dropped = self._stats_dropped
            queue_max = self._stats_max_queue
            self._stats_frames = 0
            self._stats_bytes = 0
            self._stats_dropped = 0
            self._stats_max_queue = 0
            if frames == 0 or dt <= 0:
                continue
            avg_kb = bytes_total / frames / 1024.0
            logger.debug(
                "stats: fps=%.1f frames=%d dropped=%d ws_queue_max=%d "
                "avg_kb=%.1f clients=%d backend=%r",
                frames / dt, frames, dropped, queue_max, avg_kb,
                len(self._client_queues), self._backend or "-",
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start_capture(self) -> None:
        """Start the capture loop as a background task (idempotent)."""
        if self._capture_task is not None and not self._capture_task.done():
            return

        self._capture_task = asyncio.create_task(self._capture_loop(), name="capture")

    async def stop_capture(self) -> None:
        """Stop the capture loop."""
        if self._capture_task is not None and not self._capture_task.done():
            self._capture_task.cancel()
            try:
                await self._capture_task
            except (asyncio.CancelledError, Exception):
                pass
        self._capture_task = None

    async def frames(self):
        """Async iterator yielding JPEG frame bytes.

        Starts the capture loop automatically if not already running.
        Each consumer gets its own queue so multiple readers are supported.

        Usage::

            async with ScreenMirrorService(lockdown) as svc:
                async for jpeg_bytes in svc.frames():
                    await my_transport.send(jpeg_bytes)
        """
        await self.start_capture()
        # Per-client buffer: holds enough frames to absorb a brief consumer
        # stall without dropping mid-GOP. ~1.5 s at 60 fps. See _broadcast_msg
        # for the drop policy when this fills.
        q: asyncio.Queue = asyncio.Queue(maxsize=90)
        self._client_queues.add(q)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # If the capture task died, propagate its error.
                    if self._capture_task is not None and self._capture_task.done():
                        self._capture_task.result()
                        return
                    continue
                if isinstance(msg, bytes):
                    yield msg
        finally:
            self._client_queues.discard(q)

    async def serve(self) -> None:
        """Start capturing and serving to the built-in browser viewer. Blocks until Ctrl-C."""
        try:
            from aiohttp import web  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "screen-mirror requires aiohttp: "
                "pip install pymobiledevice3[screen-mirror]"
            )

        self._quiet_noisy_loggers()
        self._log_startup_banner()

        # Keep the device display on while streaming.
        power = PowerAssertionService(self._lockdown)
        async with power.create_power_assertion(
            "PreventUserIdleDisplaySleep", "pymobiledevice3-screen-mirror", timeout=0
        ):
            await self.start_capture()
            server_task = asyncio.create_task(self._run_server(), name="server")
            self._stats_task = asyncio.create_task(self._stats_loop(), name="stats")

            try:
                await asyncio.gather(self._capture_task, server_task)
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass
            finally:
                await self.stop_capture()
                server_task.cancel()
                if self._stats_task is not None:
                    self._stats_task.cancel()
                await asyncio.gather(server_task, self._stats_task,
                                     return_exceptions=True)

    # ------------------------------------------------------------------
    # Capture loop
    # ------------------------------------------------------------------

    def _broadcast_msg(self, msg: object) -> None:
        """Push *msg* (str or bytes) to every connected browser's queue.

        On overflow, drain the queue completely. Live H.264 only resyncs at
        keyframes, and the sender already caches the latest keyframe — when
        a saturated consumer eventually drains, it'll get the next keyframe
        from the live stream (typically <1 s away on this iPad's encoder)
        and the browser's decoder resyncs cleanly. Dropping only the oldest
        message would leak mid-GOP corruption to the wire.
        """
        if isinstance(msg, (bytes, bytearray)):
            self._record_frame_stats(msg)
        for q in list(self._client_queues):
            if q.full():
                self._stats_dropped += 1
                while True:
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        break
            q.put_nowait(msg)
            if q.qsize() > self._stats_max_queue:
                self._stats_max_queue = q.qsize()

    def _record_frame_stats(self, frame: bytes) -> None:
        self._stats_frames += 1
        self._stats_bytes += len(frame)

    async def _capture_loop(self) -> None:
        """Forward H.264 from the iPad straight to every WebSocket client.

        No decode, no re-encode — the browser does hardware H.264 decoding
        via WebCodecs. Server-side cost is just framing + WebSocket I/O.
        """
        udid = getattr(self._lockdown, "identifier", None)
        try:
            cap = IOSScreenCapture.create(udid=udid, backend=self._prefer_backend)
        except (BackendUnavailableError, ValueError) as exc:
            raise RuntimeError(f"Cannot start capture: {exc}") from exc

        try:
            cap.start()
        except (DeviceNotFoundError, MultipleDevicesError,
                ScreenRecordingPermissionError) as exc:
            raise RuntimeError(f"Cannot start capture: {exc}") from exc

        backend_name = "CMIO" if cap.__class__.__name__ == "ValeriaCMIO" else "libusb"
        self._set_backend(f"Valeria/{backend_name}")

        try:
            async for frame in cap.aframes():
                if not self._display_width and cap.width:
                    self._display_width = cap.width // 2
                    self._display_height = cap.height // 2

                # Synthesize the player config from the first SPS we see.
                # avc1.<profile_idc><constraints><level_idc> is what
                # WebCodecs.VideoDecoder.configure() expects.
                if self._stream_config is None and len(frame.sps) >= 4:
                    self._stream_config = json.dumps({
                        "codec": (
                            f"avc1."
                            f"{frame.sps[1]:02x}"
                            f"{frame.sps[2]:02x}"
                            f"{frame.sps[3]:02x}"
                        ),
                        "width": cap.width,
                        "height": cap.height,
                    })
                    self._broadcast_msg(f"config:{self._stream_config}")

                annexb = frame.to_annex_b()

                # Cache the most recent keyframe; new clients will get it on
                # connect so their decoder has an IDR + parameter sets to
                # initialise from.
                if frame.is_keyframe:
                    self._latest_keyframe = annexb

                self._broadcast_msg(annexb)
        except asyncio.CancelledError:
            raise
        finally:
            cap.stop()

    # ------------------------------------------------------------------
    # Web server
    # ------------------------------------------------------------------

    async def _run_server(self) -> None:
        from aiohttp import web

        app = web.Application()
        app.router.add_get("/", self._handle_index)
        app.router.add_get("/ws", self._handle_ws)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self._host, self._port)
        await site.start()

        # When bound to 0.0.0.0, show the real LAN IP so the user can click it.
        display_host = self._host
        if display_host in ("0.0.0.0", ""):
            import socket as _socket
            try:
                with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    display_host = s.getsockname()[0]
            except Exception:
                display_host = "localhost"

        url = f"http://{display_host}:{self._port}"

        # Wait briefly for the capture backend to be selected so the
        # ready-line can name it.
        for _ in range(30):
            if self._backend:
                break
            await asyncio.sleep(0.1)

        # Use logger (not print) so the URL is captured by `tee` and
        # gets a timestamp like the rest of the log. print() goes to
        # stdout which is block-buffered when piped, so the line was
        # invisible in tester logs until process exit.
        if self._backend:
            logger.info("Screen mirror ready at %s (backend: %s; Ctrl-C to stop)",
                        url, self._backend)
        else:
            logger.info("Screen mirror ready at %s (Ctrl-C to stop)", url)

        try:
            await asyncio.Event().wait()
        finally:
            await runner.cleanup()

    async def _handle_index(self, _request: object) -> object:
        from aiohttp import web

        for _ in range(40):
            if self._display_width:
                break
            await asyncio.sleep(0.1)

        w = self._display_width or 810
        h = self._display_height or 1080
        html = (_HTML_TEMPLATE
                .replace("__W__", str(w))
                .replace("__H__", str(h))
                .replace("__BACKEND__", self._backend or "connecting"))
        return web.Response(text=html, content_type="text/html")

    async def _handle_ws(self, request: object) -> object:
        from aiohttp import web

        ws = web.WebSocketResponse()
        await ws.prepare(request)  # type: ignore[arg-type]

        # See note on the other Queue above — maxsize=2 dropped H.264 packets
        # mid-GOP under any backpressure, leaving the browser's decoder with
        # broken inter-frame references.
        q: asyncio.Queue = asyncio.Queue(maxsize=90)
        self._client_queues.add(q)
        logger.debug("Browser connected (%d clients)", len(self._client_queues))

        try:
            if self._stream_config:
                await ws.send_str(f"config:{self._stream_config}")
            if self._backend:
                await ws.send_str(f"backend:{self._backend}")
            if self._latest_keyframe:
                await ws.send_bytes(self._latest_keyframe)

            while not ws.closed:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=5.0)
                    if isinstance(msg, str):
                        await ws.send_str(msg)
                    else:
                        await ws.send_bytes(msg)
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    break
        finally:
            self._client_queues.discard(q)
            logger.debug("Browser disconnected (%d clients)", len(self._client_queues))

        return ws

# ---------------------------------------------------------------------------
# Browser UI
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pymobiledevice3 · screen mirror</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #111; display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  min-height: 100dvh; font-family: ui-monospace, "Cascadia Code", "SF Mono", monospace;
  color: #888; gap: 8px; padding: 10px;
}
#wrap {
  position: relative; border: 1.5px solid #2a2a2a; border-radius: 14px;
  overflow: hidden; box-shadow: 0 8px 48px rgba(0,0,0,.9);
}
#screen { display: block; }
#bar { display: flex; gap: 16px; font-size: 11px; letter-spacing: .05em; align-items: center; }
.dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #333; margin-right: 5px; }
.ok .dot { background: #3f3; } .err .dot { background: #f33; } .warn .dot { background: #fa0; }
</style>
</head>
<body>
<div id="wrap"><canvas id="screen" width="__W__" height="__H__"></canvas></div>
<div id="bar">
  <span id="sws" class="warn"><span class="dot"></span>stream</span>
  <span id="sfps">– fps</span>
  <span id="sbe">__BACKEND__</span>
</div>
<script>
(function () {
  'use strict';

  if (typeof VideoDecoder === 'undefined') {
    document.body.innerHTML =
      '<p style="color:#f33;padding:20px;font-family:monospace">' +
      'WebCodecs not available. Use Chrome 94+, Edge 94+, ' +
      'Safari 16.4+, or Firefox 130+.</p>';
    return;
  }

  const screenEl = document.getElementById('screen');
  const ctx      = screenEl.getContext('2d');
  const sws      = document.getElementById('sws');
  const sfps     = document.getElementById('sfps');
  const sbe      = document.getElementById('sbe');

  let nativeW = __W__, nativeH = __H__;
  function fit() {
    const maxH = window.innerHeight * 0.94;
    const maxW = window.innerWidth * 0.98;
    const s = Math.min(maxH / nativeH, maxW / nativeW);
    screenEl.style.width  = Math.round(nativeW * s) + 'px';
    screenEl.style.height = Math.round(nativeH * s) + 'px';
  }
  fit(); window.addEventListener('resize', fit);

  // Scan an Annex-B byte sequence for an IDR NAL unit (type 5). Tells the
  // decoder whether to treat the chunk as a keyframe.
  function hasIdr(bytes) {
    for (let i = 0; i + 4 < bytes.length; i++) {
      if (bytes[i] === 0 && bytes[i+1] === 0 && bytes[i+2] === 0 && bytes[i+3] === 1) {
        if ((bytes[i+4] & 0x1f) === 5) return true;
      }
    }
    return false;
  }

  let decoder = null, configured = false, ts = 0;
  let frameCount = 0, lastFpsTime = performance.now();

  function setupDecoder(cfg) {
    if (decoder) {
      try { decoder.close(); } catch (_) {}
    }
    nativeW = cfg.width; nativeH = cfg.height;
    screenEl.width = nativeW; screenEl.height = nativeH;
    fit();
    decoder = new VideoDecoder({
      output(frame) {
        ctx.drawImage(frame, 0, 0, nativeW, nativeH);
        frame.close();
        frameCount++;
        const now = performance.now();
        if (now - lastFpsTime >= 1000) {
          sfps.textContent = frameCount + ' fps';
          frameCount = 0; lastFpsTime = now;
        }
      },
      error(e) { console.error('VideoDecoder:', e); sws.className = 'err'; }
    });
    decoder.configure({
      codec: cfg.codec,
      optimizeForLatency: true,
    });
    configured = true;
  }

  function feed(bytes) {
    if (!configured) return;  // discarding pre-config bytes
    const isKey = hasIdr(bytes);
    try {
      decoder.decode(new EncodedVideoChunk({
        type: isKey ? 'key' : 'delta',
        timestamp: ts,
        data: bytes,
      }));
    } catch (e) {
      console.error('decode error:', e);
    }
    ts += 16667;  // microseconds; fake monotonic clock at ~60 fps
  }

  function connect() {
    const ws = new WebSocket('ws://' + location.host + '/ws');
    ws.binaryType = 'arraybuffer';
    ws.onopen  = () => { sws.className = 'ok'; };
    ws.onclose = () => { sws.className = 'err'; configured = false; setTimeout(connect, 2000); };
    ws.onerror = () => { sws.className = 'err'; };
    ws.onmessage = e => {
      if (typeof e.data === 'string') {
        if (e.data.startsWith('config:')) {
          try { setupDecoder(JSON.parse(e.data.slice(7))); }
          catch (err) { console.error('bad config:', err); sws.className = 'err'; }
        } else if (e.data.startsWith('backend:')) {
          sbe.textContent = e.data.slice(8);
        }
        return;
      }
      feed(new Uint8Array(e.data));
    };
  }
  connect();
})();
</script>
</body>
</html>
"""
