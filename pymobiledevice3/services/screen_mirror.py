"""
pymobiledevice3/services/screen_mirror.py

Browser-based screen mirror for iOS devices.

Capture backends (tried in priority order)
------------------------------------------
1. **AVFoundation** (macOS + USB only, 30-60 fps)
   Same CoreMediaIO/QuickTime mechanism as QuickTime Player.
   Requires ``pip install pyobjc-framework-AVFoundation pyobjc-framework-CoreMediaIO
   pyobjc-framework-Quartz``.

2. **Accessibility daemon** (~4 fps, USB or WiFi)
   ``deviceCaptureScreenshot`` via the accessibility audit daemon.
   Works without Developer Mode.

Requirements
------------
- Device paired and trusted
- ``pip install aiohttp``          web server
- ``pip install pillow``           PNG→JPEG re-encoding (optional)
"""

from __future__ import annotations

import asyncio
import io
import logging
import time
from typing import Optional

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit

logger = logging.getLogger(__name__)

_JPEG_QUALITY = 60


def _compress_frame(png_bytes: bytes, quality: int = _JPEG_QUALITY) -> bytes:
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(png_bytes))
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=quality, optimize=False)
        jpeg = buf.getvalue()
        return jpeg if len(jpeg) < len(png_bytes) else png_bytes
    except ImportError:
        return png_bytes


class ScreenMirrorService:
    """
    Captures iOS screen frames and serves them to a browser via WebSocket.

    Usage::

        async with ScreenMirrorService(lockdown) as svc:
            await svc.serve()   # blocks; open http://localhost:8080
    """

    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        host: str = "127.0.0.1",
        port: int = 8080,
        fps_cap: float = 60.0,
        jpeg_quality: int = _JPEG_QUALITY,
    ) -> None:
        self._lockdown = lockdown
        self._host = host
        self._port = port
        self._min_interval = 1.0 / fps_cap
        self._jpeg_quality = jpeg_quality

        self._client_queues: set[asyncio.Queue] = set()
        self._latest_frame: Optional[bytes] = None
        self._display_width: int = 0
        self._display_height: int = 0

    async def __aenter__(self) -> "ScreenMirrorService":
        return self

    async def __aexit__(self, *_: object) -> None:
        pass

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def serve(self) -> None:
        """Start capturing and serving. Blocks until Ctrl-C."""
        try:
            from aiohttp import web  # noqa: F401
        except ImportError:
            raise RuntimeError("aiohttp is required: pip install aiohttp")

        capture_task = asyncio.create_task(self._capture_loop(), name="capture")
        server_task = asyncio.create_task(self._run_server(), name="server")

        try:
            await asyncio.gather(capture_task, server_task)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            capture_task.cancel()
            server_task.cancel()
            await asyncio.gather(capture_task, server_task, return_exceptions=True)

    # ------------------------------------------------------------------
    # Capture loop
    # ------------------------------------------------------------------

    def _push_frame(self, png: bytes) -> None:
        """Compress and broadcast a raw PNG frame to all WebSocket clients."""
        if not self._display_width:
            # Extract native dimensions from PNG IHDR (bytes 16–23) and halve
            # for logical points (all current iOS devices are 2× or 3× Retina;
            # halving is exact for 2× and gives a close-enough aspect for 3×).
            try:
                import struct as _struct
                w, h = _struct.unpack(">II", png[16:24])
                self._display_width = w // 2
                self._display_height = h // 2
                logger.info("Display (from PNG IHDR): %dx%d native → %dx%d logical",
                            w, h, self._display_width, self._display_height)
            except Exception:
                pass

        frame = _compress_frame(png, self._jpeg_quality)
        self._latest_frame = frame
        for q in list(self._client_queues):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(frame)

    def _broadcast_frame(self, jpeg: bytes) -> None:
        """Send a pre-compressed JPEG frame to all WebSocket clients."""
        self._latest_frame = jpeg
        for q in list(self._client_queues):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(jpeg)

    async def _capture_loop(self) -> None:
        """Try capture methods in priority order: AVFoundation → accessibility."""
        if await self._capture_loop_avfoundation():
            return
        await self._capture_loop_accessibility()

    async def _capture_loop_avfoundation(self) -> bool:
        """
        Highest priority: AVFoundation via CoreMediaIO (macOS only, 30-60 fps).
        Uses the same mechanism as QuickTime — iOS device appears as a capture device
        over USB.  Requires: ``pip install pyobjc-framework-AVFoundation
        pyobjc-framework-CoreMediaIO pyobjc-framework-Quartz``
        """
        try:
            from pymobiledevice3.services.avfoundation_capture import AVFoundationCapture
        except ImportError:
            return False

        udid = getattr(self._lockdown, 'identifier', None)
        cap = AVFoundationCapture(jpeg_quality=self._jpeg_quality / 100.0, udid=udid)
        if not cap.start():
            return False

        if cap.width and cap.height:
            self._display_width = cap.width // 2
            self._display_height = cap.height // 2
            logger.info("AVFoundation: %dx%d native → %dx%d logical",
                        cap.width, cap.height, self._display_width, self._display_height)

        logger.info("Screenshot: AVFoundation (high-fps)")
        try:
            while True:
                jpeg = await cap.get_frame(timeout=1.0)
                if jpeg:
                    # Extract dimensions from JPEG SOF0 marker on first frame
                    if not self._display_width and len(jpeg) > 16:
                        try:
                            from PIL import Image
                            img = Image.open(io.BytesIO(jpeg))
                            w, h = img.size
                            self._display_width = w // 2
                            self._display_height = h // 2
                            logger.info("AVFoundation: %dx%d → %dx%d logical",
                                        w, h, self._display_width, self._display_height)
                        except Exception:
                            pass
                    self._broadcast_frame(jpeg)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("AVFoundation capture error: %s — falling back", exc)
            return False
        finally:
            cap.stop()
        return True

    async def _capture_loop_accessibility(self) -> None:
        """Fallback path: ``deviceCaptureScreenshot`` via accessibility daemon (~4 fps)."""
        async with AccessibilityAudit(self._lockdown) as audit:
            logger.info("Screenshot: accessibility daemon (fallback)")
            while True:
                t0 = time.monotonic()
                try:
                    result = await audit._invoke("deviceCaptureScreenshot")
                    png = result.get("imageData", b"") if isinstance(result, dict) else b""
                    if not png:
                        await asyncio.sleep(0.1)
                        continue

                    if not self._display_width and isinstance(result, dict):
                        try:
                            parts = result.get("displayBounds", "").strip("{}").split(",")
                            self._display_width = int(float(parts[2]))
                            self._display_height = int(float(parts[3]))
                            logger.info("Display (from bounds): %dx%d",
                                        self._display_width, self._display_height)
                        except Exception:
                            pass

                    self._push_frame(png)

                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("Accessibility capture error: %s", exc)
                    await asyncio.sleep(0.5)
                    continue

                elapsed = time.monotonic() - t0
                sleep = self._min_interval - elapsed
                if sleep > 0:
                    await asyncio.sleep(sleep)

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
        link = f"\033]8;;{url}\033\\{url}\033]8;;\033\\"
        print()
        print(f"  Screen mirror ready  →  {link}")
        print("  Open in any browser  ·  Ctrl-C to stop")
        print()

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
        html = _HTML_TEMPLATE.replace("__W__", str(w)).replace("__H__", str(h))
        return web.Response(text=html, content_type="text/html")

    async def _handle_ws(self, request: object) -> object:
        from aiohttp import web

        ws = web.WebSocketResponse()
        await ws.prepare(request)  # type: ignore[arg-type]

        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=2)
        self._client_queues.add(q)
        logger.debug("Browser connected (%d clients)", len(self._client_queues))

        try:
            if self._latest_frame:
                await ws.send_bytes(self._latest_frame)

            while not ws.closed:
                try:
                    frame = await asyncio.wait_for(q.get(), timeout=5.0)
                    await ws.send_bytes(frame)
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
<div id="wrap"><img id="screen" alt=""></div>
<div id="bar">
  <span id="sws" class="warn"><span class="dot"></span>stream</span>
  <span id="sfps">– fps</span>
</div>
<script>
(function () {
  'use strict';
  const W = __W__, H = __H__;
  const screenEl = document.getElementById('screen');
  const sws      = document.getElementById('sws');
  const sfps     = document.getElementById('sfps');

  function fit() {
    const maxH = window.innerHeight * 0.94;
    const maxW = window.innerWidth * 0.98;
    const s = Math.min(maxH / H, maxW / W);
    screenEl.style.width  = Math.round(W * s) + 'px';
    screenEl.style.height = Math.round(H * s) + 'px';
  }
  fit(); window.addEventListener('resize', fit);

  let prevUrl = null, frameCount = 0, lastFpsTime = performance.now();
  function connect() {
    const ws = new WebSocket('ws://' + location.host + '/ws');
    ws.binaryType = 'blob';
    ws.onopen  = () => { sws.className = 'ok'; };
    ws.onclose = () => { sws.className = 'err'; setTimeout(connect, 2000); };
    ws.onerror = () => { sws.className = 'err'; };
    ws.onmessage = e => {
      const url = URL.createObjectURL(e.data);
      screenEl.src = url;
      if (prevUrl) URL.revokeObjectURL(prevUrl);
      prevUrl = url;
      frameCount++;
      const now = performance.now();
      if (now - lastFpsTime >= 1000) {
        sfps.textContent = frameCount + ' fps';
        frameCount = 0; lastFpsTime = now;
      }
    };
  }
  connect();
})();
</script>
</body>
</html>
"""
