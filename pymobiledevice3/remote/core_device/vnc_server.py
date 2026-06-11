"""
RFB 3.8 (VNC) server for the device's screen.

Open via macOS Finder ``Cmd+K`` → ``vnc://127.0.0.1:5900`` (or any
VNC client). No browser, no WebCodecs, no canvas state to corrupt --
each framebuffer update is a fresh JPEG decoded by the OS's native
client. Mouse clicks on the screen-sharing window translate to HID
touch on the device.

Encoding negotiated: Tight (with JPEG sub-encoding) when the client
advertises it; Raw fallback otherwise. Both deliver the JPEG bytes
produced by ``vt_jpeg.HevcToJpegTranscoder`` -- Raw decodes the JPEG
host-side first, Tight forwards the JPEG straight through.

Protocol references:
- RFC 6143 (RFB 3.8)
- Tight encoding: see TightVNC's "rfbproto.rst" for the JPEG sub-encoding
  (high-nibble 0x9 in the compression-control byte + compact length).
"""

import asyncio
import contextlib
import logging
import os
import socket
import struct
import uuid
from typing import Optional

from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.hevc_phantom import build_phantoms_for_bootstrap
from pymobiledevice3.remote.core_device.hid_service import (
    DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
    TOUCHSCREEN_STATE_CONTACT,
    TOUCHSCREEN_STATE_RELEASE,
    UniversalHIDServiceService,
)
from pymobiledevice3.remote.core_device.screen_stream import depacketize_hevc
from pymobiledevice3.remote.core_device.vt_jpeg import HevcToJpegTranscoder
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

logger = logging.getLogger(__name__)

_HEVC_NAL_IDR_W_RADL = 19
_HEVC_NAL_IDR_N_LP = 20
_HEVC_NAL_CRA = 21
_HEVC_NAL_VPS = 32
_HEVC_NAL_SPS = 33
_HEVC_NAL_PPS = 34


def _is_key_nal(nt: int) -> bool:
    return nt in (_HEVC_NAL_IDR_W_RADL, _HEVC_NAL_IDR_N_LP, _HEVC_NAL_CRA)


# RFB encoding identifiers
_ENC_RAW = 0
_ENC_COPY_RECT = 1
_ENC_TIGHT = 7
# pseudo-encodings (negative int32, but client lists them as positive in
# SetEncodings; we just match what the client advertises)
_ENC_CURSOR = -239
_ENC_DESKTOP_SIZE = -223
_ENC_LAST_RECT = -224

_SERVER_NAME = b"iPhone screen (pymobiledevice3)"


def _tight_compact_len(n: int) -> bytes:
    """RFB Tight encoding's compact length: 1-3 bytes, low 7 bits per
    byte with high bit = continuation."""
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return bytes([(n & 0x7F) | 0x80, (n >> 7) & 0x7F])
    return bytes([(n & 0x7F) | 0x80, ((n >> 7) & 0x7F) | 0x80, (n >> 14) & 0xFF])


class _VncClient:
    """Per-connection state."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.encodings: list[int] = []
        self.wants_update = asyncio.Event()
        self.last_sent_jpeg: Optional[bytes] = None
        # Pointer button state for click->drag->release synthesis.
        self.pressed = False
        self.last_x = 0
        self.last_y = 0


class VncStreamServer:
    """RFB 3.8 server. Streams the device screen as JPEG-encoded Tight
    (or Raw fallback) framebuffer updates."""

    def __init__(
        self,
        rsd: RemoteServiceDiscoveryService,
        *,
        bind: str = "127.0.0.1",
        port: int = 5901,
        display_id: int = 1,
        jpeg_quality: float = 0.7,
    ) -> None:
        self._rsd = rsd
        self._bind = bind
        self._port = port
        self._display_id = display_id
        self._jpeg_quality = jpeg_quality
        self._sender_ip = rsd.service.address[0]

        # Filled once we have a decoder + first frame.
        self._fb_width = 0
        self._fb_height = 0
        self._ready = asyncio.Event()
        self._latest_jpeg: Optional[bytes] = None

        self._clients: set[_VncClient] = set()
        self._transcoder: Optional[HevcToJpegTranscoder] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # HID for pointer-event translation.
        self._uhs: Optional[UniversalHIDServiceService] = None
        self._hid_lock = asyncio.Lock()

    # ----- HEVC -> JPEG callback marshalling --------------------------------
    def _on_jpeg_from_worker(self, jpeg: bytes) -> None:
        """Called from the VT transcoder worker thread."""
        loop = self._loop
        if loop is None:
            return
        loop.call_soon_threadsafe(self._broadcast_jpeg, jpeg)

    def _broadcast_jpeg(self, jpeg: bytes) -> None:
        self._latest_jpeg = jpeg
        if not self._ready.is_set() and self._transcoder is not None:
            self._fb_width = self._transcoder.width
            self._fb_height = self._transcoder.height
            self._ready.set()
        for c in self._clients:
            c.wants_update.set()

    # ----- RTP recv + phantom-NAL bridge ------------------------------------
    async def _udp_recv_and_pipe(self, sock: socket.socket) -> None:
        """Same depacketize loop as ScreenStreamServer / JpegStreamServer:
        gather Annex-B AUs, inject phantom NALs once at bootstrap, feed
        the VT transcoder."""
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
            if 64 <= pt <= 95:
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
                                "VT transcoder started: HEVC %dx%d -> JPEG (q=%.2f)",
                                self._transcoder.width,
                                self._transcoder.height,
                                self._jpeg_quality,
                            )
                        except Exception:
                            logger.exception("VT transcoder failed to start")
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
                            logger.info("phantom synthesis: %d NALs", len(phantoms))
                            for ph in phantoms:
                                self._transcoder.feed(b"\x00\x00\x00\x01" + ph)
                        except Exception:
                            logger.exception("phantom synthesis failed")
                        phantoms_built = True
                    if self._transcoder is not None:
                        annexb = b"".join(b"\x00\x00\x00\x01" + nal for nal in current_au)
                        self._transcoder.feed(annexb)
                current_au = []
                au_is_key = False
                au_corrupt = False

    # ----- HID --------------------------------------------------------------
    async def _ensure_hid(self) -> None:
        async with self._hid_lock:
            if self._uhs is None:
                uhs = UniversalHIDServiceService(self._rsd)
                await uhs.connect()
                self._uhs = uhs

    async def _stop_hid(self) -> None:
        if self._uhs is not None:
            with contextlib.suppress(Exception):
                await self._uhs.close()
            self._uhs = None

    async def _handle_pointer(self, client: _VncClient, button_mask: int, x: int, y: int) -> None:
        """Translate an RFB PointerEvent into HID touchscreen contact.

        The device's HID coords are uint16 normalised across the full
        display; we rescale from framebuffer pixels (0..fb_w/h) to
        0..65535. Left mouse button (bit 0) == finger touch."""
        if self._fb_width <= 0 or self._fb_height <= 0:
            return
        hid_x = max(0, min(65535, int(x * 65535 / max(1, self._fb_width - 1))))
        hid_y = max(0, min(65535, int(y * 65535 / max(1, self._fb_height - 1))))
        pressed = bool(button_mask & 1)
        try:
            await self._ensure_hid()
            assert self._uhs is not None
            if pressed:
                await self._uhs.send_touchscreen(
                    TOUCHSCREEN_STATE_CONTACT,
                    hid_x,
                    hid_y,
                    service_id=DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
                )
            elif client.pressed:
                # Transition pressed -> released: send release at the
                # last drag position.
                await self._uhs.send_touchscreen(
                    TOUCHSCREEN_STATE_RELEASE,
                    hid_x,
                    hid_y,
                    service_id=DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
                )
        except Exception:
            logger.exception("HID send failed")
        client.pressed = pressed
        client.last_x = hid_x
        client.last_y = hid_y

    # ----- RFB protocol -----------------------------------------------------
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client = _VncClient(reader, writer)
        logger.info("VNC client connected: %s", peer)
        try:
            # Wait for the first frame so we have framebuffer dimensions.
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._ready.wait(), timeout=10.0)
            if not self._ready.is_set():
                logger.warning("VNC client %s: stream not ready, dropping", peer)
                return
            await self._handshake(client)
            self._clients.add(client)
            await asyncio.gather(
                self._client_send_loop(client),
                self._client_recv_loop(client),
            )
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception:
            logger.exception("VNC client crashed: %s", peer)
        finally:
            self._clients.discard(client)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            logger.info("VNC client disconnected: %s", peer)

    async def _handshake(self, client: _VncClient) -> None:
        r = client.reader
        w = client.writer
        # 1. ProtocolVersion (12 bytes each way).
        w.write(b"RFB 003.008\n")
        await w.drain()
        logger.info("handshake: sent server version RFB 003.008")
        client_version_bytes = await r.readexactly(12)
        client_version = client_version_bytes.decode("ascii", errors="replace").rstrip()
        logger.info("handshake: client version %r", client_version)
        # Parse minor version. The protocol changes between 3.3 / 3.7 /
        # 3.8 across the security handshake:
        #
        #   3.3 -- server unilaterally picks ONE security type and sends
        #          it as a U32. No SecurityResult on None auth.
        #   3.7 -- server sends a list (count + types[]), client picks.
        #          No SecurityResult on None auth.
        #   3.8 -- server sends a list, client picks, server always
        #          sends SecurityResult.
        #
        # macOS Screen Sharing.app picks 3.3 (regardless of our offer)
        # because that's the protocol Apple Remote Desktop wraps. So
        # we MUST support 3.3 if we want to be reachable from Finder
        # Cmd+K -> vnc:// out of the box.
        minor = 8
        try:
            if client_version.startswith("RFB 003."):
                minor = int(client_version[8:11])
        except ValueError:
            minor = 8
        # macOS Screen Sharing's password dialog refuses an empty entry
        # even when the server advertises None auth, so we advertise
        # VNC Auth (security type 2) and accept whatever the client
        # sends in the challenge/response -- the user can type any
        # password and the connection proceeds. Standard "open VNC
        # server with mock auth" pattern.
        if minor < 7:
            # RFB 3.3: server unilaterally picks the security type.
            w.write(struct.pack(">I", 2))  # VNC Auth
            await w.drain()
            logger.info("handshake: 3.3 path -- server picked VNC Auth")
        else:
            # RFB 3.7 / 3.8: send security list, client picks. Offer
            # only VNC Auth so we always end up in the same code path.
            w.write(b"\x01\x02")
            await w.drain()
            logger.info("handshake: sent security types [VNC Auth=2]")
            chosen = (await r.readexactly(1))[0]
            logger.info("handshake: client picked security=%d", chosen)
            if chosen != 2:
                msg = b"unsupported security type"
                w.write(struct.pack(">I", 1) + struct.pack(">I", len(msg)) + msg)
                await w.drain()
                raise ConnectionError(f"client picked unsupported security={chosen}")
        # VNC Auth challenge/response. Send 16 random bytes; the
        # client encrypts them with DES using its (up to) 8-byte
        # password as the key and sends the 16-byte ciphertext back.
        # We don't actually verify the response -- any input is OK.
        challenge = os.urandom(16)
        w.write(challenge)
        await w.drain()
        await r.readexactly(16)  # response (ignored)
        logger.info("handshake: VNC Auth accepted (any password)")
        # 3.x always sends SecurityResult AFTER VNC Auth, regardless of
        # whether None auth would have skipped it.
        w.write(b"\x00\x00\x00\x00")
        await w.drain()
        logger.info("handshake: sent SecurityResult=OK")
        # ClientInit (shared flag — we don't care).
        shared = (await r.readexactly(1))[0]
        logger.info("handshake: client shared=%d", shared)
        # 5. ServerInit: width, height, pixel format, name.
        # Pixel format = 32bpp little-endian BGRA. (For Tight-JPEG the
        # client doesn't need this to match the JPEG; for Raw we'd
        # need to emit BGRA bytes -- this server only emits Tight-JPEG
        # frames so the pixel format is mostly cosmetic but we still
        # advertise something sensible.)
        pixel_format = struct.pack(
            ">BBBB HHH BBB 3x",
            32,  # bits-per-pixel
            24,  # depth
            0,  # big-endian-flag
            1,  # true-colour-flag
            255,
            255,
            255,  # red/green/blue max
            16,
            8,
            0,  # red/green/blue shift
        )
        server_init = (
            struct.pack(">HH", self._fb_width, self._fb_height)
            + pixel_format
            + struct.pack(">I", len(_SERVER_NAME))
            + _SERVER_NAME
        )
        w.write(server_init)
        await w.drain()
        logger.info("handshake: sent ServerInit (%dx%d, name=%r)", self._fb_width, self._fb_height, _SERVER_NAME)

    async def _client_recv_loop(self, client: _VncClient) -> None:
        r = client.reader
        while True:
            msg_type_b = await r.readexactly(1)
            msg_type = msg_type_b[0]
            if msg_type == 0:
                # SetPixelFormat: padding(3) + pixel-format(16). Ignored
                # -- we always send Tight-JPEG; client must accept ours.
                await r.readexactly(3 + 16)
            elif msg_type == 2:
                # SetEncodings: padding(1) + n(2) + n * int32
                await r.readexactly(1)
                n = struct.unpack(">H", await r.readexactly(2))[0]
                raw = await r.readexactly(4 * n)
                client.encodings = list(struct.unpack(f">{n}i", raw))
                logger.info(
                    "VNC client encodings: %s",
                    [
                        {
                            _ENC_RAW: "Raw",
                            _ENC_COPY_RECT: "CopyRect",
                            _ENC_TIGHT: "Tight",
                            _ENC_CURSOR: "Cursor",
                            _ENC_DESKTOP_SIZE: "DesktopSize",
                            _ENC_LAST_RECT: "LastRect",
                        }.get(e, str(e))
                        for e in client.encodings
                    ],
                )
            elif msg_type == 3:
                # FramebufferUpdateRequest: incremental(1) + x(2) + y(2) + w(2) + h(2)
                await r.readexactly(9)
                client.wants_update.set()
            elif msg_type == 4:
                # KeyEvent: down-flag(1) + padding(2) + key(4). Ignored.
                await r.readexactly(7)
            elif msg_type == 5:
                # PointerEvent: button-mask(1) + x(2) + y(2)
                data = await r.readexactly(5)
                button_mask, px, py = struct.unpack(">BHH", data)
                await self._handle_pointer(client, button_mask, px, py)
            elif msg_type == 6:
                # ClientCutText: padding(3) + length(4) + text. Ignored.
                await r.readexactly(3)
                ln = struct.unpack(">I", await r.readexactly(4))[0]
                if ln:
                    await r.readexactly(ln)
            else:
                logger.warning("VNC client sent unknown msg-type %d, terminating", msg_type)
                return

    async def _client_send_loop(self, client: _VncClient) -> None:
        w = client.writer
        while True:
            await client.wants_update.wait()
            client.wants_update.clear()
            jpeg = self._latest_jpeg
            if jpeg is None or jpeg is client.last_sent_jpeg:
                continue
            client.last_sent_jpeg = jpeg
            # FramebufferUpdate: msg-type(1) + padding(1) + n-rects(2) + rects
            #
            # Tight rect: x(2) y(2) w(2) h(2) encoding(4=Tight=7)
            #             control-byte(1) + compact-length + JPEG bytes
            # Tight control-byte for JPEG sub-encoding: 0x90
            # (high nibble 1001 = JPEG, low nibble 0000).
            #
            # We always send the WHOLE framebuffer as a single rect.
            # Tight is *not* a true "diff"; we just pay the JPEG once.
            use_tight = _ENC_TIGHT in client.encodings
            if use_tight:
                rect_header = struct.pack(
                    ">HHHHi",
                    0,
                    0,
                    self._fb_width,
                    self._fb_height,
                    _ENC_TIGHT,
                )
                jpeg_body = b"\x90" + _tight_compact_len(len(jpeg)) + jpeg
                payload = (
                    b"\x00"  # msg-type = FramebufferUpdate
                    b"\x00"  # padding
                    + struct.pack(">H", 1)  # one rect
                    + rect_header
                    + jpeg_body
                )
            else:
                # Raw fallback. We'd need to decode the JPEG and send
                # BGRA pixels. Not implementing for v1 -- modern clients
                # (including macOS Screen Sharing) advertise Tight.
                logger.warning(
                    "VNC client doesn't support Tight encoding; Raw fallback not implemented, dropping connection"
                )
                return
            w.write(payload)
            try:
                await w.drain()
            except (ConnectionResetError, BrokenPipeError):
                return

    # ----- top-level orchestration ------------------------------------------
    async def serve(self) -> None:
        # 1) UDP socket for RTP/HEVC.
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
            "video stream up: %dx%d HEVC, sender_port=%s",
            int(cfg.get("CustomWidth", 0)),
            int(cfg.get("CustomHeight", 0)),
            cfg.get("SourcePort"),
        )

        # 3) Background tasks.
        loop = asyncio.get_running_loop()
        self._loop = loop
        feed_task = asyncio.create_task(self._udp_recv_and_pipe(sock))

        # 4) TCP listener for VNC clients.
        server = await asyncio.start_server(self._handle_client, self._bind, self._port)
        stop_event = asyncio.Event()

        def _request_stop() -> None:
            if not stop_event.is_set():
                logger.info("shutting down...")
                stop_event.set()

        import signal as _signal

        for signame in ("SIGINT", "SIGTERM"):
            with contextlib.suppress(NotImplementedError, AttributeError):
                loop.add_signal_handler(getattr(_signal, signame), _request_stop)

        serve_task = asyncio.create_task(server.serve_forever())
        try:
            logger.info(
                "VNC ready: connect with `vnc://%s:%d` (Finder Cmd+K). Ctrl-C to stop.",
                self._bind,
                self._port,
            )
            await stop_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            if not serve_task.done():
                serve_task.cancel()
            logger.info("shutdown: closing TCP listener")
            server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), timeout=2.0)
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
            logger.info("shutdown: stopping device stream")
            with contextlib.suppress(Exception):
                await asyncio.wait_for(svc.stop_media_stream(sid), timeout=3.0)
            with contextlib.suppress(Exception):
                await svc.close()
            current = asyncio.current_task()
            stragglers = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
            for t in stragglers:
                t.cancel()
            if stragglers:
                with contextlib.suppress(Exception):
                    await asyncio.wait(stragglers, timeout=2.0)
            logger.info("shutdown complete")
