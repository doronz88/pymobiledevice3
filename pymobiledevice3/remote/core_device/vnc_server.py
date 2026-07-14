"""
RFB 3.8 (VNC) server for the device's screen.

Open via macOS Finder ``Cmd+K`` → ``vnc://127.0.0.1:5901`` (or any
VNC client). No browser, no WebCodecs, no canvas state to corrupt --
each framebuffer update is a fresh BGRA frame straight from the
VideoToolbox HEVC decoder.

Pipeline: RTP/HEVC -> VTDecompressionSession (BGRA output) -> Raw VNC.

No JPEG round-trip on this path. The previous design encoded BGRA ->
JPEG -> decoded JPEG -> BGRA again before sending; macOS Screen
Sharing's client doesn't advertise Tight, so the JPEG was always
thrown away. Skipping it removes the second lossy step (q=0.7 JPEG on
top of the device's already-tear-y HEVC frame under motion) and the
encode+decode CPU work.

Only the Raw encoding is offered. Raw is mandatory per RFC 6143 §7.7.1
-- every VNC client supports it, including macOS Screen Sharing and
every third-party viewer that doesn't speak Apple-private encodings.

Protocol reference: RFC 6143 (RFB 3.8).
"""

import asyncio
import contextlib
import logging
import os
import select
import socket
import struct
import sys
import uuid
from typing import Optional

from pymobiledevice3.remote.core_device.aac_eld import AACELDDecoder
from pymobiledevice3.remote.core_device.audio_player import AudioQueuePlayer
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.hid_service import (
    ASCII_TO_HID,
    DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
    HID_BUTTON_STATE_DOWN,
    HID_BUTTON_STATE_UP,
    KEY_BACKSPACE,
    KEY_CAPS_LOCK,
    KEY_DOWN,
    KEY_ENTER,
    KEY_ESC,
    KEY_F1,
    KEY_LEFT,
    KEY_LEFT_ALT,
    KEY_LEFT_CTRL,
    KEY_LEFT_GUI,
    KEY_LEFT_SHIFT,
    KEY_RIGHT,
    KEY_RIGHT_ALT,
    KEY_RIGHT_CTRL,
    KEY_RIGHT_GUI,
    KEY_RIGHT_SHIFT,
    KEY_TAB,
    KEY_UP,
    TOUCHSCREEN_STATE_CONTACT,
    TOUCHSCREEN_STATE_RELEASE,
    IndigoHIDService,
    UniversalHIDServiceService,
)
from pymobiledevice3.remote.core_device.screen_stream import UdpMediaTransport, depacketize_hevc, open_media_receiver
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

logger = logging.getLogger(__name__)


def _resolve_decoder(choice: str):
    """Pick the HEVC decoder class.

    ``choice`` is one of ``"auto"`` (VideoToolbox on macOS, libav
    everywhere else), ``"vt"`` (force VideoToolbox), or ``"av"``
    (force libav / PyAV). ``PYMD3_HEVC_DECODER=av`` overrides
    ``"auto"`` for parity with the CLI flag.

    Both classes expose the same ``feed`` / ``on_frame`` /
    ``on_decode_error`` / ``width`` / ``height`` / ``close`` surface so
    the recv loop below doesn't branch on the choice.
    """
    choice = (choice or "auto").lower()
    if choice == "auto":
        if os.environ.get("PYMD3_HEVC_DECODER", "").lower() == "av":
            choice = "av"
        else:
            choice = "vt" if sys.platform == "darwin" else "av"
    if choice == "vt":
        from pymobiledevice3.remote.core_device.vt_jpeg import HevcToBgraTranscoder

        return HevcToBgraTranscoder
    if choice == "av":
        from pymobiledevice3.remote.core_device.hevc_av import HevcToBgraTranscoder

        return HevcToBgraTranscoder
    raise ValueError(f"unknown decoder choice: {choice!r}")


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
# pseudo-encodings (negative int32, but client lists them as positive in
# SetEncodings; we just match what the client advertises)
_ENC_CURSOR = -239
_ENC_DESKTOP_SIZE = -223
_ENC_LAST_RECT = -224

_SERVER_NAME = b"iPhone screen (pymobiledevice3)"

# Named iOS hardware buttons → (usage_page, usage_code). Same table as
# ``cli/developer/core_device.py``; replicated rather than imported so
# this server module stays decoupled from the CLI layer.
_BTN_HOME = (0x0C, 0x40)
_BTN_LOCK = (0x0C, 0x30)
_BTN_VOL_UP = (0x0C, 0xE9)
_BTN_VOL_DOWN = (0x0C, 0xEA)
_BTN_MUTE = (0x0C, 0xE2)
_BTN_SIRI = (0x0C, 0xCF)

# RFB mouse-button bit (zero-indexed) -> iOS button.
# Left button (bit 0) is the touch-pointer, handled separately.
_MOUSE_BUTTON_TO_HID: dict[int, tuple[int, int]] = {
    1: _BTN_LOCK,  # middle click
    2: _BTN_HOME,  # right click
}

# Modifier keysyms. macOS Screen Sharing sends each modifier as its
# own KeyEvent down/up around the letter, so we track state per
# client and gate the hotkey lookup on Ctrl being held.
_KEYSYM_CTRL = frozenset({0xFFE3, 0xFFE4})  # Control_L / Control_R
_KEYSYM_SHIFT = frozenset({0xFFE1, 0xFFE2})
_KEYSYM_ALT = frozenset({0xFFE9, 0xFFEA})  # Alt_L (Option) / Alt_R
_KEYSYM_CMD = frozenset({0xFFE7, 0xFFE8, 0xFFEB, 0xFFEC})  # Meta_L/R or Super_L/R

# X11 modifier-keysym -> HID modifier usage. Both sides of the keyboard
# are kept so a client distinguishing L/R shift still works (we just
# treat them as separate bits in the bitmap).
_KEYSYM_TO_HID_MODIFIER: dict[int, int] = {
    0xFFE1: KEY_LEFT_SHIFT,
    0xFFE2: KEY_RIGHT_SHIFT,
    0xFFE3: KEY_LEFT_CTRL,
    0xFFE4: KEY_RIGHT_CTRL,
    0xFFE7: KEY_LEFT_GUI,
    0xFFE8: KEY_RIGHT_GUI,  # Meta_L / Meta_R
    0xFFE9: KEY_LEFT_ALT,
    0xFFEA: KEY_RIGHT_ALT,
    0xFFEB: KEY_LEFT_GUI,
    0xFFEC: KEY_RIGHT_GUI,  # Super_L / Super_R
}

# X11 special keysyms (non-printable) -> HID usage.
_KEYSYM_TO_HID_SPECIAL: dict[int, int] = {
    0xFF08: KEY_BACKSPACE,
    0xFF09: KEY_TAB,
    0xFF0D: KEY_ENTER,
    0xFF8D: KEY_ENTER,  # Return / KP_Enter
    0xFF1B: KEY_ESC,
    0xFFE5: KEY_CAPS_LOCK,
    0xFF50: 0x4A,  # Home
    0xFF51: KEY_LEFT,
    0xFF52: KEY_UP,
    0xFF53: KEY_RIGHT,
    0xFF54: KEY_DOWN,
    0xFF55: 0x4B,  # Page_Up
    0xFF56: 0x4E,  # Page_Down
    0xFF57: 0x4D,  # End
    0xFF63: 0x49,  # Insert
    0xFFFF: 0x4C,  # Delete (forward)
    # F1..F12 are sequential keysyms 0xFFBE..0xFFC9 and sequential HID
    # usages KEY_F1..KEY_F12.
    **{0xFFBE + i: KEY_F1 + i for i in range(12)},
}


# Ctrl + keysym -> iOS button. Ctrl is the prefix because:
# - No Fn required: every Mac keyboard has a real Ctrl key.
# - Cmd never reaches us: Screen Sharing.app intercepts Cmd+anything
#   for its own window shortcuts.
# - Option+letter emits special chars on Mac (Opt+s -> ß etc.) which
#   Screen Sharing forwards as those chars, not the base letter.
# - Reserves plain letters / symbols for the upcoming text-input HID
#   path, so hotkeys won't collide with typing once we add it.
# Both ASCII cases are mapped, so Caps Lock or held-Shift don't break
# a hotkey (e.g. Ctrl+] vs Ctrl+}).
_CTRL_COMBO_TO_HID: dict[int, tuple[int, int]] = {
    ord("h"): _BTN_HOME,
    ord("H"): _BTN_HOME,
    ord("l"): _BTN_LOCK,
    ord("L"): _BTN_LOCK,
    ord("["): _BTN_VOL_DOWN,
    ord("{"): _BTN_VOL_DOWN,
    ord("]"): _BTN_VOL_UP,
    ord("}"): _BTN_VOL_UP,
    ord("\\"): _BTN_MUTE,
    ord("|"): _BTN_MUTE,
    ord("s"): _BTN_SIRI,
    ord("S"): _BTN_SIRI,
}


class _VncClient:
    """Per-connection state."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.encodings: list[int] = []
        self.wants_update = asyncio.Event()
        # Identity-keyed dedupe: the broadcaster swaps in a new ``bytes``
        # object per frame, so reference equality is enough.
        self.last_sent_frame: Optional[bytes] = None
        # Pointer button state for click->drag->release synthesis.
        self.pressed = False
        self.last_x = 0
        self.last_y = 0
        # Previous RFB button mask, used to diff non-left buttons
        # (right/middle) on each PointerEvent so we can fire the
        # mapped iOS hardware button on the down->up edge.
        self.last_button_mask = 0
        # Modifier state -- Ctrl is the only one consulted for hotkey
        # gating today; the rest are tracked for symmetry / future use.
        self.mod_ctrl = False
        self.mod_shift = False
        self.mod_alt = False
        self.mod_cmd = False
        # keysym -> (page, code) for hotkeys whose key-down fired a
        # button-down. We need this so that on key-up we send the
        # matching button-up regardless of whether the user released
        # Ctrl first.
        self.active_combos: dict[int, tuple[int, int]] = {}
        # Currently-held HID keyboard usage codes. Every key event
        # rewrites this set and re-emits the full bitmap report.
        self.pressed_keys: set[int] = set()
        # keysym -> set of usage codes the key-down emitted. Tracked so
        # key-up can release the same usages, even if the host's
        # interpretation of the keysym (e.g. shifted vs unshifted) has
        # drifted between the down and the up.
        self.active_typing: dict[int, tuple[int, ...]] = {}


class VncStreamServer:
    """RFB 3.8 server. Streams the device screen as Raw BGRA
    framebuffer updates."""

    def __init__(
        self,
        rsd: RemoteServiceDiscoveryService,
        *,
        bind: str = "0.0.0.0",
        port: int = 5901,
        display_id: int = 1,
        audio: bool = False,
        decoder: str = "auto",
        allow_rtcp_fb: bool = False,
        ltrp_enabled: bool = False,
    ) -> None:
        self._rsd = rsd
        self._bind = bind
        self._port = port
        self._display_id = display_id
        self._audio_enabled = audio
        self._sender_ip = rsd.service.address[0]
        # Protobuf-level negotiation knobs; see media_stream_offer.py.
        self._allow_rtcp_fb = allow_rtcp_fb
        self._ltrp_enabled = ltrp_enabled
        self._transcoder_cls = _resolve_decoder(decoder)
        logger.info("HEVC decoder: %s", self._transcoder_cls.__module__)

        # Filled once we have a decoder + first frame.
        self._fb_width = 0
        self._fb_height = 0
        self._ready = asyncio.Event()
        # Raw BGRA bytes of the most recent decoded frame. Exactly
        # ``fb_width * fb_height * 4`` bytes once ``_ready`` is set.
        self._latest_frame: Optional[bytes] = None

        self._clients: set[_VncClient] = set()
        self._transcoder = None  # type: ignore[assignment]
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._frames_emitted = 0

        # RTCP feedback (PLI = "send me a fresh IDR"). Populated from
        # ``streamConfig`` after start_video_stream returns. Without
        # these we can't kick the encoder, and decoder-refresh becomes
        # a no-op.
        self._active_transport: Optional[UdpMediaTransport] = None
        self._local_ssrc: int = 0
        self._remote_ssrc: int = 0
        self._rtcp_dest: Optional[tuple[str, int]] = None
        self._pli_tasks: set[asyncio.Task] = set()
        # Extended highest video RTP seq, for the periodic Receiver Report that
        # keeps the device from reaping the video session (RTCPTimeoutEnabled).
        self._rtp_highest_seq: int = 0

        # Keyframe-recovery state. Reverse-engineered from AVConference's
        # receiver (VIDEOPROCESSING_RE_ROADMAP.md §8, decision C): DeviceHub
        # requests a keyframe (FIR/PLI) ONLY when its decoder reports a genuine
        # failure, and dedupes it against an already-requested keyframe. It never
        # rebuilds the decoder and never fires on packet gaps, predicted
        # reference loss, motion, or timers -- its telemetry showed FIR=0 for a
        # whole heavy-motion session while never tearing. So the old
        # motion/heartbeat decoder-rebuild loop and the pre-decode RPS-prediction
        # PLI (both of which caused the "smear then fix" churn) are gone. All
        # that remains: on a real VT decode error, send one PLI and wait for the
        # IDR; keep the single decoder for the whole session.
        #
        # ``_keyframe_pending`` is the dedup gate -- True from when we send a PLI
        # until the requested IDR is fed (mirrors DeviceHub's "a more recent key
        # frame has already been assembled, skipping FIR"). ``_keyframe_sent_t``
        # backstops a lost PLI/IDR with a timed re-send. ``_idr_observed_at``
        # suppresses the drain noise of pre-IDR P-frames erroring against the
        # freshly reset reference set.
        self._keyframe_pending = False
        self._keyframe_sent_t: float = 0.0
        self._idr_observed_at: float = 0.0
        # Rebuild the VT session from the next IDR. Without a jitter buffer +
        # FEC (which DeviceHub has), pmd3's decoder can wedge on stale
        # references and stop emitting -- feeding a later IDR to the same
        # session does not always un-stick it, so we tear it down and rebuild
        # from a fresh IDR. This fires ONLY on the two legitimate triggers
        # (a genuine decode failure, or a new client that needs a clean start),
        # never on motion/timers/predicted-loss -- that speculative churn was
        # the tear source we removed.
        self._rebuild_pending = False

        # Audio state -- mirrors screen_stream.py's audio side.
        # Decoded PCM goes straight to the host's speakers via the
        # AudioQueuePlayer; nothing is broadcast over RFB (RFB has no
        # audio of its own). The audio session is paired with the
        # video session on the device by sharing client_session_id.
        self._audio_player: Optional[AudioQueuePlayer] = None
        self._audio_decoder: Optional[AACELDDecoder] = None
        self._audio_transport: Optional[UdpMediaTransport] = None
        self._audio_local_ssrc: int = 0
        self._audio_remote_ssrc: int = 0
        self._audio_rtcp_dest: Optional[tuple[str, int]] = None
        self._audio_rtp_packets_received: int = 0
        self._audio_rtp_highest_seq: int = 0
        self._audio_session_id: Optional[uuid.UUID] = None
        self._audio_svc: Optional[DisplayService] = None

        # HID for pointer-event translation (UniversalHIDService for the
        # touchscreen surface, IndigoHIDService for hardware buttons
        # like Home / Lock / Volume / Siri / Mute).
        self._uhs: Optional[UniversalHIDServiceService] = None
        self._indigo: Optional[IndigoHIDService] = None
        self._hid_lock = asyncio.Lock()
        # _ServiceID dtuhidd assigned to our host-registered virtual
        # keyboard. Lazily filled on first key event; serialized by
        # ``_hid_lock`` so a burst of keystrokes at startup doesn't race
        # multiple createService calls.
        self._kb_service_id: Optional[int] = None

    # ----- HEVC -> BGRA callback marshalling --------------------------------
    def _on_frame_from_worker(self, bgra: bytes) -> None:
        """Called from the VT transcoder worker thread."""
        loop = self._loop
        if loop is None:
            return
        loop.call_soon_threadsafe(self._broadcast_frame, bgra)

    def _on_decode_error_from_worker(self) -> None:
        """Worker-thread hook for VT decode failures / FrameDropped."""
        loop = self._loop
        if loop is None:
            return
        loop.call_soon_threadsafe(self._on_decode_error)

    def _on_decode_error(self) -> None:
        """Loop-thread handler for a genuine VT decode failure / FrameDropped.
        DeviceHub decision C: request a keyframe once, deduped, and wait for the
        IDR -- no decoder teardown, no re-arm storm. The post-IDR grace window
        skips the pre-IDR P-frames still draining VT's queue against the freshly
        reset reference set (that's expected noise, not a fresh failure)."""
        loop = self._loop
        if loop is None:
            return
        now = loop.time()
        if self._idr_observed_at > 0.0 and (now - self._idr_observed_at) < 0.5:
            return
        self._request_keyframe(now, reason="decode-error")

    def _broadcast_frame(self, bgra: bytes) -> None:
        self._latest_frame = bgra
        self._frames_emitted += 1
        if not self._ready.is_set() and self._transcoder is not None:
            self._fb_width = self._transcoder.width
            self._fb_height = self._transcoder.height
            self._ready.set()
        for c in self._clients:
            c.wants_update.set()

    # ----- RTP recv + transcoder feed ---------------------------------------
    async def _udp_recv_and_pipe(self, transport: UdpMediaTransport) -> None:
        """Same depacketize loop as ScreenStreamServer: gather Annex-B
        AUs and feed the VT transcoder."""
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
        rtp_packets = 0
        feed_count = 0
        au_dropped = 0
        seq_gaps = 0
        frame_count_at_last_log = 0
        last_stat_t = loop.time()
        # Debug: dump the exact Annex-B we hand VT to a file so the bitstream
        # can be re-decoded offline (ffmpeg / a second VT pass) and compared
        # against the live output. Set PMD3_SERVE_VNC_DUMP=/path.hevc.
        dump_path = os.environ.get("PMD3_SERVE_VNC_DUMP")
        dump_fh = open(dump_path, "wb") if dump_path else None
        if dump_fh is not None:
            logger.info("PMD3_SERVE_VNC_DUMP: writing fed Annex-B to %s", dump_path)
        while True:
            try:
                data = await transport.recv()
            except (OSError, asyncio.CancelledError):
                if dump_fh is not None:
                    with contextlib.suppress(Exception):
                        dump_fh.close()
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
            # Maintain the extended highest-seq for the RR keepalive.
            cur_ext = self._rtp_highest_seq
            cycles = (cur_ext >> 16) & 0xFFFF
            last_seq16 = cur_ext & 0xFFFF
            if seq < last_seq16 and (last_seq16 - seq) > 0x8000:
                cycles = (cycles + 1) & 0xFFFF
            new_ext = (cycles << 16) | seq
            if cur_ext == 0 or ((new_ext - cur_ext) & 0xFFFFFFFF) < 0x80000000:
                self._rtp_highest_seq = new_ext
            if last_seq is not None and seq != ((last_seq + 1) & 0xFFFF):
                fu_buffer.clear()
                au_corrupt = True
                seq_gaps += 1
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
                    au_is_key = True
                current_au.append(nal)

            if marker:
                if current_au and not au_corrupt:
                    # Rebuild from a fresh IDR when one was requested (genuine
                    # decode failure or new client). The wedged session is torn
                    # down here; the bootstrap branch below builds a clean one
                    # from this very IDR. This is NOT the old motion/heartbeat
                    # churn -- it only fires on a real trigger, so a clean stream
                    # keeps its single decoder for the whole session.
                    if self._rebuild_pending and au_is_key and self._transcoder is not None:
                        with contextlib.suppress(Exception):
                            self._transcoder.close()
                        self._transcoder = None
                        self._rebuild_pending = False
                        self._idr_observed_at = loop.time()
                        logger.debug("decoder rebuilt on requested IDR")
                    # Bootstrap the transcoder from an IDR (it needs VPS/SPS/PPS).
                    if (
                        self._transcoder is None
                        and au_is_key
                        and cached_vps is not None
                        and cached_sps is not None
                        and cached_pps is not None
                    ):
                        try:
                            self._transcoder = self._transcoder_cls(
                                cached_vps,
                                cached_sps,
                                cached_pps,
                                on_frame=self._on_frame_from_worker,
                                on_decode_error=self._on_decode_error_from_worker,
                            )
                            logger.info(
                                "VT transcoder started: HEVC %dx%d -> BGRA",
                                self._transcoder.width,
                                self._transcoder.height,
                            )
                        except Exception:
                            logger.exception("VT transcoder failed to start")
                    if self._transcoder is not None:
                        # Feed EVERY assembled AU -- never skip a decode
                        # (decision B). A frame that references a lost/late
                        # reference is decoded-with-concealment by VT; only if
                        # that concealment is genuinely bad does VT flag
                        # FrameDropped -> _on_decode_error requests a keyframe.
                        # We do NOT pre-predict reference loss and drop the
                        # frame -- that was the old churn that caused the tear.
                        annexb = b"".join(b"\x00\x00\x00\x01" + nal for nal in current_au)
                        if dump_fh is not None:
                            dump_fh.write(annexb)
                            dump_fh.flush()
                        self._transcoder.feed(annexb)
                        feed_count += 1
                        if au_is_key:
                            # The requested keyframe arrived: clear the dedup
                            # gate and open the post-IDR grace window so the
                            # pre-IDR P-frames draining VT's queue don't
                            # re-trigger a keyframe request.
                            self._idr_observed_at = loop.time()
                            self._keyframe_pending = False
                elif current_au and au_corrupt:
                    # Whole AU discarded because a sequence gap (loss OR an
                    # intra-frame reorder) landed inside it. This orphans the
                    # references of following P-frames -> VT silently conceals
                    # -> smear, with no decode error surfaced. Counting these
                    # tells us whether the smear is drop-driven (needs a
                    # reorder/jitter buffer, decision A) or a valid stream VT
                    # mis-decodes.
                    au_dropped += 1
                current_au = []
                au_is_key = False
                au_corrupt = False

            rtp_packets += 1
            now = loop.time()
            if now - last_stat_t >= 2.0:
                frames_now = self._frames_emitted
                logger.debug(
                    "ingress stats: rtp=%d feeds=%d frames=%d au_dropped=%d seq_gaps=%d (Δframes=%d / %.1fs)",
                    rtp_packets,
                    feed_count,
                    frames_now,
                    au_dropped,
                    seq_gaps,
                    frames_now - frame_count_at_last_log,
                    now - last_stat_t,
                )
                rtp_packets = 0
                feed_count = 0
                au_dropped = 0
                seq_gaps = 0
                frame_count_at_last_log = frames_now
                last_stat_t = now

    # ----- RTCP PLI + decoder refresh ---------------------------------------
    def _build_rtcp_pli(self) -> bytes:
        """RTCP Picture Loss Indication (RFC 4585 §6.3.1). 12 bytes.

        Asks the device's encoder to emit a fresh IDR. The PLI is what
        gets us out from under stale long-term-reference state -- we
        send it, the device sends a new IDR, we rebuild the decoder
        from that IDR."""
        return struct.pack(
            "!BBHII",
            0x81,  # V=2, P=0, FMT=1
            0xCE,  # PT=206 (PSFB)
            2,  # length = 2 (3 words after this header)
            self._local_ssrc & 0xFFFFFFFF,
            self._remote_ssrc & 0xFFFFFFFF,
        )

    async def _send_rtcp_pli(self) -> None:
        transport = self._active_transport
        if transport is None or self._rtcp_dest is None:
            return
        if not (self._local_ssrc and self._remote_ssrc):
            return
        try:
            await transport.sendto(self._build_rtcp_pli(), *self._rtcp_dest)
            logger.debug("sent RTCP PLI (requested fresh keyframe)")
        except OSError as exc:
            logger.debug("PLI send failed (%s)", exc)

    def _build_rtcp_rr(self) -> bytes:
        """RTCP Receiver Report (RFC 3550 §6.4.2) + SDES, byte-compatible with
        screen_stream.py. The device's video streamConfig has RTCPTimeoutEnabled
        with a ~25 s interval; PLIs alone don't reset it -- without periodic RRs
        the device reaps the video session and stops emitting AUs, which froze
        serve-vnc permanently (it has no stream-restart). One RR/s keeps it alive.
        """
        rr = struct.pack(
            "!BBHII BBBB IIII",
            0x81,  # V=2, RC=1
            0xC9,  # PT=201 (RR)
            7,
            self._local_ssrc & 0xFFFFFFFF,
            self._remote_ssrc & 0xFFFFFFFF,
            0,  # fraction lost
            0,
            0,
            0,  # 3-byte cumulative loss
            self._rtp_highest_seq & 0xFFFFFFFF,
            0,  # interarrival jitter
            0,  # last SR
            0,  # delay since last SR
        )
        return rr + self._build_rtcp_sdes(self._local_ssrc)

    @staticmethod
    def _build_rtcp_sdes(ssrc: int) -> bytes:
        """Minimal SDES with an empty CNAME (matches Xcode's compound RR+SDES)."""
        return struct.pack("!BBHI BBBB", 0x81, 0xCA, 2, ssrc & 0xFFFFFFFF, 0x01, 0x00, 0x00, 0x00)

    async def _rtcp_send_loop(self, transport: UdpMediaTransport) -> None:
        """Send a video RR every second to keep the device's video session
        alive (see _build_rtcp_rr). Not gated on packets-received: send from the
        start so a brief no-frame window at bring-up can't let the session lapse."""
        while True:
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return
            if self._rtcp_dest is None or not (self._local_ssrc and self._remote_ssrc):
                continue
            try:
                await transport.sendto(self._build_rtcp_rr(), *self._rtcp_dest)
            except OSError as exc:
                logger.debug("video RTCP RR send failed (%s); socket may be torn down", exc)
                return

    def _request_keyframe(self, now: float, *, reason: str) -> None:
        """Send one RTCP PLI to ask the encoder for a fresh IDR, deduped against
        an already-outstanding request (DeviceHub decision C, doc §8). No
        decoder teardown -- we keep decoding and let the IDR reset VT's
        references when it lands. The dedup gate clears when that IDR is fed
        (recv loop) or the timeout backstop re-opens it."""
        if self._rtcp_dest is None or not (self._local_ssrc and self._remote_ssrc):
            return
        if self._keyframe_pending:
            return  # already asked; wait for the IDR (mirrors "skipping FIR")
        self._keyframe_pending = True
        # Rebuild the decoder from the IDR we're about to request -- the current
        # session may be wedged on stale references (see _rebuild_pending).
        self._rebuild_pending = True
        self._keyframe_sent_t = now
        pli_task = asyncio.create_task(self._send_rtcp_pli())
        self._pli_tasks.add(pli_task)
        pli_task.add_done_callback(self._pli_tasks.discard)
        logger.debug("keyframe requested (%s): %d client(s)", reason, len(self._clients))

    async def _keyframe_timeout_loop(self) -> None:
        """Backstop a lost PLI or lost IDR. If a keyframe request has been
        outstanding too long with no IDR fed, re-open the gate and ask again.

        This is NOT the old motion/heartbeat/settle rebuild churn -- with no
        request outstanding it does nothing, matching DeviceHub's FIR=0 steady
        state (it never requests a keyframe absent a real decode failure)."""
        loop = asyncio.get_running_loop()
        resend_after = 2.0
        while True:
            try:
                await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                return
            if not self._keyframe_pending:
                continue
            now = loop.time()
            if (now - self._keyframe_sent_t) >= resend_after:
                # Previous PLI or its IDR was lost -- re-open the gate and retry.
                self._keyframe_pending = False
                self._request_keyframe(now, reason="timeout-resend")

    # ----- Audio: AAC-ELD recv + decode + play ------------------------------
    async def _audio_udp_recv(self, transport: UdpMediaTransport) -> None:
        """Receive RTP audio packets, strip the RTP header, decode the
        AAC-ELD AU via AudioToolbox, and feed the PCM to the local
        AudioQueue. Mirrors :meth:`screen_stream.ScreenStreamServer._audio_udp_recv`
        but plays locally instead of broadcasting."""
        loop = asyncio.get_running_loop()
        consecutive_errors = 0
        _ERR_RECREATE_THRESHOLD = 5
        pkt_count = 0
        last_stat_t = loop.time()
        while True:
            try:
                data = await transport.recv()
            except (OSError, asyncio.CancelledError):
                return
            if len(data) < 12:
                continue
            pt = data[1] & 0x7F
            if 64 <= pt <= 95:  # RTCP -- ignore
                continue
            # Track sequence + receive count so our RR reports a sensible
            # extended-highest-seq field. Without this the device reaps
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
            decoder = self._audio_decoder
            player = self._audio_player
            if decoder is None or player is None:
                continue
            try:
                pcm = decoder.decode(payload)
                consecutive_errors = 0
            except Exception as exc:
                consecutive_errors += 1
                logger.debug("audio decode failed (%s) -- dropping", exc)
                if consecutive_errors >= _ERR_RECREATE_THRESHOLD:
                    logger.warning(
                        "audio decoder stuck after %d consecutive errors -- recreating",
                        consecutive_errors,
                    )
                    try:
                        self._audio_decoder = AACELDDecoder()
                        consecutive_errors = 0
                    except Exception:
                        logger.exception("audio decoder recreation failed")
                continue
            if pcm:
                player.play(pcm)
            pkt_count += 1
            now = loop.time()
            if now - last_stat_t >= 5.0:
                played, dropped, enq_err = player.stats()
                logger.debug(
                    "audio stats: rtp=%d, played=%d, dropped=%d, enq_err=%d",
                    pkt_count,
                    played,
                    dropped,
                    enq_err,
                )
                pkt_count = 0
                last_stat_t = now

    def _build_audio_rtcp_rr(self) -> bytes:
        """Audio-side counterpart of :meth:`_build_rtcp_pli` -- a minimal
        Receiver Report. The device's audio session has
        ``RTCPTimeoutInterval=20 s``; without these RRs the encoder
        stops emitting silently after ~20 s."""
        return struct.pack(
            "!BBHII BBBB IIII",
            0x81,  # V=2, P=0, RC=1
            0xC9,  # PT=201 (RR)
            7,
            self._audio_local_ssrc & 0xFFFFFFFF,
            self._audio_remote_ssrc & 0xFFFFFFFF,
            0,
            0,
            0,
            0,  # fraction lost / cumulative loss
            self._audio_rtp_highest_seq & 0xFFFFFFFF,
            0,
            0,
            0,  # jitter / lsr / dlsr
        )

    async def _audio_rtcp_send_loop(self, transport: UdpMediaTransport) -> None:
        sent = 0
        while True:
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return
            if self._audio_rtcp_dest is None or self._audio_rtp_packets_received == 0:
                continue
            try:
                await transport.sendto(self._build_audio_rtcp_rr(), *self._audio_rtcp_dest)
                sent += 1
                # One log line per 30 RRs (every 30 s) confirms the
                # session keepalive is firing -- useful when triaging
                # "audio stopped after a while" reports.
                if sent % 30 == 0:
                    logger.debug("audio RTCP RR: %d sent (highest_seq=0x%08x)", sent, self._audio_rtp_highest_seq)
            except OSError as exc:
                logger.debug("audio RTCP send failed (%s); socket may be torn down", exc)
                return

    # ----- HID --------------------------------------------------------------
    async def _ensure_hid(self) -> None:
        async with self._hid_lock:
            if self._uhs is None:
                uhs = UniversalHIDServiceService(self._rsd)
                await uhs.connect()
                self._uhs = uhs

    async def _ensure_indigo(self) -> None:
        async with self._hid_lock:
            if self._indigo is None:
                ihs = IndigoHIDService(self._rsd)
                await ihs.connect()
                self._indigo = ihs

    async def _stop_hid(self) -> None:
        if self._uhs is not None:
            with contextlib.suppress(Exception):
                await self._uhs.close()
            self._uhs = None
        if self._indigo is not None:
            with contextlib.suppress(Exception):
                await self._indigo.close()
            self._indigo = None

    async def _ensure_keyboard(self) -> None:
        await self._ensure_hid()
        if self._kb_service_id is None:
            async with self._hid_lock:
                if self._kb_service_id is None:
                    assert self._uhs is not None
                    self._kb_service_id = await self._uhs.create_keyboard_service()

    async def _send_hid_button(self, page: int, code: int, *, down: bool) -> None:
        state = HID_BUTTON_STATE_DOWN if down else HID_BUTTON_STATE_UP
        try:
            await self._ensure_indigo()
            assert self._indigo is not None
            await self._indigo.send_button(page, code, state)
        except Exception:
            logger.exception("HID button send failed (page=0x%02X code=0x%02X)", page, code)

    async def _handle_pointer(self, client: _VncClient, button_mask: int, x: int, y: int) -> None:
        """Translate an RFB PointerEvent into HID activity.

        Left button (bit 0)  -> touchscreen contact at (x, y).
        Right button (bit 2) -> iOS Home button.
        Middle button (bit 1) -> iOS Lock/Power button.

        Touch coords are rescaled from framebuffer pixels to the
        device's uint16 normalised range (0..65535)."""
        if self._fb_width <= 0 or self._fb_height <= 0:
            return

        # Diff non-left buttons for press/release edge detection.
        changed = button_mask ^ client.last_button_mask
        for bit, (page, code) in _MOUSE_BUTTON_TO_HID.items():
            mask = 1 << bit
            if changed & mask:
                await self._send_hid_button(page, code, down=bool(button_mask & mask))
        client.last_button_mask = button_mask

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

    async def _handle_key(self, client: _VncClient, down: bool, keysym: int) -> None:
        """Translate an RFB KeyEvent into HID activity.

        Three paths:

        - Ctrl+<key> combos in ``_CTRL_COMBO_TO_HID`` fire an Indigo hardware
          button (Home / Lock / Vol / Mute / Siri).
        - Modifier keysyms (Shift/Ctrl/Alt/GUI) toggle the matching HID
          modifier usages in the virtual-keyboard bitmap, and also update
          the legacy ``mod_*`` flags that the Ctrl-combo path consults.
        - Anything else -- printable ASCII via :data:`ASCII_TO_HID`, or
          named keys via ``_KEYSYM_TO_HID_SPECIAL`` -- toggles its usage in
          the virtual-keyboard bitmap and re-emits the full report.

        Key-up always releases the same usages the matching key-down
        emitted, even if the host's interpretation of the keysym drifted
        in between (e.g. Shift released before the letter).
        """
        # Track the legacy modifier-bool state so the Ctrl-combo path
        # below keeps working alongside the keyboard path.
        if keysym in _KEYSYM_CTRL:
            client.mod_ctrl = down
        elif keysym in _KEYSYM_SHIFT:
            client.mod_shift = down
        elif keysym in _KEYSYM_ALT:
            client.mod_alt = down
        elif keysym in _KEYSYM_CMD:
            client.mod_cmd = down

        # Ctrl-prefixed hardware-button hotkeys. Eat the event so the
        # letter doesn't also get typed on the device.
        if down and client.mod_ctrl and keysym in _CTRL_COMBO_TO_HID:
            mapping = _CTRL_COMBO_TO_HID[keysym]
            client.active_combos[keysym] = mapping
            await self._send_hid_button(mapping[0], mapping[1], down=True)
            return
        if not down and keysym in client.active_combos:
            active = client.active_combos.pop(keysym)
            await self._send_hid_button(active[0], active[1], down=False)
            return

        # Resolve the keysym to one or more HID usages.
        usages: tuple[int, ...] = ()
        if keysym in _KEYSYM_TO_HID_MODIFIER:
            usages = (_KEYSYM_TO_HID_MODIFIER[keysym],)
        elif keysym in _KEYSYM_TO_HID_SPECIAL:
            usages = (_KEYSYM_TO_HID_SPECIAL[keysym],)
        elif 0x20 <= keysym <= 0x7E:
            mapping = ASCII_TO_HID.get(chr(keysym))
            if mapping is not None:
                usage, needs_shift = mapping
                # Shifted character on key-down: synthesise Shift in the
                # bitmap if no client-tracked Shift is already held.
                if needs_shift and not (
                    KEY_LEFT_SHIFT in client.pressed_keys or KEY_RIGHT_SHIFT in client.pressed_keys
                ):
                    usages = (KEY_LEFT_SHIFT, usage)
                else:
                    usages = (usage,)
        if not usages:
            return

        if down:
            client.active_typing[keysym] = usages
            client.pressed_keys.update(usages)
        else:
            for u in client.active_typing.pop(keysym, usages):
                client.pressed_keys.discard(u)
        try:
            await self._ensure_keyboard()
            assert self._uhs is not None and self._kb_service_id is not None
            await self._uhs.send_keyboard(self._kb_service_id, client.pressed_keys)
        except Exception:
            logger.exception("HID keyboard send failed (keysym=0x%04X down=%s)", keysym, down)

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
            # Ask the encoder for a fresh IDR so this client starts from a clean
            # keyframe (a new receiver legitimately needs one -- like DeviceHub
            # getting the initial keyframe at stream start). This is a single
            # deduped PLI, not a decoder rebuild.
            if self._transcoder is not None and self._rtcp_dest is not None:
                loop = self._loop
                if loop is not None:
                    self._request_keyframe(loop.time(), reason="client-connect")
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
        logger.debug("handshake: sent server version RFB 003.008")
        client_version_bytes = await r.readexactly(12)
        client_version = client_version_bytes.decode("ascii", errors="replace").rstrip()
        logger.debug("handshake: client version %r", client_version)
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
            logger.debug("handshake: 3.3 path -- server picked VNC Auth")
        else:
            # RFB 3.7 / 3.8: send security list, client picks. Offer
            # only VNC Auth so we always end up in the same code path.
            w.write(b"\x01\x02")
            await w.drain()
            logger.debug("handshake: sent security types [VNC Auth=2]")
            chosen = (await r.readexactly(1))[0]
            logger.debug("handshake: client picked security=%d", chosen)
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
        logger.debug("handshake: VNC Auth accepted (any password)")
        # 3.x always sends SecurityResult AFTER VNC Auth, regardless of
        # whether None auth would have skipped it.
        w.write(b"\x00\x00\x00\x00")
        await w.drain()
        logger.debug("handshake: sent SecurityResult=OK")
        # ClientInit (shared flag — we don't care).
        shared = (await r.readexactly(1))[0]
        logger.debug("handshake: client shared=%d", shared)
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
        logger.debug("handshake: sent ServerInit (%dx%d, name=%r)", self._fb_width, self._fb_height, _SERVER_NAME)

    async def _client_recv_loop(self, client: _VncClient) -> None:
        r = client.reader
        while True:
            msg_type_b = await r.readexactly(1)
            msg_type = msg_type_b[0]
            if msg_type == 0:
                # SetPixelFormat: padding(3) + pixel-format(16). We
                # always send pixels in the format ServerInit advertised
                # (32-bit BGRX); we don't honor the client's preferred
                # format. Log it so we can see whether mac Screen
                # Sharing tried to switch us to something else.
                await r.readexactly(3)
                pf = await r.readexactly(16)
                bpp, depth, big, true_c, rmax, gmax, bmax, rshift, gshift, bshift = struct.unpack(
                    ">BBBB HHH BBB", pf[:13]
                )
                logger.debug(
                    "SetPixelFormat ignored: bpp=%d depth=%d big=%d true_c=%d max=(%d,%d,%d) shift=(%d,%d,%d)",
                    bpp,
                    depth,
                    big,
                    true_c,
                    rmax,
                    gmax,
                    bmax,
                    rshift,
                    gshift,
                    bshift,
                )
            elif msg_type == 2:
                # SetEncodings: padding(1) + n(2) + n * int32
                await r.readexactly(1)
                n = struct.unpack(">H", await r.readexactly(2))[0]
                raw = await r.readexactly(4 * n)
                client.encodings = list(struct.unpack(f">{n}i", raw))
                logger.debug(
                    "VNC client encodings: %s",
                    [
                        {
                            _ENC_RAW: "Raw",
                            _ENC_COPY_RECT: "CopyRect",
                            _ENC_CURSOR: "Cursor",
                            _ENC_DESKTOP_SIZE: "DesktopSize",
                            _ENC_LAST_RECT: "LastRect",
                        }.get(e, str(e))
                        for e in client.encodings
                    ],
                )
            elif msg_type == 3:
                # FramebufferUpdateRequest: incremental(1) + x(2) + y(2) + w(2) + h(2)
                payload = await r.readexactly(9)
                inc, fx, fy, fw, fh = struct.unpack(">BHHHH", payload)
                logger.debug(
                    "FramebufferUpdateRequest incremental=%d (%d,%d) %dx%d",
                    inc,
                    fx,
                    fy,
                    fw,
                    fh,
                )
                client.wants_update.set()
            elif msg_type == 4:
                # KeyEvent: down-flag(1) + padding(2) + key(4)  (X11 keysym).
                payload = await r.readexactly(7)
                down_flag, keysym = struct.unpack(">B2xI", payload)
                await self._handle_key(client, bool(down_flag), keysym)
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
        loop = asyncio.get_running_loop()
        expected = self._fb_width * self._fb_height * 4
        # Each framebuffer is width*height*4 (~14 MB at 1264x2752). Writing that
        # through the asyncio StreamWriter runs the copy+flush ON the event loop,
        # and at motion frame rates it starves ``sock_recv`` of the RTP socket
        # -> the kernel drops incoming media packets -> broken references
        # (mosaic) + collapsed fps the moment a client attaches during motion.
        # Send instead on a BLOCKING-style loop over a dup of the client socket
        # from a thread-pool executor: ``send``/``select`` release the GIL, so
        # the event loop keeps draining RTP while the frame goes out. dup()
        # shares the file description (and O_NONBLOCK) with asyncio's socket, so
        # we must NOT setblocking() -- we select() on the non-blocking fd. The
        # asyncio side only reads (the recv loop); nothing else writes here, so
        # a second send-direction fd is safe (TCP is full-duplex).
        base_sock = client.writer.get_extra_info("socket")
        if base_sock is None:
            return
        send_sock = socket.socket(fileno=os.dup(base_sock.fileno()))

        def _blocking_send(hdr: bytes, frm: bytes) -> None:
            for chunk in (hdr, frm):
                mv = memoryview(chunk)
                total = 0
                n = len(chunk)
                while total < n:
                    try:
                        total += send_sock.send(mv[total:])
                    except BlockingIOError:
                        select.select([], [send_sock], [], 2.0)

        rect_header = struct.pack(">HHHHi", 0, 0, self._fb_width, self._fb_height, _ENC_RAW)
        header = b"\x00\x00" + struct.pack(">H", 1) + rect_header
        try:
            while True:
                await client.wants_update.wait()
                client.wants_update.clear()
                frame = self._latest_frame
                if frame is None or frame is client.last_sent_frame:
                    continue
                if len(frame) != expected:
                    # SPS-locked dimensions shouldn't change mid-session, but if
                    # VT ever hands us a differently sized buffer we skip rather
                    # than desync the TCP stream.
                    logger.warning(
                        "frame size mismatch: got %d bytes, fb expects %d (%dx%d * 4) -- dropping",
                        len(frame),
                        expected,
                        self._fb_width,
                        self._fb_height,
                    )
                    continue
                client.last_sent_frame = frame
                try:
                    await loop.run_in_executor(None, _blocking_send, header, frame)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    return
        finally:
            with contextlib.suppress(OSError):
                send_sock.close()

    # ----- top-level orchestration ------------------------------------------
    async def serve(self) -> None:
        # 1) Start device-side video stream + open the RTP receiver on the right transport:
        # the pytcp stack over the userspace tunnel (a host kernel socket is unreachable from
        # the device), a host kernel socket otherwise. Generate a single client_session_id up
        # front so the audio stream (started below) gets paired with the video session on the
        # device -- this is what Xcode's Mirror does.
        shared_session_id = uuid.uuid4()
        svc = DisplayService(self._rsd)
        await svc.connect()
        transport, receiver_ip = open_media_receiver(svc, (8 * 1024 * 1024, 4 * 1024 * 1024))
        answer = await svc.start_video_stream(
            receiver_ip=receiver_ip,
            receiver_port=transport.port,
            sender_ip=self._sender_ip,
            display_id=self._display_id,
            client_session_id=shared_session_id,
            allow_rtcp_fb=self._allow_rtcp_fb,
            ltrp_enabled=self._ltrp_enabled,
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

        # RTCP feedback setup: ``LocalSSRC``/``RemoteSSRC`` in
        # streamConfig are from the device's perspective, so OURS is
        # ``RemoteSSRC`` and THEIRS is ``LocalSSRC`` (yes, really).
        # Without all three of (source_port, local_ssrc, remote_ssrc)
        # we can't send PLI and the decoder-refresh loop will skip.
        source_port = int(cfg.get("SourcePort", 0))
        self._local_ssrc = int(cfg.get("RemoteSSRC", 0))
        self._remote_ssrc = int(cfg.get("LocalSSRC", 0))
        self._rtcp_dest = (self._sender_ip, source_port) if source_port else None
        self._active_transport = transport
        if self._rtcp_dest and self._local_ssrc and self._remote_ssrc:
            logger.info(
                "RTCP feedback enabled: dest=%s, ours=%d, theirs=%d",
                self._rtcp_dest,
                self._local_ssrc,
                self._remote_ssrc,
            )
        else:
            logger.warning(
                "RTCP feedback disabled (missing fields: SourcePort=%s LocalSSRC=%s RemoteSSRC=%s)"
                " -- keyframe recovery will be a no-op; a genuine decode failure cannot be recovered",
                source_port,
                self._local_ssrc,
                self._remote_ssrc,
            )

        # 3) Audio stream (optional). RFB has no audio; we play the
        # decoded PCM through the host's speakers via AudioQueue. The
        # device's audio session shares ``client_session_id`` with the
        # video session so they're paired on the device-side media
        # manager (same as Xcode's Mirror). Without RR keepalives the
        # device reaps the audio session after ~20 s.
        audio_recv_task: Optional[asyncio.Task] = None
        audio_rtcp_task: Optional[asyncio.Task] = None
        if self._audio_enabled:
            try:
                audio_svc = DisplayService(self._rsd)
                await audio_svc.connect()
                audio_transport, audio_receiver_ip = open_media_receiver(audio_svc, (4 * 1024 * 1024, 1 * 1024 * 1024))
                audio_answer = await audio_svc.start_audio_stream(
                    receiver_ip=audio_receiver_ip,
                    receiver_port=audio_transport.port,
                    sender_ip=self._sender_ip,
                    client_session_id=shared_session_id,
                )
                audio_sid_raw = audio_answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
                audio_sid = audio_sid_raw if isinstance(audio_sid_raw, uuid.UUID) else uuid.UUID(audio_sid_raw)
                audio_cfg = audio_answer["connection"].get("streamConfig", {})
                a_source_port = int(audio_cfg.get("SourcePort", 0))
                self._audio_local_ssrc = int(audio_cfg.get("RemoteSSRC", 0))
                self._audio_remote_ssrc = int(audio_cfg.get("LocalSSRC", 0))
                self._audio_rtcp_dest = (self._sender_ip, a_source_port) if a_source_port else None
                self._audio_transport = audio_transport
                self._audio_svc = audio_svc
                self._audio_session_id = audio_sid
                self._audio_decoder = AACELDDecoder()
                self._audio_player = AudioQueuePlayer()
                logger.info(
                    "audio stream up: PT=%s mode=%s sender_port=%s",
                    audio_cfg.get("RxPayloadType"),
                    audio_cfg.get("AudioStreamMode"),
                    a_source_port,
                )
            except Exception:
                logger.exception("audio startup failed -- continuing without audio")
                self._audio_enabled = False
                # Tear down anything we managed to create before the error.
                if self._audio_player is not None:
                    with contextlib.suppress(Exception):
                        self._audio_player.close()
                    self._audio_player = None
                self._audio_decoder = None
                self._audio_transport = None
                self._audio_svc = None
                self._audio_session_id = None

        # 4) Background tasks.
        loop = asyncio.get_running_loop()
        self._loop = loop
        feed_task = asyncio.create_task(self._udp_recv_and_pipe(transport))
        keyframe_task = asyncio.create_task(self._keyframe_timeout_loop())
        # Video RR keepalive -- without this the device reaps the video session
        # after ~25 s (RTCPTimeoutEnabled) and serve-vnc freezes with no recovery.
        rtcp_task = asyncio.create_task(self._rtcp_send_loop(transport))
        if self._audio_enabled and self._audio_transport is not None:
            audio_recv_task = asyncio.create_task(self._audio_udp_recv(self._audio_transport))
            if self._audio_rtcp_dest and self._audio_local_ssrc and self._audio_remote_ssrc:
                audio_rtcp_task = asyncio.create_task(self._audio_rtcp_send_loop(self._audio_transport))
            else:
                logger.warning(
                    "audio RTCP disabled (missing fields in streamConfig) -- session will be reaped after ~20 s"
                )

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
            logger.debug("shutdown: closing TCP listener")
            server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), timeout=2.0)
            logger.debug("shutdown: stopping HID")
            await self._stop_hid()
            logger.debug("shutdown: stopping keyframe-timeout loop")
            keyframe_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await keyframe_task
            rtcp_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await rtcp_task
            logger.debug("shutdown: stopping VT transcoder")
            feed_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await feed_task
            if self._pli_tasks:
                with contextlib.suppress(Exception):
                    await asyncio.wait(list(self._pli_tasks), timeout=1.0)
            if self._transcoder is not None:
                with contextlib.suppress(Exception):
                    self._transcoder.close()
                self._transcoder = None
            with contextlib.suppress(Exception):
                transport.close()
            if audio_recv_task is not None:
                logger.debug("shutdown: stopping audio recv loop")
                audio_recv_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await audio_recv_task
            if audio_rtcp_task is not None:
                logger.debug("shutdown: stopping audio RTCP loop")
                audio_rtcp_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await audio_rtcp_task
            if self._audio_player is not None:
                logger.debug("shutdown: stopping AudioQueue player")
                with contextlib.suppress(Exception):
                    self._audio_player.close()
                self._audio_player = None
            if self._audio_svc is not None and self._audio_session_id is not None:
                logger.debug("shutdown: stopping audio stream")
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(self._audio_svc.stop_media_stream(self._audio_session_id), timeout=3.0)
                with contextlib.suppress(Exception):
                    await self._audio_svc.close()
            if self._audio_transport is not None:
                with contextlib.suppress(Exception):
                    self._audio_transport.close()
            logger.debug("shutdown: stopping device stream")
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
