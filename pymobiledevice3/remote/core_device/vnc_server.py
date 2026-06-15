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
import socket
import struct
import sys
import uuid
from collections import deque
from typing import Optional

from pymobiledevice3.remote.core_device.aac_eld import AACELDDecoder
from pymobiledevice3.remote.core_device.audio_player import AudioQueuePlayer
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.hevc_rps import HevcRpsTracker, is_slice_nal
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
from pymobiledevice3.remote.core_device.screen_stream import depacketize_hevc
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
        bind: str = "127.0.0.1",
        port: int = 5901,
        display_id: int = 1,
        audio: bool = False,
        decoder: str = "auto",
        allow_rtcp_fb: bool = False,
        ltrp_enabled: bool = True,
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
        self._active_sock: Optional[socket.socket] = None
        self._local_ssrc: int = 0
        self._remote_ssrc: int = 0
        self._rtcp_dest: Optional[tuple[str, int]] = None
        self._pli_tasks: set[asyncio.Task] = set()

        # Motion-based decoder-rebuild state. Mirrors screen_stream.py's
        # _decoder_refresh_loop: the VT decoder accumulates stale
        # long-term-reference-picture state under motion and renders
        # torn frames without erroring. Recovery is to send PLI + tear
        # the decoder down + rebuild from the next IDR -- the exact
        # thing a manual page reload does for the browser path.
        self._au_byte_window: deque[tuple[float, int]] = deque()
        self._motion_active = False
        self._motion_ended_t: float = 0.0
        self._last_refresh_t: float = 0.0
        # When True, the next IDR triggers a transcoder rebuild. We
        # stop feeding deltas to the existing transcoder so we don't
        # accumulate MORE stale state while waiting for the IDR.
        self._refresh_pending = False

        # Decoder-error sticky keyframe-required state (ported from
        # iSharScreen's FrameQualityGate -- the libwebrtc two-condition
        # pattern). Motion-based refresh handles the "torn frame, no
        # error reported" case; this handles the converse "VT reported
        # a decode failure, recover before the stream silently freezes."
        # Cleared only when BOTH a fresh IDR was fed AND a clean frame
        # decoded post-IDR -- guards against the silent-freeze failure
        # where the IDR response to our PLI is itself lost or arrives
        # corrupted, leaving the decoder stuck on stale references.
        self._keyframe_required = False
        self._idr_observed = False
        # Pre-decode reference-picture-set tracker. Parses incoming
        # slice headers and reports when a P-slice references a POC
        # we never saw -- the decoder will silently conceal that
        # frame (the visible tear). Firing PLI on this signal is
        # one full frame ahead of waiting for VT to surface a
        # decode error, and catches the silent-conceal case where
        # VT never errors at all.
        self._rps_tracker = HevcRpsTracker()
        # Suppress decode errors for this long after we feed an IDR --
        # the VT queue may still hold pre-IDR P-frames that error
        # against the freshly reset reference set, which is expected
        # drain noise, not a real recovery failure.
        self._idr_observed_at: float = 0.0
        self._fir_attempts: int = 0
        self._cap_warned: bool = False

        # Audio state -- mirrors screen_stream.py's audio side.
        # Decoded PCM goes straight to the host's speakers via the
        # AudioQueuePlayer; nothing is broadcast over RFB (RFB has no
        # audio of its own). The audio session is paired with the
        # video session on the device by sharing client_session_id.
        self._audio_player: Optional[AudioQueuePlayer] = None
        self._audio_decoder: Optional[AACELDDecoder] = None
        self._audio_sock: Optional[socket.socket] = None
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
        """Loop-thread handler. Promotes a decode error into the sticky
        keyframe-required state and arms a refresh, subject to the
        post-IDR grace window and the existing ``_refresh_pending``
        gate (don't double-arm an in-flight recovery)."""
        loop = self._loop
        if loop is None:
            return
        now = loop.time()
        # Post-IDR grace: errors right after we fed an IDR are almost
        # always queued pre-IDR P-frames decoding against the freshly
        # reset reference set. Suppress them so they don't trigger
        # back-to-back PLI storms. 500 ms covers the typical drain.
        if self._idr_observed_at > 0.0 and (now - self._idr_observed_at) < 0.5:
            return
        if self._refresh_pending:
            return  # already armed; let the IDR land first
        if self._keyframe_required:
            # Already in recovery -- the periodic re-arm in
            # _decoder_refresh_loop handles further PLI attempts.
            return
        self._keyframe_required = True
        self._idr_observed = False
        self._fire_decoder_refresh(now, reason="decode-error")

    def _broadcast_frame(self, bgra: bytes) -> None:
        self._latest_frame = bgra
        self._frames_emitted += 1
        if not self._ready.is_set() and self._transcoder is not None:
            self._fb_width = self._transcoder.width
            self._fb_height = self._transcoder.height
            self._ready.set()
        # Sticky-keyframe two-condition clear: a clean decoded frame
        # only counts as "recovered" if we already saw the IDR fed
        # for this recovery cycle. Without `_idr_observed` we'd
        # false-clear on a pre-IDR P-frame that happened to decode
        # without an API error.
        if self._keyframe_required and self._idr_observed:
            self._keyframe_required = False
            self._idr_observed = False
            self._fir_attempts = 0
            self._cap_warned = False
            logger.debug("decode recovered (IDR + clean frame)")
        for c in self._clients:
            c.wants_update.set()

    # ----- RTP recv + transcoder feed ---------------------------------------
    async def _udp_recv_and_pipe(self, sock: socket.socket) -> None:
        """Same depacketize loop as ScreenStreamServer: gather Annex-B
        AUs and feed the VT transcoder."""
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
        rtp_packets = 0
        feed_count = 0
        frame_count_at_last_log = 0
        last_stat_t = loop.time()
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
                    self._rps_tracker.feed_sps(cached_sps)
                elif nt == _HEVC_NAL_PPS:
                    cached_pps = bytes(nal)
                elif _is_key_nal(nt):
                    au_is_key = True
                current_au.append(nal)

            if marker:
                if current_au and not au_corrupt:
                    # Motion signal: track AU sizes in a 1 s window so
                    # the refresh loop can detect motion start/end.
                    au_bytes = sum(len(n) for n in current_au)
                    self._au_byte_window.append((loop.time(), au_bytes))
                    # Decoder rebuild on a fresh IDR -- the previous
                    # transcoder's LTRP table is suspected stale, so we
                    # close it and let the bootstrap branch below build
                    # a fresh one from this very IDR.
                    if self._refresh_pending and au_is_key and self._transcoder is not None:
                        with contextlib.suppress(Exception):
                            self._transcoder.close()
                        self._transcoder = None
                        self._refresh_pending = False
                        # Drop the RPS DPB shadow with the decoder. A
                        # rebuilt VT only has the next IDR's POC in
                        # its DPB; old POCs are gone. If we kept the
                        # tracker's seen set, false-negatives would
                        # silently let a P-slice referencing a
                        # pre-rebuild POC slip past the pre-decode
                        # check straight into a guaranteed tear.
                        self._rps_tracker.reset()
                        # Sticky-keyframe IDR observation: the new
                        # transcoder built below will be seeded by
                        # this very IDR. Stamp the grace window now
                        # so the new VT's first few frames aren't
                        # treated as fresh decode errors, and arm
                        # the IDR-observed half of the two-condition
                        # clear if recovery was in progress.
                        self._idr_observed_at = loop.time()
                        if self._keyframe_required:
                            self._idr_observed = True
                        logger.debug("decoder rebuilt on fresh IDR")
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
                    # While ``_refresh_pending`` is true we have already
                    # PLIed and are waiting for the IDR that will be the
                    # new decoder's first frame. Don't feed the existing
                    # transcoder any more deltas -- they'd just compound
                    # the LTRP staleness we're trying to escape.
                    if self._transcoder is not None and not self._refresh_pending:
                        # Pre-decode RPS check: parse the first slice
                        # NAL's short-term RPS. If any used-by-curr
                        # reference points to a POC we never saw, the
                        # decoder will silently conceal -- fire PLI
                        # now and skip the guaranteed-tear feed.
                        # ``check_slice`` also stamps the POC parser
                        # state regardless of outcome.
                        slice_nal = next(
                            (n for n in current_au if is_slice_nal((n[0] >> 1) & 0x3F)),
                            None,
                        )
                        missing: set[int] = set()
                        if slice_nal is not None:
                            missing = self._rps_tracker.check_slice(slice_nal)
                        if missing and not au_is_key:
                            logger.debug(
                                "rps: P-slice references missing POCs %s -- pre-decode PLI",
                                sorted(missing),
                            )
                            self._on_decode_error()
                            if self._refresh_pending:
                                current_au = []
                                au_is_key = False
                                au_corrupt = False
                                rtp_packets += 1
                                continue
                        annexb = b"".join(b"\x00\x00\x00\x01" + nal for nal in current_au)
                        self._transcoder.feed(annexb)
                        feed_count += 1
                        # Add this slice's POC to the DPB shadow so
                        # later slices can reference it. For IDRs
                        # this stamps POC=0; for P-slices it stamps
                        # the derived POC from check_slice above.
                        self._rps_tracker.commit_decoded()
                        # Sticky-keyframe IDR observation: half of the
                        # two-condition clear (the other half is a
                        # clean decoded frame, handled in
                        # ``_broadcast_frame``). Also stamps the
                        # post-IDR grace window so the in-flight
                        # pre-IDR P-frames in VT's queue don't
                        # re-trigger ``_on_decode_error``.
                        if au_is_key:
                            self._idr_observed_at = loop.time()
                            if self._keyframe_required:
                                self._idr_observed = True
                current_au = []
                au_is_key = False
                au_corrupt = False

            rtp_packets += 1
            now = loop.time()
            if now - last_stat_t >= 2.0:
                frames_now = self._frames_emitted
                logger.debug(
                    "ingress stats: rtp=%d feeds=%d frames=%d (Δframes=%d / %.1fs)",
                    rtp_packets,
                    feed_count,
                    frames_now,
                    frames_now - frame_count_at_last_log,
                    now - last_stat_t,
                )
                rtp_packets = 0
                feed_count = 0
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
        sock = self._active_sock
        if sock is None or self._rtcp_dest is None:
            return
        if not (self._local_ssrc and self._remote_ssrc):
            return
        try:
            loop = asyncio.get_running_loop()
            await loop.sock_sendto(sock, self._build_rtcp_pli(), (*self._rtcp_dest, 0, 0))
            logger.debug("sent RTCP PLI (requested fresh keyframe)")
        except OSError as exc:
            logger.debug("PLI send failed (%s)", exc)

    def _fire_decoder_refresh(self, now: float, *, reason: str) -> None:
        """Arm the decoder-rebuild + PLI sequence. The recv loop will
        close the transcoder when the IDR arrives."""
        if self._refresh_pending:
            return  # already armed; let the IDR land first
        self._refresh_pending = True
        pli_task = asyncio.create_task(self._send_rtcp_pli())
        self._pli_tasks.add(pli_task)
        pli_task.add_done_callback(self._pli_tasks.discard)
        self._last_refresh_t = now
        window_bps = sum(s for _, s in self._au_byte_window)
        logger.debug(
            "decoder-refresh (%s): %d client(s), %d B/s window",
            reason,
            len(self._clients),
            window_bps,
        )

    async def _decoder_refresh_loop(self) -> None:
        """Watch the RTP byte rate as a motion signal; rebuild the VT
        decoder periodically while motion is ongoing, after motion
        settles, and as an idle heartbeat. This is the VNC analogue of
        screen_stream's _decoder_refresh_loop -- the same trick a
        browser page-reload pulls.

        Triggers (in order of priority):
          1. ``active`` -- motion is currently happening and it's been
             ``active_interval`` since the last refresh. Without this,
             sustained motion shows tears the entire time the user is
             interacting; the next refresh wouldn't come until either
             motion ends + settle_delay (the ``settled`` path) or the
             heartbeat fires, which can be many seconds.
          2. ``settled`` -- motion just ended and settle_delay has
             passed. Catches the tail end of an interaction.
          3. ``heartbeat`` -- nothing's happening, but it's been long
             enough that we want a safety-net refresh anyway.

        ``min_interval`` caps back-to-back refreshes (each one costs a
        ~30 ms gap while the new decoder waits for its first IDR).
        """
        loop = asyncio.get_running_loop()
        motion_threshold_bps = 100_000  # 100 KB/s = motion
        active_interval = 1.5  # fire this often during sustained motion
        settle_delay = 0.4  # wait after motion ends
        heartbeat = 10.0  # max between refreshes when idle
        min_interval = 0.8  # cap back-to-back refreshes
        # Sticky-keyframe re-arm cadence + cap. Ported from
        # iSharScreen's FrameQualityGate: while we're in
        # ``_keyframe_required`` and Apple's encoder hasn't responded
        # to our PLI with a usable IDR, keep re-emitting PLI at
        # ``re_arm_interval`` (the encoder's typical IDR generate+
        # transmit window settles in ~100-300 ms; 1.0 s leaves
        # headroom against overlapping IDR responses). After
        # ``re_arm_cap`` attempts give up and clear the flag so we
        # stop flooding -- the motion/heartbeat triggers above will
        # still catch the next natural refresh window.
        re_arm_interval = 1.0
        re_arm_cap = 8
        while True:
            try:
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                return
            if not self._clients:
                continue
            if self._transcoder is None or self._rtcp_dest is None:
                continue
            now = loop.time()
            # Sticky re-arm: highest priority -- if the decoder is
            # still in keyframe_required after a previous refresh
            # cleared `_refresh_pending`, keep firing PLI on the
            # re-arm cadence until either a clean post-IDR frame
            # arrives (clears keyframe_required in `_broadcast_frame`)
            # or we hit the cap.
            if (
                self._keyframe_required
                and not self._refresh_pending
                and (now - self._last_refresh_t) >= re_arm_interval
            ):
                self._fir_attempts += 1
                if self._fir_attempts >= re_arm_cap:
                    if not self._cap_warned:
                        logger.warning(
                            "decoder still tearing after %d PLI attempts; "
                            "giving up sticky recovery (motion/heartbeat "
                            "refresh remains armed)",
                            self._fir_attempts,
                        )
                        self._cap_warned = True
                    self._keyframe_required = False
                    self._idr_observed = False
                    self._fir_attempts = 0
                else:
                    self._fire_decoder_refresh(now, reason="re-arm")
                    continue
            while self._au_byte_window and self._au_byte_window[0][0] < now - 1.0:
                self._au_byte_window.popleft()
            window_bytes = sum(s for _, s in self._au_byte_window)
            currently_active = window_bytes >= motion_threshold_bps
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

    # ----- Audio: AAC-ELD recv + decode + play ------------------------------
    async def _audio_udp_recv(self, sock: socket.socket) -> None:
        """Receive RTP audio packets, strip the RTP header, decode the
        AAC-ELD AU via AudioToolbox, and feed the PCM to the local
        AudioQueue. Mirrors :meth:`screen_stream.ScreenStreamServer._audio_udp_recv`
        but plays locally instead of broadcasting."""
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        consecutive_errors = 0
        _ERR_RECREATE_THRESHOLD = 5
        pkt_count = 0
        last_stat_t = loop.time()
        while True:
            try:
                data = await loop.sock_recv(sock, 65535)
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

    async def _audio_rtcp_send_loop(self, sock: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        sent = 0
        while True:
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return
            if self._audio_rtcp_dest is None or self._audio_rtp_packets_received == 0:
                continue
            try:
                await loop.sock_sendto(sock, self._build_audio_rtcp_rr(), (*self._audio_rtcp_dest, 0, 0))
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
            # Force a decoder rebuild for this client. The VT decoder
            # may have been accumulating stale LTRP state for the
            # entire time the server has been running before this
            # client connected; trigger the same refresh path that
            # motion-settled and heartbeat use so the very first
            # framebuffer update is decoded from a fresh IDR.
            if self._transcoder is not None and self._rtcp_dest is not None:
                loop = self._loop
                if loop is not None:
                    self._fire_decoder_refresh(loop.time(), reason="client-connect")
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
        w = client.writer
        expected = self._fb_width * self._fb_height * 4
        while True:
            await client.wants_update.wait()
            client.wants_update.clear()
            frame = self._latest_frame
            if frame is None or frame is client.last_sent_frame:
                continue
            if len(frame) != expected:
                # SPS-locked dimensions shouldn't change mid-session,
                # but if VT ever hands us a differently sized buffer we
                # skip rather than desync the TCP stream.
                logger.warning(
                    "frame size mismatch: got %d bytes, fb expects %d (%dx%d * 4) -- dropping",
                    len(frame),
                    expected,
                    self._fb_width,
                    self._fb_height,
                )
                continue
            client.last_sent_frame = frame
            # FramebufferUpdate: msg-type(1) + padding(1) + n-rects(2) +
            # rect-header(12) + pixel bytes. One full-frame Raw rect.
            rect_header = struct.pack(
                ">HHHHi",
                0,
                0,
                self._fb_width,
                self._fb_height,
                _ENC_RAW,
            )
            header = (
                b"\x00\x00"  # msg-type + padding
                + struct.pack(">H", 1)  # one rect
                + rect_header
            )
            w.write(header)
            w.write(frame)
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

        # 2) Start device-side video stream. Generate a single
        # client_session_id up front so the audio stream (started
        # below) gets paired with the video session on the device --
        # this is what Xcode's Mirror does.
        shared_session_id = uuid.uuid4()
        svc = DisplayService(self._rsd)
        await svc.connect()
        local_ip = svc.service.local_address[0]
        answer = await svc.start_video_stream(
            receiver_ip=local_ip,
            receiver_port=port,
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
        self._active_sock = sock
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
                " -- decoder-refresh will be a no-op; tears under motion will not be cleaned up",
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
                audio_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                audio_sock.bind(("::", 0))
                with contextlib.suppress(OSError):
                    audio_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                audio_port = audio_sock.getsockname()[1]
                audio_svc = DisplayService(self._rsd)
                await audio_svc.connect()
                audio_answer = await audio_svc.start_audio_stream(
                    receiver_ip=local_ip,
                    receiver_port=audio_port,
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
                self._audio_sock = audio_sock
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
                self._audio_sock = None
                self._audio_svc = None
                self._audio_session_id = None

        # 4) Background tasks.
        loop = asyncio.get_running_loop()
        self._loop = loop
        feed_task = asyncio.create_task(self._udp_recv_and_pipe(sock))
        refresh_task = asyncio.create_task(self._decoder_refresh_loop())
        if self._audio_enabled and self._audio_sock is not None:
            audio_recv_task = asyncio.create_task(self._audio_udp_recv(self._audio_sock))
            if self._audio_rtcp_dest and self._audio_local_ssrc and self._audio_remote_ssrc:
                audio_rtcp_task = asyncio.create_task(self._audio_rtcp_send_loop(self._audio_sock))
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
            logger.debug("shutdown: stopping refresh loop")
            refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await refresh_task
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
                sock.close()
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
            if self._audio_sock is not None:
                with contextlib.suppress(Exception):
                    self._audio_sock.close()
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
