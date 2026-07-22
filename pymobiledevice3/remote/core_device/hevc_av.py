"""HEVC -> BGRA decoder via PyAV / libavcodec.

Pipeline::

    Annex-B HEVC AU
        -> av.codec.CodecContext('hevc', 'r').decode()
        -> av.VideoFrame (yuvj420p)
        -> reformat to bgra at the SPS's cropped dimensions
        -> raw BGRA bytes (width * height * 4)

Cross-platform (macOS / Linux / Windows). PyAV ships a static FFmpeg
with HEVC decode enabled, so no system libs needed. Software decode;
hardware acceleration is available via libav hwaccels but adds setup
complexity and isn't required at the iOS DisplayService bitrate /
resolution.

Performance on the iOS DisplayService HEVC stream (``1264x2736 @
60 fps``, ~6 Mbps): measured at ~0.9 ms decode + ~0.3 ms BGRA
convert per frame on Apple Silicon -- 14x headroom against the
16.67 ms / frame budget at 60 fps. Comfortable on modern x86_64 too.

Output goes through a thread-safe queue so the asyncio caller can
drain frames without touching libav's internal threads.
"""

from __future__ import annotations

import contextlib
import logging
import queue
import threading

from pymobiledevice3.remote.core_device.hevc_rps import (
    parse_sps,
    remove_emulation_prevention,
)

logger = logging.getLogger(__name__)

# PyAV is an optional dep -- VideoToolbox is the default decoder on
# macOS, so a Mac user who never forces the libav path doesn't need
# PyAV installed. The error message is the user-facing install hint
# when serve-vnc actually needs this path (non-macOS hosts, or
# ``--decoder av``).
try:
    import av  # type: ignore[import]
    import av.codec  # pyright: ignore[reportMissingImports]
    import av.error  # pyright: ignore[reportMissingImports]
except ModuleNotFoundError as e:  # pragma: no cover
    raise ModuleNotFoundError("PyAV is required for the libav HEVC decoder path. Install with: pip install av") from e


class HevcToBgraTranscoder:
    """Annex-B HEVC -> raw BGRA bytes via libavcodec.

    ``feed(annexb)`` enqueues Annex-B AU bytes from the depacketizer.
    ``on_frame(bgra)`` fires on the worker thread for each successfully
    decoded frame. ``on_decode_error()`` fires when libav raises or
    produces no output for an AU -- the sticky-keyframe recovery path
    in ``vnc_server`` arms PLI off this signal.
    """

    def __init__(
        self,
        vps: bytes,
        sps: bytes,
        pps: bytes,
        *,
        on_frame,
        on_decode_error=None,
    ) -> None:
        # libav reports decoded-frame dimensions rounded up to the
        # codec's coding-block alignment (typically a multiple of 16);
        # the SPS's pic_width / pic_height_in_luma_samples carry the
        # *cropped* values that match VT's CMVideoFormatDescription
        # output. Use the SPS values so both decoder paths publish
        # the same frame size to the VNC layer.
        try:
            sps_rbsp = remove_emulation_prevention(sps[2:])
            sps_state = parse_sps(sps_rbsp)
            self.width = sps_state.pic_width_in_luma_samples
            self.height = sps_state.pic_height_in_luma_samples
            if self.width <= 0 or self.height <= 0:
                raise ValueError(f"hevc_av: SPS gave nonsense dimensions {self.width}x{self.height}")
        except Exception as e:
            raise RuntimeError(f"hevc_av: SPS parse failed: {e}") from e

        self._on_frame = on_frame
        self._on_decode_error = on_decode_error

        self._codec = av.codec.CodecContext.create("hevc", "r")
        # Seed the decoder with the parameter sets so the first AU
        # doesn't need them in-band. Even if the IDR re-carries VPS/
        # SPS/PPS (Apple's stream does), libav tolerates the dupes.
        ps_annexb = b"".join(b"\x00\x00\x00\x01" + nal for nal in (vps, sps, pps))
        with contextlib.suppress(Exception):
            list(self._codec.decode(av.Packet(ps_annexb)))

        self._inq: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="av-hevc-bgra", daemon=True)
        self._thread.start()

    def feed(self, annexb: bytes) -> None:
        self._inq.put(annexb)

    def close(self) -> None:
        self._stop.set()
        self._inq.put(None)
        self._thread.join(timeout=2.0)
        with contextlib.suppress(Exception):
            # close() was removed in newer PyAV releases (AttributeError is suppressed
            # there); keep the call for older PyAV versions that still need it.
            self._codec.close()  # pyright: ignore[reportAttributeAccessIssue]

    # -- worker --------------------------------------------------------
    def _emit_frame(self, frame) -> None:
        # PyAV's reformat to bgra returns a tightly-packed buffer
        # (linesize = width * 4) at exactly the cropped width/height
        # we requested.
        bgra_frame = frame.reformat(width=self.width, height=self.height, format="bgra")
        plane = bgra_frame.planes[0]
        ba = bytearray(bytes(plane))
        # Force A=0xff: BGRA's high byte is alpha for some viewers,
        # and libav's bgra plane carries undefined-or-zero alpha.
        ba[3::4] = b"\xff" * (len(ba) // 4)
        with contextlib.suppress(Exception):
            self._on_frame(bytes(ba))

    def _fire_decode_error(self) -> None:
        cb = self._on_decode_error
        if cb is None:
            return
        with contextlib.suppress(Exception):
            cb()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._inq.get(timeout=0.05)
            except queue.Empty:
                continue
            if item is None:
                break
            # Apple's stream is P-only with no B-reordering, so each
            # AU should produce exactly one output frame. Anything
            # else (zero frames, or an exception) is a decode error
            # the sticky-recovery path needs to know about.
            try:
                frames = list(self._codec.decode(av.Packet(item)))
            except av.error.InvalidDataError as e:
                logger.debug("av decode rejected AU: %s", e)
                self._fire_decode_error()
                continue
            except Exception as e:
                logger.warning("av decode raised %s: %s", type(e).__name__, e)
                self._fire_decode_error()
                continue
            if not frames:
                # libav consumed the AU without emitting -- typically
                # means concealed / dropped. Treat as error so the
                # sticky-keyframe path arms PLI.
                self._fire_decode_error()
                continue
            for fr in frames:
                try:
                    self._emit_frame(fr)
                except Exception as e:
                    logger.warning("av emit failed: %s", e)
                    self._fire_decode_error()
