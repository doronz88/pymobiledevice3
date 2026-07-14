"""
HEVC -> BGRA decoder via Apple VideoToolbox (macOS only, pure ctypes).

Why this module exists:
    ffmpeg's libavcodec HEVC parser cannot construct a reference picture
    set for the bitstream Apple's screen-mirror encoder emits ("Could
    not find ref with POC N / Error constructing the frame RPS"). VT
    silently tolerates the same bytes -- it's what Xcode uses. To get
    HEVC -> pixels without the LTRP/RPS pain we have to go VT direct.

Pipeline::

    Annex-B HEVC AU
        -> VTDecompressionSession (HW HEVC decode, BGRA output)
        -> CVPixelBuffer
        -> raw BGRA bytes (width*height*4)

Output goes through a thread-safe queue so the asyncio caller can drain
frames without touching VT's internal threads.

(The file name predates the redesign that dropped the JPEG round-trip;
left as-is to avoid an import churn. The current exports are
``HEVCDecoder`` and ``HevcToBgraTranscoder``.)
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import logging
import os
import queue
import sys
import threading
from ctypes import (
    CFUNCTYPE,
    POINTER,
    Structure,
    byref,
    c_int,
    c_int32,
    c_int64,
    c_size_t,
    c_uint32,
    c_void_p,
    cast,
)

# Pure-Python type/constant declarations live at module top so importers
# on non-Darwin platforms (Linux/Windows) can `import vt_jpeg` without
# triggering the framework loads below. The macOS-only setup -- CDLLs,
# function signatures, in_dll constants, helpers that close over them
# -- all sit behind the platform guard. The classes themselves raise a
# clear "macOS only" error at construction time on other platforms.
_IS_DARWIN = sys.platform == "darwin"

logger = logging.getLogger(__name__)

OSStatus = c_int32


class _CMTime(Structure):
    _fields_ = [
        ("value", c_int64),
        ("timescale", c_int32),
        ("flags", c_uint32),
        ("epoch", c_int64),
    ]


class _CMVideoDimensions(Structure):
    _fields_ = [("width", c_int32), ("height", c_int32)]


# CFUNCTYPE / Structure definitions don't need a CDLL, only ctypes itself.
VTDecompressionOutputCallback = CFUNCTYPE(
    None,
    c_void_p,
    c_void_p,
    OSStatus,
    c_uint32,
    c_void_p,
    _CMTime,
    _CMTime,
)


class _VTDecompressionOutputCallbackRecord(Structure):
    _fields_ = [
        ("decompressionOutputCallback", VTDecompressionOutputCallback),
        ("decompressionOutputRefCon", c_void_p),
    ]


# Integer/byte constants are pure data, no CDLL needed.
kCFNumberSInt32Type = 3
kVTDecodeFrame_EnableAsynchronousDecompression = 1 << 0
kVTDecodeFrame_1xRealTimePlayback = 1 << 2
kVTDecodeInfo_FrameDropped = 1 << 1
kCVPixelBufferLock_ReadOnly = 1
kCVPixelFormatType_32BGRA = 0x42475241  # 'BGRA'

if _IS_DARWIN:
    # ---- Framework handles --------------------------------------------------
    vt = ctypes.CDLL(ctypes.util.find_library("VideoToolbox"))
    cm = ctypes.CDLL(ctypes.util.find_library("CoreMedia"))
    cf = ctypes.CDLL(ctypes.util.find_library("CoreFoundation"))
    cv = ctypes.CDLL(ctypes.util.find_library("CoreVideo"))

    # ---- CoreFoundation primitives -----------------------------------------
    cf.CFRetain.restype = c_void_p
    cf.CFRetain.argtypes = [c_void_p]
    cf.CFRelease.restype = None
    cf.CFRelease.argtypes = [c_void_p]
    cf.CFDictionaryCreate.restype = c_void_p
    cf.CFDictionaryCreate.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_void_p), c_size_t, c_void_p, c_void_p]
    cf.CFNumberCreate.restype = c_void_p
    cf.CFNumberCreate.argtypes = [c_void_p, c_int32, c_void_p]
    kCFBooleanTrue = c_void_p.in_dll(cf, "kCFBooleanTrue")
    kCFBooleanFalse = c_void_p.in_dll(cf, "kCFBooleanFalse")
    kCFTypeDictionaryKeyCallBacks = c_void_p.in_dll(cf, "kCFTypeDictionaryKeyCallBacks")
    kCFTypeDictionaryValueCallBacks = c_void_p.in_dll(cf, "kCFTypeDictionaryValueCallBacks")

    def _cfnumber_i32(value: int) -> c_void_p:
        v = c_int32(value)
        return c_void_p(cf.CFNumberCreate(None, kCFNumberSInt32Type, byref(v)))

    # ---- CoreMedia bindings ------------------------------------------------
    cm.CMVideoFormatDescriptionCreateFromHEVCParameterSets.restype = OSStatus
    cm.CMVideoFormatDescriptionCreateFromHEVCParameterSets.argtypes = [
        c_void_p,
        c_size_t,
        POINTER(c_void_p),
        POINTER(c_size_t),
        c_int,
        c_void_p,
        POINTER(c_void_p),
    ]
    cm.CMVideoFormatDescriptionGetDimensions.restype = _CMVideoDimensions
    cm.CMVideoFormatDescriptionGetDimensions.argtypes = [c_void_p]
    cm.CMBlockBufferCreateWithMemoryBlock.restype = OSStatus
    cm.CMBlockBufferCreateWithMemoryBlock.argtypes = [
        c_void_p,
        c_void_p,
        c_size_t,
        c_void_p,
        c_void_p,
        c_size_t,
        c_size_t,
        c_uint32,
        POINTER(c_void_p),
    ]
    cm.CMBlockBufferReplaceDataBytes.restype = OSStatus
    cm.CMBlockBufferReplaceDataBytes.argtypes = [c_void_p, c_void_p, c_size_t, c_size_t]
    cm.CMSampleBufferCreateReady.restype = OSStatus
    cm.CMSampleBufferCreateReady.argtypes = [
        c_void_p,
        c_void_p,
        c_void_p,
        c_int64,
        c_int64,
        c_void_p,
        c_int64,
        POINTER(c_size_t),
        POINTER(c_void_p),
    ]
    cm.CMSampleBufferGetDataBuffer.restype = c_void_p
    cm.CMSampleBufferGetDataBuffer.argtypes = [c_void_p]
    cm.CMBlockBufferGetDataLength.restype = c_size_t
    cm.CMBlockBufferGetDataLength.argtypes = [c_void_p]
    cm.CMBlockBufferCopyDataBytes.restype = OSStatus
    cm.CMBlockBufferCopyDataBytes.argtypes = [c_void_p, c_size_t, c_size_t, c_void_p]

    # ---- VideoToolbox decoder ----------------------------------------------
    vt.VTDecompressionSessionCreate.restype = OSStatus
    vt.VTDecompressionSessionCreate.argtypes = [
        c_void_p,
        c_void_p,
        c_void_p,
        c_void_p,
        POINTER(_VTDecompressionOutputCallbackRecord),
        POINTER(c_void_p),
    ]
    vt.VTDecompressionSessionDecodeFrame.restype = OSStatus
    vt.VTDecompressionSessionDecodeFrame.argtypes = [
        c_void_p,
        c_void_p,
        c_uint32,
        c_void_p,
        POINTER(c_uint32),
    ]
    vt.VTDecompressionSessionWaitForAsynchronousFrames.restype = OSStatus
    vt.VTDecompressionSessionWaitForAsynchronousFrames.argtypes = [c_void_p]
    vt.VTDecompressionSessionInvalidate.restype = None
    vt.VTDecompressionSessionInvalidate.argtypes = [c_void_p]

    # ---- VideoProcessing decoder (AVConference / DeviceHub decode path) -----
    # Apple's screen-mirror clients (Xcode DeviceHub, FaceTime) do NOT decode
    # through the raw VideoToolbox entry points -- they go through
    # VideoProcessing.framework's VCPDecompressionSession* API. These wrap VT
    # but add the jitter/reordering discipline AVConference relies on, and are
    # the decoder that "never tears" per the maintainer's DeviceHub reference.
    # The VCP entry points are ABI-identical to their VT counterparts
    # (same formatDesc / decoderSpec / destImageAttrs / callbackRecord shape),
    # so we can bind them with the exact VT argtypes and drop them in.
    #
    # VideoProcessing is a dyld-shared-cache-only PrivateFramework: it has no
    # on-disk dylib, so find_library() returns None. dlopen resolves it from
    # the cache only via its full framework path.
    _VP_PATH = "/System/Library/PrivateFrameworks/VideoProcessing.framework/VideoProcessing"
    _USE_VCP = os.environ.get("PMD3_USE_VCP", "0") not in ("", "0", "false", "False")
    vp = None
    if _USE_VCP:
        try:
            vp = ctypes.CDLL(_VP_PATH)
            vp.VCPDecompressionSessionCreate.restype = OSStatus
            vp.VCPDecompressionSessionCreate.argtypes = vt.VTDecompressionSessionCreate.argtypes
            vp.VCPDecompressionSessionDecodeFrame.restype = OSStatus
            vp.VCPDecompressionSessionDecodeFrame.argtypes = vt.VTDecompressionSessionDecodeFrame.argtypes
            vp.VCPDecompressionSessionInvalidate.restype = None
            vp.VCPDecompressionSessionInvalidate.argtypes = [c_void_p]
        except (OSError, AttributeError):
            vp = None
            _USE_VCP = False

    # Decoder dispatch: default to raw VideoToolbox; swap to VideoProcessing's
    # VCP* entry points when PMD3_USE_VCP is set and the framework loaded.
    if _USE_VCP and vp is not None:
        _DEC_CREATE = vp.VCPDecompressionSessionCreate
        _DEC_DECODE = vp.VCPDecompressionSessionDecodeFrame
        _DEC_INVALIDATE = vp.VCPDecompressionSessionInvalidate
        _DEC_BACKEND = "VCP"
    else:
        _DEC_CREATE = vt.VTDecompressionSessionCreate
        _DEC_DECODE = vt.VTDecompressionSessionDecodeFrame
        _DEC_INVALIDATE = vt.VTDecompressionSessionInvalidate
        _DEC_BACKEND = "VT"

    # ---- CoreVideo pixel-buffer accessors (for direct BGRA readout) --------
    cv.CVPixelBufferLockBaseAddress.restype = c_int32
    cv.CVPixelBufferLockBaseAddress.argtypes = [c_void_p, c_uint32]
    cv.CVPixelBufferUnlockBaseAddress.restype = c_int32
    cv.CVPixelBufferUnlockBaseAddress.argtypes = [c_void_p, c_uint32]
    cv.CVPixelBufferGetBaseAddress.restype = c_void_p
    cv.CVPixelBufferGetBaseAddress.argtypes = [c_void_p]
    cv.CVPixelBufferGetBytesPerRow.restype = c_size_t
    cv.CVPixelBufferGetBytesPerRow.argtypes = [c_void_p]
    cv.CVPixelBufferGetWidth.restype = c_size_t
    cv.CVPixelBufferGetWidth.argtypes = [c_void_p]
    cv.CVPixelBufferGetHeight.restype = c_size_t
    cv.CVPixelBufferGetHeight.argtypes = [c_void_p]
    kCVPixelBufferPixelFormatTypeKey = c_void_p.in_dll(cv, "kCVPixelBufferPixelFormatTypeKey")

    def _build_dest_attrs_bgra() -> c_void_p:
        """Build a destinationImageBufferAttributes dict that pins the
        decoded output to 32-bit BGRA -- so we can read the framebuffer
        directly off the CVPixelBuffer instead of going through a JPEG
        round-trip."""
        fmt_num = _cfnumber_i32(kCVPixelFormatType_32BGRA)
        keys = (c_void_p * 1)(kCVPixelBufferPixelFormatTypeKey)
        values = (c_void_p * 1)(fmt_num)
        d = cf.CFDictionaryCreate(None, keys, values, 1, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)
        cf.CFRelease(fmt_num)
        return c_void_p(d)

    def _build_vcp_decoder_spec() -> c_void_p:
        """Build the decoderSpecification dict VCPDecompressionSessionCreate
        requires.

        VTDecompressionSessionCreate tolerates a NULL decoderSpecification;
        VCPDecompressionSessionCreate does NOT -- it unconditionally calls
        CFDictionaryGetValue() on the dict (reverse-engineered: crashes with a
        NULL-deref in CFDictionaryGetValue when a3 is NULL). It reads optional
        keys (AllowClientProcessDecode, NumberOfTiles, ...) and falls back to
        defaults when they are absent, so an empty-but-valid CFDictionary is
        enough to satisfy the lookups without opting into any of VCP's extra
        behaviours."""
        d = cf.CFDictionaryCreate(
            None, None, None, 0, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks
        )
        return c_void_p(d)


# ---------------------------------------------------------------------------
# Annex-B helpers
# ---------------------------------------------------------------------------
def _annexb_to_avcc(annexb: bytes) -> bytes:
    """Convert Annex-B start-coded NAL units to 4-byte length-prefixed (AVCC)."""
    out = bytearray()
    i = 0
    while i < len(annexb):
        if annexb[i : i + 4] == b"\x00\x00\x00\x01":
            sc = 4
        elif annexb[i : i + 3] == b"\x00\x00\x01":
            sc = 3
        else:
            i += 1
            continue
        j = i + sc
        while j < len(annexb):
            if annexb[j : j + 4] == b"\x00\x00\x00\x01" or annexb[j : j + 3] == b"\x00\x00\x01":
                break
            j += 1
        nal = annexb[i + sc : j]
        out.extend(len(nal).to_bytes(4, "big"))
        out.extend(nal)
        i = j
    return bytes(out)


# ---------------------------------------------------------------------------
# HEVCDecoder
# ---------------------------------------------------------------------------
class HEVCDecoder:
    """Annex-B HEVC -> CVPixelBuffer via VTDecompressionSession.

    Pass ``bgra_output=True`` to force the decoder to emit 32-bit BGRA
    pixel buffers (CPU-readable) instead of VT's default NV12. Useful
    when the consumer wants pixel bytes without going through a
    re-encode step."""

    def __init__(self, vps: bytes, sps: bytes, pps: bytes, *, bgra_output: bool = False) -> None:
        if not _IS_DARWIN:
            raise RuntimeError("HEVCDecoder requires macOS (VideoToolbox)")
        self._ps_buffers = [ctypes.create_string_buffer(b, len(b)) for b in (vps, sps, pps)]
        ps_ptrs = (c_void_p * 3)(*[cast(b, c_void_p) for b in self._ps_buffers])
        ps_sizes = (c_size_t * 3)(*[len(b) for b in (vps, sps, pps)])
        self._fmt = c_void_p(0)
        st = cm.CMVideoFormatDescriptionCreateFromHEVCParameterSets(
            None, 3, ps_ptrs, ps_sizes, 4, None, byref(self._fmt)
        )
        if st != 0:
            raise RuntimeError(f"CMVideoFormatDescriptionCreateFromHEVCParameterSets: OSStatus={st}")

        self._outputs: queue.Queue = queue.Queue()
        self._cb = VTDecompressionOutputCallback(self._on_output)
        cb_rec = _VTDecompressionOutputCallbackRecord(self._cb, None)
        self._session = c_void_p(0)
        dest_attrs = _build_dest_attrs_bgra() if bgra_output else None
        # VT accepts NULL decoderSpecification; VCP requires a non-NULL dict
        # (it CFDictionaryGetValue()s it unconditionally -> NULL-deref crash).
        decoder_spec = _build_vcp_decoder_spec() if _DEC_BACKEND == "VCP" else None
        st = _DEC_CREATE(None, self._fmt, decoder_spec, dest_attrs, byref(cb_rec), byref(self._session))
        if decoder_spec is not None:
            cf.CFRelease(decoder_spec)
        if dest_attrs is not None:
            cf.CFRelease(dest_attrs)
        if st != 0:
            raise RuntimeError(f"{_DEC_BACKEND}DecompressionSessionCreate: OSStatus={st}")
        logger.info(
            "decode backend: %s (%s)",
            _DEC_BACKEND,
            "VideoProcessing.framework VCPDecompressionSession -- PMD3_USE_VCP"
            if _DEC_BACKEND == "VCP"
            else "VideoToolbox VTDecompressionSession",
        )

        dims = cm.CMVideoFormatDescriptionGetDimensions(self._fmt)
        self.width = int(dims.width)
        self.height = int(dims.height)

    def _on_output(self, refcon, src_ref, status, info_flags, image_buf, pts, dur):
        # kVTDecodeInfo_FrameDropped is set when VT concealed a frame --
        # the status may be 0 (no API-level error) yet output is corrupt.
        # Treat as an error so callers can drive a sticky keyframe-required
        # recovery off the same signal as a non-zero OSStatus.
        if status != 0 or not image_buf or (info_flags & kVTDecodeInfo_FrameDropped):
            self._outputs.put((status if status != 0 else -1, None))
            return
        cf.CFRetain(image_buf)
        self._outputs.put((0, image_buf))

    def feed_annexb(self, annexb: bytes) -> None:
        avcc = _annexb_to_avcc(annexb)
        if not avcc:
            return
        bb = c_void_p(0)
        st = cm.CMBlockBufferCreateWithMemoryBlock(None, None, len(avcc), None, None, 0, len(avcc), 0, byref(bb))
        if st != 0:
            raise RuntimeError(f"CMBlockBufferCreateWithMemoryBlock: OSStatus={st}")
        scratch = ctypes.create_string_buffer(avcc, len(avcc))
        cm.CMBlockBufferReplaceDataBytes(scratch, bb, 0, len(avcc))
        sample_size = (c_size_t * 1)(len(avcc))
        sb = c_void_p(0)
        st = cm.CMSampleBufferCreateReady(None, bb, self._fmt, 1, 0, None, 1, sample_size, byref(sb))
        if st != 0:
            cf.CFRelease(bb)
            raise RuntimeError(f"CMSampleBufferCreateReady: OSStatus={st}")
        info = c_uint32(0)
        # SYNCHRONOUS, decode-every-frame (flags = 0). Reverse-engineered from
        # AVConference's receiver (VIDEOPROCESSING_RE_ROADMAP.md §7-8): DeviceHub
        # decodes every frame fully, in order, and never drops
        # (numAlarmsDropped=0, decodedFrameCount==decodedFullFrameCount).
        #
        # We must NOT set kVTDecodeFrame_1xRealTimePlayback -- that lets VT DROP a
        # frame to hold real-time pace, orphaning the following P-frames'
        # references -> tear. We also drop EnableAsynchronousDecompression: with
        # async, DecodeFrame returns before the output callback fires, so the
        # transcoder's feed-then-drain worker only picks up a frame on the NEXT
        # feed -- the most recent frame stays stuck in VT's pipeline until more
        # input arrives, which stalls the display. Synchronous decode invokes the
        # callback before returning, so every frame drains immediately, in order.
        flags = 0
        st = _DEC_DECODE(self._session, sb, flags, None, byref(info))
        cf.CFRelease(sb)
        cf.CFRelease(bb)
        if st != 0:
            self._outputs.put((st, None))

    def drain(self):
        try:
            while True:
                yield self._outputs.get_nowait()
        except queue.Empty:
            return

    def close(self) -> None:
        if self._session.value:
            _DEC_INVALIDATE(self._session)
            cf.CFRelease(self._session)
            self._session = c_void_p(0)
        if self._fmt.value:
            cf.CFRelease(self._fmt)
            self._fmt = c_void_p(0)

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()


# ---------------------------------------------------------------------------
# HevcToBgraTranscoder
# ---------------------------------------------------------------------------
class HevcToBgraTranscoder:
    """Annex-B HEVC -> raw BGRA bytes, no JPEG round-trip.

    The VTDecompressionSession is configured with
    ``destinationImageBufferAttributes={kCVPixelFormatType: 32BGRA}`` so
    we get a CPU-readable BGRA pixel buffer per frame. The worker thread
    locks the buffer, copies the bytes out, and fires ``on_frame(bgra)``
    on the caller's behalf.

    Bytes are exactly ``width * height * 4`` (B, G, R, A in memory
    order). The A channel is forced to 0xff so VNC clients that treat
    the 4th byte as alpha don't render frames as transparent.

    The callback runs on the worker thread; asyncio callers should
    marshal back with ``loop.call_soon_threadsafe``."""

    def __init__(
        self,
        vps: bytes,
        sps: bytes,
        pps: bytes,
        *,
        on_frame,
        on_decode_error=None,
    ) -> None:
        self._dec = HEVCDecoder(vps, sps, pps, bgra_output=True)
        self._on_frame = on_frame
        # Optional hook fired when VT reports a decode failure or a
        # FrameDropped infoFlag. Always invoked on the worker thread --
        # asyncio consumers must marshal with ``call_soon_threadsafe``.
        self._on_decode_error = on_decode_error
        self.width = self._dec.width
        self.height = self._dec.height
        self._inq: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="vt-hevc-bgra", daemon=True)
        self._thread.start()

    def feed(self, annexb: bytes) -> None:
        self._inq.put(annexb)

    def close(self) -> None:
        self._stop.set()
        self._inq.put(None)
        self._thread.join(timeout=2.0)
        self._dec.close()

    def _emit(self, image_buf: int) -> None:
        st = cv.CVPixelBufferLockBaseAddress(image_buf, kCVPixelBufferLock_ReadOnly)
        if st != 0:
            return
        try:
            w = int(cv.CVPixelBufferGetWidth(image_buf))
            h = int(cv.CVPixelBufferGetHeight(image_buf))
            bpr = int(cv.CVPixelBufferGetBytesPerRow(image_buf))
            base = cv.CVPixelBufferGetBaseAddress(image_buf)
            if not base or w <= 0 or h <= 0:
                return
            if bpr == w * 4:
                data = ctypes.string_at(base, h * bpr)
            else:
                # Strip per-row padding when VT chose a wider stride.
                rows = [ctypes.string_at(base + y * bpr, w * 4) for y in range(h)]
                data = b"".join(rows)
        finally:
            cv.CVPixelBufferUnlockBaseAddress(image_buf, kCVPixelBufferLock_ReadOnly)
        ba = bytearray(data)
        ba[3::4] = b"\xff" * (len(ba) // 4)
        with contextlib.suppress(Exception):
            self._on_frame(bytes(ba))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._inq.get(timeout=0.05)
            except queue.Empty:
                continue
            if item is None:
                break
            try:
                self._dec.feed_annexb(item)
            except Exception:
                continue
            for status, image_buf in self._dec.drain():
                if status != 0 or not image_buf:
                    cb = self._on_decode_error
                    if cb is not None:
                        with contextlib.suppress(Exception):
                            cb()
                    continue
                try:
                    self._emit(image_buf)
                finally:
                    cf.CFRelease(image_buf)
