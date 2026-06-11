"""
HEVC -> JPEG transcoder via Apple VideoToolbox (macOS only, pure ctypes).

Why this module exists:
    ffmpeg's libavcodec HEVC parser cannot construct a reference picture
    set for the bitstream Apple's screen-mirror encoder emits ("Could
    not find ref with POC N / Error constructing the frame RPS"). VT
    silently tolerates the same bytes -- it's what Xcode uses. To get
    HEVC -> JPEG without the LTRP/RPS pain we have to go VT direct.

Pipeline::

    Annex-B HEVC AU
        -> VTDecompressionSession (HW HEVC decode)
        -> CVPixelBuffer (NV12 by default)
        -> VTCompressionSession (codec='jpeg')
        -> JPEG bytes (one self-contained file per frame)

Output goes through a thread-safe queue so the asyncio caller can drain
JPEGs without touching VT's internal threads.

The HEVCDecoder + JpegEncoder pair are largely the same shape as the
H.264 transcoder I built earlier in this session (later reverted) --
the JPEG encoder is simpler because there are no parameter sets to
extract or framing to massage.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import queue
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

# ---------------------------------------------------------------------------
# Framework handles
# ---------------------------------------------------------------------------
vt = ctypes.CDLL(ctypes.util.find_library("VideoToolbox"))
cm = ctypes.CDLL(ctypes.util.find_library("CoreMedia"))
cf = ctypes.CDLL(ctypes.util.find_library("CoreFoundation"))
cv = ctypes.CDLL(ctypes.util.find_library("CoreVideo"))

OSStatus = c_int32


class _CMTime(Structure):
    _fields_ = [
        ("value", c_int64),
        ("timescale", c_int32),
        ("flags", c_uint32),
        ("epoch", c_int64),
    ]


# ---------------------------------------------------------------------------
# CoreFoundation primitives
# ---------------------------------------------------------------------------
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
kCFNumberSInt32Type = 3


def _cfnumber_i32(value: int) -> c_void_p:
    v = c_int32(value)
    return c_void_p(cf.CFNumberCreate(None, kCFNumberSInt32Type, byref(v)))


# ---------------------------------------------------------------------------
# CoreMedia bindings
# ---------------------------------------------------------------------------
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


class _CMVideoDimensions(Structure):
    _fields_ = [("width", c_int32), ("height", c_int32)]


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

# ---------------------------------------------------------------------------
# VideoToolbox decoder
# ---------------------------------------------------------------------------
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

kVTDecodeFrame_EnableAsynchronousDecompression = 1 << 0
kVTDecodeFrame_1xRealTimePlayback = 1 << 2

# ---------------------------------------------------------------------------
# VideoToolbox compression (JPEG output)
# ---------------------------------------------------------------------------
VTCompressionOutputCallback = CFUNCTYPE(
    None,
    c_void_p,
    c_void_p,
    OSStatus,
    c_uint32,
    c_void_p,
)

vt.VTCompressionSessionCreate.restype = OSStatus
vt.VTCompressionSessionCreate.argtypes = [
    c_void_p,
    c_int32,
    c_int32,
    c_uint32,
    c_void_p,
    c_void_p,
    c_void_p,
    VTCompressionOutputCallback,
    c_void_p,
    POINTER(c_void_p),
]
vt.VTCompressionSessionEncodeFrame.restype = OSStatus
vt.VTCompressionSessionEncodeFrame.argtypes = [
    c_void_p,
    c_void_p,
    _CMTime,
    _CMTime,
    c_void_p,
    c_void_p,
    POINTER(c_uint32),
]
vt.VTCompressionSessionCompleteFrames.restype = OSStatus
vt.VTCompressionSessionCompleteFrames.argtypes = [c_void_p, _CMTime]
vt.VTCompressionSessionInvalidate.restype = None
vt.VTCompressionSessionInvalidate.argtypes = [c_void_p]
vt.VTSessionSetProperty.restype = OSStatus
vt.VTSessionSetProperty.argtypes = [c_void_p, c_void_p, c_void_p]

# codec FourCC = 'jpeg'
kCMVideoCodecType_JPEG = 0x6A706567

kVTCompressionPropertyKey_RealTime = c_void_p.in_dll(vt, "kVTCompressionPropertyKey_RealTime")
kVTCompressionPropertyKey_Quality = c_void_p.in_dll(vt, "kVTCompressionPropertyKey_Quality")


def _cfnumber_f32(value: float) -> c_void_p:
    cf.CFNumberCreate.argtypes = [c_void_p, c_int32, c_void_p]
    v = ctypes.c_float(value)
    # kCFNumberFloat32Type = 5
    return c_void_p(cf.CFNumberCreate(None, 5, byref(v)))


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
    """Annex-B HEVC -> CVPixelBuffer via VTDecompressionSession."""

    def __init__(self, vps: bytes, sps: bytes, pps: bytes) -> None:
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
        st = vt.VTDecompressionSessionCreate(None, self._fmt, None, None, byref(cb_rec), byref(self._session))
        if st != 0:
            raise RuntimeError(f"VTDecompressionSessionCreate: OSStatus={st}")

        dims = cm.CMVideoFormatDescriptionGetDimensions(self._fmt)
        self.width = int(dims.width)
        self.height = int(dims.height)

    def _on_output(self, refcon, src_ref, status, info_flags, image_buf, pts, dur):
        if status != 0 or not image_buf:
            self._outputs.put((status, None))
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
        flags = kVTDecodeFrame_EnableAsynchronousDecompression | kVTDecodeFrame_1xRealTimePlayback
        st = vt.VTDecompressionSessionDecodeFrame(self._session, sb, flags, None, byref(info))
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
            vt.VTDecompressionSessionInvalidate(self._session)
            cf.CFRelease(self._session)
            self._session = c_void_p(0)
        if self._fmt.value:
            cf.CFRelease(self._fmt)
            self._fmt = c_void_p(0)

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()


# ---------------------------------------------------------------------------
# JpegEncoder
# ---------------------------------------------------------------------------
class JpegEncoder:
    """CVPixelBuffer -> JPEG bytes via VTCompressionSession (HW)."""

    def __init__(self, width: int, height: int, quality: float = 0.7) -> None:
        self.width = width
        self.height = height
        self._cb = VTCompressionOutputCallback(self._on_output)
        self._session = c_void_p(0)
        st = vt.VTCompressionSessionCreate(
            None,
            width,
            height,
            kCMVideoCodecType_JPEG,
            None,
            None,
            None,
            self._cb,
            None,
            byref(self._session),
        )
        if st != 0:
            raise RuntimeError(f"VTCompressionSessionCreate(jpeg): OSStatus={st}")
        # Properties: real-time, quality 0.0-1.0
        vt.VTSessionSetProperty(self._session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue)
        q = _cfnumber_f32(quality)
        vt.VTSessionSetProperty(self._session, kVTCompressionPropertyKey_Quality, q)
        cf.CFRelease(q)
        self._outputs: queue.Queue = queue.Queue()

    def _on_output(self, refcon, src_ref, status, info_flags, sample_buf):
        if status != 0 or not sample_buf:
            self._outputs.put(None)
            return
        try:
            bb = cm.CMSampleBufferGetDataBuffer(sample_buf)
            if not bb:
                self._outputs.put(None)
                return
            n = cm.CMBlockBufferGetDataLength(bb)
            scratch = ctypes.create_string_buffer(n)
            cm.CMBlockBufferCopyDataBytes(bb, 0, n, scratch)
            self._outputs.put(ctypes.string_at(scratch, n))
        except Exception:
            self._outputs.put(None)

    def feed(self, image_buf: int, pts_ticks: int, timescale: int = 90_000) -> None:
        pts = _CMTime(pts_ticks, timescale, 1, 0)
        dur = _CMTime(timescale // 60, timescale, 1, 0)
        info = c_uint32(0)
        st = vt.VTCompressionSessionEncodeFrame(self._session, image_buf, pts, dur, None, None, byref(info))
        if st != 0:
            self._outputs.put(None)

    def drain(self):
        try:
            while True:
                yield self._outputs.get_nowait()
        except queue.Empty:
            return

    def flush(self) -> None:
        vt.VTCompressionSessionCompleteFrames(self._session, _CMTime(0, 0, 0, 0))

    def close(self) -> None:
        if self._session.value:
            self.flush()
            vt.VTCompressionSessionInvalidate(self._session)
            cf.CFRelease(self._session)
            self._session = c_void_p(0)

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()


# ---------------------------------------------------------------------------
# Combined transcoder
# ---------------------------------------------------------------------------
class HevcToJpegTranscoder:
    """Decoupling worker: caller pushes Annex-B HEVC AUs via ``feed()``,
    a background thread runs them through the VT decoder + JPEG encoder
    and fires ``on_jpeg(bytes)`` for each finished JPEG frame.

    The callback runs on the worker thread; if your caller is asyncio
    you'll typically marshal back with ``loop.call_soon_threadsafe``."""

    def __init__(
        self,
        vps: bytes,
        sps: bytes,
        pps: bytes,
        *,
        on_jpeg,
        quality: float = 0.7,
    ) -> None:
        self._dec = HEVCDecoder(vps, sps, pps)
        self._enc = JpegEncoder(self._dec.width, self._dec.height, quality=quality)
        self._on_jpeg = on_jpeg
        self.width = self._dec.width
        self.height = self._dec.height
        self._inq: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="vt-hevc-jpeg", daemon=True)
        self._thread.start()

    def feed(self, annexb: bytes) -> None:
        self._inq.put(annexb)

    def close(self) -> None:
        self._stop.set()
        self._inq.put(None)
        self._thread.join(timeout=2.0)
        self._enc.close()
        self._dec.close()

    def _drain_enc_to_callback(self) -> None:
        for jpeg in self._enc.drain():
            if jpeg:
                with contextlib.suppress(Exception):
                    self._on_jpeg(jpeg)

    def _run(self) -> None:
        pts = 0
        tick = 90_000 // 60
        while not self._stop.is_set():
            try:
                item = self._inq.get(timeout=0.05)
            except queue.Empty:
                self._drain_enc_to_callback()
                continue
            if item is None:
                break
            try:
                self._dec.feed_annexb(item)
            except Exception:
                continue
            for status, image_buf in self._dec.drain():
                if status != 0 or not image_buf:
                    continue
                self._enc.feed(image_buf, pts_ticks=pts)
                pts += tick
                cf.CFRelease(image_buf)
            self._drain_enc_to_callback()
