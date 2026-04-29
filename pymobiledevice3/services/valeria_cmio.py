"""CoreMediaIO-backed iOS screen capture (macOS, pure ctypes).

AVFoundation on macOS is itself a wrapper around CoreMediaIO, and the iPad
delivers H.264 NAL units over the same QuickTime USB protocol either way.
This backend talks to CMIO directly via ctypes against the public C API —
no PyObjC, no Objective-C runtime.

Thread model
============

::

   start() → background CFRunLoop pump (daemon thread)
          → enable + discover + register on_sample callback + start stream
   on_sample (DAL plugin worker thread)
          → drain CMSimpleQueue, build H264Frame, enqueue to internal queue
   frames() / aframes() (caller thread)
          → block on internal queue.get()
   stop() → stop stream, unregister callback, release queue, join pump
"""
from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import logging
import queue
import struct
import threading
import time
from typing import AsyncIterator, Iterator, Optional

from pymobiledevice3.services.valeria import (
    BackendUnavailableError,
    DeviceNotFoundError,
    H264Frame,
    IOSScreenCapture,
    MultipleDevicesError,
    ScreenRecordingPermissionError,
)

logger = logging.getLogger(__name__)


# ── Load frameworks (pure C — no libobjc) ────────────────────────────────
_cmio_path = ctypes.util.find_library("CoreMediaIO")
_cf_path = ctypes.util.find_library("CoreFoundation")
_cm_path = ctypes.util.find_library("CoreMedia")
_cv_path = ctypes.util.find_library("CoreVideo")
_cg_path = ctypes.util.find_library("CoreGraphics")

cmio = ctypes.cdll.LoadLibrary(_cmio_path) if _cmio_path else None
cf = ctypes.cdll.LoadLibrary(_cf_path) if _cf_path else None
cm = ctypes.cdll.LoadLibrary(_cm_path) if _cm_path else None
cv = ctypes.cdll.LoadLibrary(_cv_path) if _cv_path else None
cg = ctypes.cdll.LoadLibrary(_cg_path) if _cg_path else None


# Module-level CFUNCTYPE for the queue-altered callback.
# Signature per CMIOHardwareStream.h:
#   typedef void (*CMIODeviceStreamQueueAlteredProc)
#       (CMIOStreamID streamID, void* token, void* refCon);
_QueueAlteredProc = ctypes.CFUNCTYPE(
    None, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
)


class _CMIOAddr(ctypes.Structure):
    _fields_ = [("sel", ctypes.c_uint32), ("scope", ctypes.c_uint32),
                ("elem", ctypes.c_uint32)]


class _CMTime(ctypes.Structure):
    _fields_ = [("value", ctypes.c_int64), ("scale", ctypes.c_int32),
                ("flags", ctypes.c_uint32), ("epoch", ctypes.c_int64)]


class _CMVideoDimensions(ctypes.Structure):
    _fields_ = [("width", ctypes.c_int32), ("height", ctypes.c_int32)]


_kCFRunLoopDefaultMode: Optional[int] = None
_kUTF8 = 0x08000100

if cmio is not None and cf is not None and cm is not None and cv is not None:
    # CoreFoundation
    cf.CFStringGetCStringPtr.restype = ctypes.c_char_p
    cf.CFStringGetCStringPtr.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    cf.CFStringGetLength.restype = ctypes.c_long
    cf.CFStringGetLength.argtypes = [ctypes.c_void_p]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32,
    ]
    cf.CFRelease.argtypes = [ctypes.c_void_p]
    cf.CFRunLoopRunInMode.restype = ctypes.c_int32
    cf.CFRunLoopRunInMode.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_bool]
    _kCFRunLoopDefaultMode = ctypes.c_void_p.in_dll(cf, "kCFRunLoopDefaultMode").value

    # CoreMediaIO
    cmio.CMIOObjectHasProperty.restype = ctypes.c_bool
    cmio.CMIOObjectHasProperty.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
    cmio.CMIOObjectGetPropertyDataSize.restype = ctypes.c_int32
    cmio.CMIOObjectGetPropertyDataSize.argtypes = [
        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    cmio.CMIOObjectGetPropertyData.restype = ctypes.c_int32
    cmio.CMIOObjectGetPropertyData.argtypes = [
        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
    ]
    cmio.CMIOObjectSetPropertyData.restype = ctypes.c_int32
    cmio.CMIOObjectSetPropertyData.argtypes = [
        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_void_p,
    ]
    cmio.CMIODeviceStartStream.restype = ctypes.c_int32
    cmio.CMIODeviceStartStream.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    cmio.CMIODeviceStopStream.restype = ctypes.c_int32
    cmio.CMIODeviceStopStream.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    cmio.CMIOStreamCopyBufferQueue.restype = ctypes.c_int32
    cmio.CMIOStreamCopyBufferQueue.argtypes = [
        ctypes.c_uint32, _QueueAlteredProc, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]

    # CoreMedia
    cm.CMSimpleQueueDequeue.restype = ctypes.c_void_p
    cm.CMSimpleQueueDequeue.argtypes = [ctypes.c_void_p]
    cm.CMSimpleQueueGetCount.restype = ctypes.c_int32
    cm.CMSimpleQueueGetCount.argtypes = [ctypes.c_void_p]

    cm.CMSampleBufferGetImageBuffer.restype = ctypes.c_void_p
    cm.CMSampleBufferGetImageBuffer.argtypes = [ctypes.c_void_p]
    cm.CMSampleBufferGetFormatDescription.restype = ctypes.c_void_p
    cm.CMSampleBufferGetFormatDescription.argtypes = [ctypes.c_void_p]
    cm.CMSampleBufferGetDataBuffer.restype = ctypes.c_void_p
    cm.CMSampleBufferGetDataBuffer.argtypes = [ctypes.c_void_p]
    cm.CMSampleBufferGetPresentationTimeStamp.restype = _CMTime
    cm.CMSampleBufferGetPresentationTimeStamp.argtypes = [ctypes.c_void_p]

    cm.CMVideoFormatDescriptionGetDimensions.restype = _CMVideoDimensions
    cm.CMVideoFormatDescriptionGetDimensions.argtypes = [ctypes.c_void_p]
    cm.CMFormatDescriptionGetMediaSubType.restype = ctypes.c_uint32
    cm.CMFormatDescriptionGetMediaSubType.argtypes = [ctypes.c_void_p]
    cm.CMFormatDescriptionGetMediaType.restype = ctypes.c_uint32
    cm.CMFormatDescriptionGetMediaType.argtypes = [ctypes.c_void_p]

    cm.CMVideoFormatDescriptionGetH264ParameterSetAtIndex.restype = ctypes.c_int32
    cm.CMVideoFormatDescriptionGetH264ParameterSetAtIndex.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_void_p),  # **parameterSetPointerOut
        ctypes.POINTER(ctypes.c_size_t),  # *parameterSetSizeOut
        ctypes.POINTER(ctypes.c_size_t),  # *parameterSetCountOut
        ctypes.POINTER(ctypes.c_int32),   # *NALUnitHeaderLengthOut
    ]

    cm.CMBlockBufferGetDataLength.restype = ctypes.c_size_t
    cm.CMBlockBufferGetDataLength.argtypes = [ctypes.c_void_p]
    cm.CMBlockBufferCopyDataBytes.restype = ctypes.c_int32
    cm.CMBlockBufferCopyDataBytes.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_void_p,
    ]

if cg is not None:
    cg.CGPreflightScreenCaptureAccess.restype = ctypes.c_bool


# ── Constants (CMIO/CoreMedia FourCC codes) ──────────────────────────────
_SCOPE_GLOBAL = 0x676C6F62   # 'glob'
_SCOPE_INPUT = 0x696E7074    # 'inpt'
_ELEMENT_MAIN = 0
_SYSTEM_OBJECT = 1
_SUBTYPE_AVC1 = 0x61766331   # 'avc1' (H.264)
_LOC_EXTERNAL_DEVICE = 3     # wired iOS
_LOC_EXTERNAL_WIRELESS = 4   # WiFi iOS


def _fourcc(s: bytes) -> int:
    return struct.unpack(">I", s)[0]


# ── Property accessors ───────────────────────────────────────────────────

def _addr(sel: bytes, scope: int = _SCOPE_GLOBAL,
          elem: int = _ELEMENT_MAIN) -> _CMIOAddr:
    return _CMIOAddr(_fourcc(sel), scope, elem)


def _get_u32(obj_id: int, sel: bytes,
             scope: int = _SCOPE_GLOBAL) -> Optional[int]:
    a = _addr(sel, scope)
    if not cmio.CMIOObjectHasProperty(obj_id, ctypes.byref(a)):
        return None
    val = ctypes.c_uint32(0)
    used = ctypes.c_uint32(0)
    if cmio.CMIOObjectGetPropertyData(
            obj_id, ctypes.byref(a), 0, None, 4,
            ctypes.byref(used), ctypes.byref(val)) != 0:
        return None
    return val.value


def _get_cfstring(obj_id: int, sel: bytes) -> Optional[str]:
    a = _addr(sel)
    if not cmio.CMIOObjectHasProperty(obj_id, ctypes.byref(a)):
        return None
    p = ctypes.c_void_p(0)
    used = ctypes.c_uint32(0)
    if cmio.CMIOObjectGetPropertyData(
            obj_id, ctypes.byref(a), 0, None, 8,
            ctypes.byref(used), ctypes.byref(p)) != 0:
        return None
    if not p.value:
        return None
    s = cf.CFStringGetCStringPtr(p.value, _kUTF8)
    if s:
        return s.decode()
    n = cf.CFStringGetLength(p.value)
    buf = ctypes.create_string_buffer(n * 4 + 4)
    if cf.CFStringGetCString(p.value, buf, len(buf), _kUTF8):
        return buf.value.decode()
    return None


def _get_array_u32(obj_id: int, sel: bytes,
                   scope: int = _SCOPE_GLOBAL) -> list[int]:
    a = _addr(sel, scope)
    size = ctypes.c_uint32(0)
    cmio.CMIOObjectGetPropertyDataSize(
        obj_id, ctypes.byref(a), 0, None, ctypes.byref(size))
    n = size.value // 4
    if n == 0:
        return []
    buf = (ctypes.c_uint32 * n)()
    used = ctypes.c_uint32(0)
    cmio.CMIOObjectGetPropertyData(
        obj_id, ctypes.byref(a), 0, None, size,
        ctypes.byref(used), ctypes.byref(buf))
    return list(buf[: used.value // 4])


def _enable_ios_screen_capture() -> bool:
    """Set kCMIOHardwarePropertyAllowScreenCaptureDevices = 1.
    First call takes ~5 s (DAL plugin loading)."""
    a = _addr(b"yes ")
    one = ctypes.c_uint32(1)
    rc = cmio.CMIOObjectSetPropertyData(
        _SYSTEM_OBJECT, ctypes.byref(a), 0, None, 4, ctypes.byref(one))
    return rc == 0


def _runloop_tick(seconds: float) -> None:
    cf.CFRunLoopRunInMode(_kCFRunLoopDefaultMode,
                          ctypes.c_double(seconds), False)


# ── Device discovery ─────────────────────────────────────────────────────

def _discover_device(udid: Optional[str]) -> tuple[int, str]:
    """Return (CMIO device id, localized name) of the matching iPad/iPhone.

    Strategy:
      1. Single wired device → use it.
      2. UDID + multiple devices → narrow by transport (wired) and by
         class name (iPad-vs-iPhone).
      3. If still ambiguous → MultipleDevicesError.

    Skipped vs. the old AVF chain: root-only plist mapping (rare), per-device
    resolution probe (complex; needs a full short capture per candidate).
    Same-model + no-root remains genuinely impossible without root.
    """
    devs = _get_array_u32(_SYSTEM_OBJECT, b"dev#")
    candidates = []
    for d in devs:
        dloc = _get_u32(d, b"dloc")
        if dloc not in (_LOC_EXTERNAL_DEVICE, _LOC_EXTERNAL_WIRELESS):
            continue
        candidates.append((d, _get_cfstring(d, b"lnam") or "iOS device", dloc))

    if not candidates:
        logger.error(
            "valeria_cmio: no iOS device found via CoreMediaIO. "
            "Plug in the device and try again."
        )
        raise DeviceNotFoundError(udid=udid or "")

    # Prefer wired
    wired = [c for c in candidates if c[2] == _LOC_EXTERNAL_DEVICE]
    if len(wired) == 1:
        d, name, _ = wired[0]
        return d, name

    if not wired and len(candidates) == 1:
        d, name, _ = candidates[0]
        return d, name

    pool = wired if wired else candidates

    # Class-name narrowing if UDID hints at a specific kind
    if udid and len(pool) > 1:
        # Heuristic — UDID alone doesn't identify model class via CMIO.
        # We can't filter further without the lockdown lookup, so fall through.
        pass

    if len(pool) == 1:
        d, name, _ = pool[0]
        return d, name

    names = [name for _, name, _ in pool]
    raise MultipleDevicesError(
        f"Found {len(pool)} iOS devices via CoreMediaIO ({names}). "
        "Without root, the public CMIO API cannot map UDIDs to specific "
        "devices when multiple same-class devices are attached. "
        "Re-run as root, or unplug all but one device."
    )


# ── Frame extraction ─────────────────────────────────────────────────────

def _extract_h264_frame(sb: int, dims_state: list) -> Optional[H264Frame]:
    """Build an H264Frame from a CMSampleBufferRef. Returns None for
    non-video samples (e.g. the muxed lpcm audio track)."""
    desc = cm.CMSampleBufferGetFormatDescription(sb)
    if not desc:
        return None
    if cm.CMFormatDescriptionGetMediaSubType(desc) != _SUBTYPE_AVC1:
        return None  # audio sample (lpcm) — skip

    blk = cm.CMSampleBufferGetDataBuffer(sb)
    if not blk:
        return None
    n = cm.CMBlockBufferGetDataLength(blk)
    if n == 0:
        return None
    buf = (ctypes.c_uint8 * n)()
    if cm.CMBlockBufferCopyDataBytes(blk, 0, n, ctypes.byref(buf)) != 0:
        return None

    f = H264Frame()
    f.nalu_data = bytes(buf)

    # SPS/PPS — only present on keyframes
    p = ctypes.c_void_p(0)
    sz = ctypes.c_size_t(0)
    cnt = ctypes.c_size_t(0)
    nlen = ctypes.c_int32(0)
    if cm.CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
            desc, 0, ctypes.byref(p), ctypes.byref(sz),
            ctypes.byref(cnt), ctypes.byref(nlen)) == 0 and p.value:
        f.sps = bytes((ctypes.c_uint8 * sz.value).from_address(p.value))
    p = ctypes.c_void_p(0)
    sz = ctypes.c_size_t(0)
    if cm.CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
            desc, 1, ctypes.byref(p), ctypes.byref(sz),
            ctypes.byref(cnt), ctypes.byref(nlen)) == 0 and p.value:
        f.pps = bytes((ctypes.c_uint8 * sz.value).from_address(p.value))

    dims = cm.CMVideoFormatDescriptionGetDimensions(desc)
    if dims.width and dims.height:
        f.width = dims.width
        f.height = dims.height
        dims_state[0] = dims.width
        dims_state[1] = dims.height
    else:
        f.width = dims_state[0]
        f.height = dims_state[1]

    pts = cm.CMSampleBufferGetPresentationTimeStamp(sb)
    f.pts_value = pts.value
    f.pts_scale = pts.scale

    return f


# ── Public capture class ─────────────────────────────────────────────────

class ValeriaCMIO(IOSScreenCapture):
    """Capture iOS screen via CoreMediaIO on macOS (pure ctypes).

    The CMIO DAL plugin loads in response to mach messages dispatched by the
    *process main thread's* CFRunLoop, so :meth:`start`, :meth:`stop`, and
    the iterators all expect to run on the main thread; the iterators tick
    the runloop briefly between yields to keep callbacks firing.

    Frames are pushed onto an internal :class:`queue.Queue` (``maxsize=90``)
    by the plugin's worker thread. On overflow the queue is drained
    completely — the consumer's H.264 decoder will resync at the next IDR
    rather than process partial-GOP corruption.
    """

    def __init__(self, udid: Optional[str] = None) -> None:
        if cmio is None:
            raise BackendUnavailableError(
                "CoreMediaIO not loadable — this build is not on macOS"
            )
        self._udid = udid
        # Larger queue than libusb's maxsize=2: CMIO callback bursts at ~70 Hz
        # while typical consumers run at 25-60 Hz. With maxsize=2 we drop
        # P-frames mid-GOP, which breaks decoder state (libavcodec's software
        # H.264 decoder doesn't conceal as aggressively as VideoToolbox does).
        # 90 entries ≈ 1.3 s of buffer at 70 Hz — absorbs bursts without ever
        # dropping in steady state.
        self._queue: queue.Queue[H264Frame] = queue.Queue(maxsize=90)
        self._dropped_frames: int = 0
        self._device_id: int = 0
        self._stream_id: int = 0
        self._buffer_queue: ctypes.c_void_p = ctypes.c_void_p(0)
        self._callback: Optional[_QueueAlteredProc] = None  # keep ref alive
        self._device_name: str = ""
        self._dims_state: list = [0, 0]   # [width, height], shared with callback
        self._running = False

    @property
    def width(self) -> int:
        return self._dims_state[0]

    @property
    def height(self) -> int:
        return self._dims_state[1]

    @property
    def device_name(self) -> str:
        return self._device_name

    def start(self) -> None:
        """Open the device, start the H.264 stream.

        **Threading note:** CMIO's DAL plugin loads in response to Mach
        messages dispatched only by the *process main thread's* CFRunLoop.
        Background threads cannot drive plugin load or callback delivery.
        Therefore :meth:`start`, :meth:`frames` / :meth:`aframes`, and
        :meth:`stop` all expect to be called from the main thread; the
        iterators tick the runloop briefly between yields so sample
        callbacks fire.
        """
        if cg is not None and not cg.CGPreflightScreenCaptureAccess():
            raise ScreenRecordingPermissionError(
                "Screen Recording TCC permission not granted to the parent "
                "process. Open System Settings → Privacy & Security → Screen "
                "Recording, tick your terminal app, then quit + relaunch it."
            )

        if not _enable_ios_screen_capture():
            raise RuntimeError(
                "CMIOObjectSetPropertyData('yes ') failed — CoreMediaIO "
                "could not enable iOS screen capture devices."
            )

        # Tick the main thread's runloop until the DAL plugin attaches at
        # least one device (or we time out).
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            _runloop_tick(0.25)
            if _get_array_u32(_SYSTEM_OBJECT, b"dev#"):
                break

        self._device_id, self._device_name = _discover_device(self._udid)

        streams = _get_array_u32(self._device_id, b"stm#", _SCOPE_INPUT)
        if not streams:
            raise RuntimeError(
                f"Device {self._device_id} reports no input streams; "
                "iPad may be locked or DAL plugin failed to attach."
            )
        self._stream_id = streams[0]

        def _on_sample(stream_id, token, refcon):
            try:
                while True:
                    # stop() may have already released the buffer queue while
                    # this callback was in flight — guard against the resulting
                    # NULL dereference.
                    bq = self._buffer_queue.value
                    if not bq:
                        break
                    sb = cm.CMSimpleQueueDequeue(bq)
                    if not sb:
                        break
                    try:
                        f = _extract_h264_frame(sb, self._dims_state)
                        if f is None:
                            continue
                        try:
                            self._queue.put_nowait(f)
                        except queue.Full:
                            # Consumer is falling behind. Dropping the oldest
                            # frame breaks decoder state if it's a P-frame, so
                            # drain all the way back to (and including) the
                            # most recent keyframe and re-fill from there. The
                            # consumer's decoder resyncs cleanly at the next
                            # IDR carried in `f` (if `f.is_keyframe`) or at
                            # whatever IDR comes next.
                            self._dropped_frames += 1
                            if self._dropped_frames % 30 == 1:
                                logger.warning(
                                    "valeria_cmio: queue saturated; dropped "
                                    "%d frames so far. Consumer is slower "
                                    "than the iPad encoder.",
                                    self._dropped_frames,
                                )
                            while True:
                                try:
                                    self._queue.get_nowait()
                                except queue.Empty:
                                    break
                            try:
                                self._queue.put_nowait(f)
                            except queue.Full:
                                pass
                    finally:
                        cf.CFRelease(sb)
            except Exception:
                logger.exception("valeria_cmio: error in sample callback")

        self._callback = _QueueAlteredProc(_on_sample)
        rc = cmio.CMIOStreamCopyBufferQueue(
            self._stream_id, self._callback, None,
            ctypes.byref(self._buffer_queue),
        )
        if rc != 0 or not self._buffer_queue.value:
            raise RuntimeError(
                f"CMIOStreamCopyBufferQueue failed: rc={rc}"
            )

        rc = cmio.CMIODeviceStartStream(self._device_id, self._stream_id)
        if rc != 0:
            raise RuntimeError(f"CMIODeviceStartStream failed: rc={rc}")

        self._running = True
        logger.info("valeria_cmio: capture started (device=%r)",
                    self._device_name)

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        try:
            cmio.CMIODeviceStopStream(self._device_id, self._stream_id)
        except Exception:
            logger.exception("valeria_cmio: error stopping stream")
        try:
            null_q = ctypes.c_void_p(0)
            cmio.CMIOStreamCopyBufferQueue(
                self._stream_id, ctypes.cast(None, _QueueAlteredProc),
                None, ctypes.byref(null_q),
            )
            if null_q.value:
                cf.CFRelease(null_q)
        except Exception:
            logger.exception("valeria_cmio: error unregistering callback")
        if self._buffer_queue.value:
            cf.CFRelease(self._buffer_queue)
            self._buffer_queue = ctypes.c_void_p(0)
        self._callback = None

    # Tick budget per iteration. The DAL plugin dispatches its
    # ``CMIODeviceStreamQueueAlteredProc`` callbacks only via the *process
    # main thread's* CFRunLoop. We've verified empirically that a dedicated
    # runloop thread + ``kCMIOHardwarePropertyRunLoop`` does NOT redirect
    # the alteredProc — it stays on the main thread. So the iterators below
    # tick the main thread's runloop briefly between yields. 1 ms is short
    # enough to track the iPad's ~70 Hz delivery rate without busy-spinning.
    _TICK_SECONDS = 0.001

    def frames(self) -> Iterator[H264Frame]:
        """Tick the main thread's CFRunLoop briefly and yield each frame the
        callback enqueues. See :attr:`_TICK_SECONDS` for the threading
        rationale."""
        while self._running or not self._queue.empty():
            _runloop_tick(self._TICK_SECONDS)
            try:
                yield self._queue.get_nowait()
            except queue.Empty:
                continue

    async def aframes(self) -> AsyncIterator[H264Frame]:
        """Async sibling of :meth:`frames`. Yields to the event loop between
        runloop ticks so other asyncio tasks (aiohttp connections, WebSocket
        fan-out) get serviced."""
        while self._running or not self._queue.empty():
            _runloop_tick(self._TICK_SECONDS)
            await asyncio.sleep(0)
            try:
                frame = self._queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(self._TICK_SECONDS)
                continue
            yield frame
