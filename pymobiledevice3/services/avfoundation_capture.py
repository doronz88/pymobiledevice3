"""
AVFoundation-based iOS screen capture (macOS only).

Uses CoreMediaIO to expose the iOS device's screen as an AVCaptureDevice —
the same mechanism QuickTime Player uses.  Delivers decoded video frames at
30-60 fps over the existing USB connection.

Requirements (all optional — the module degrades gracefully):
    pip install pyobjc-framework-AVFoundation pyobjc-framework-CoreMediaIO pyobjc-framework-Quartz

If PyObjC is not installed the public entry point ``AVFoundationCapture.start()``
returns *False* and the caller should fall back to another capture method.

Camera TCC
----------
macOS requires Camera permission to access iOS capture devices via CoreMediaIO.
On first use, ``requestAccessForMediaType:`` triggers a system dialog asking
the user to grant Camera access to the parent terminal app (Terminal.app,
iTerm2, etc.).  Once granted, all processes launched from that terminal inherit
the permission automatically.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import logging
import platform
import queue
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PyObjC imports — optional, macOS only
# ---------------------------------------------------------------------------

_PYOBJC = False
try:
    if platform.system() == "Darwin":
        import objc as _objc  # noqa: F401
        import AVFoundation as _AVF  # noqa: F401
        import CoreMedia as _CM  # noqa: F401
        import Quartz as _Q  # noqa: F401
        from Foundation import NSObject as _NSObject, NSRunLoop as _NSRunLoop, NSDate as _NSDate  # noqa: F401
        _PYOBJC = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# CoreMediaIO property call (pure ctypes — no PyObjC needed)
# ---------------------------------------------------------------------------


def _enable_ios_screen_capture() -> bool:
    """Set kCMIOHardwarePropertyAllowScreenCaptureDevices = 1.

    Without this call iOS devices are invisible to AVFoundation.
    This is a **per-process** setting.
    """
    path = ctypes.util.find_library("CoreMediaIO")
    if not path:
        return False
    try:
        cmio = ctypes.cdll.LoadLibrary(path)
    except OSError:
        return False

    class _Addr(ctypes.Structure):
        _fields_ = [
            ("mSelector", ctypes.c_uint32),
            ("mScope", ctypes.c_uint32),
            ("mElement", ctypes.c_uint32),
        ]

    addr = _Addr(
        0x79657320,  # 'yes ' — kCMIOHardwarePropertyAllowScreenCaptureDevices
        0x676C6F62,  # 'glob' — kCMIOObjectPropertyScopeGlobal
        0,           # kCMIOObjectPropertyElementMain
    )
    allow = ctypes.c_uint32(1)
    rc = cmio.CMIOObjectSetPropertyData(
        ctypes.c_uint32(1),           # kCMIOObjectSystemObject
        ctypes.byref(addr),
        ctypes.c_uint32(0), None,     # qualifier
        ctypes.c_uint32(4),           # dataSize
        ctypes.byref(allow),
    )
    if rc != 0:
        logger.debug("CMIOObjectSetPropertyData returned %d", rc)
    return rc == 0


def _run_loop_tick(seconds: float = 1.0) -> None:
    """Spin the NSRunLoop so CoreMediaIO can process Mach messages
    (DAL plugin loading, device detection, etc.)."""
    _NSRunLoop.currentRunLoop().runUntilDate_(
        _NSDate.dateWithTimeIntervalSinceNow_(seconds)
    )


def _get_usb_product_name(udid: str) -> Optional[str]:
    """Look up the USB product name for an iOS device by its UDID.

    The USB serial number of iOS devices matches the UDID exposed by usbmux.
    Returns the USB product string (e.g. "iPad", "iPhone") or *None*.
    """
    try:
        import usb.core
        for dev in usb.core.find(find_all=True, idVendor=0x05AC):  # Apple
            try:
                if dev.serial_number == udid:
                    return dev.product
            except Exception:
                continue
    except ImportError:
        pass
    return None


def _discover_ios_device(udid: Optional[str] = None, timeout: float = 5.0):
    """Enable CMIO, spin the run loop, and return an iOS AVCaptureDevice.

    If *udid* is given, looks up the USB product name for that UDID and
    matches it against AVFoundation's ``localizedName()``.  When only one
    iOS capture device is found, returns it directly regardless of name.

    Returns ``None`` if no device is found or if multiple same-name devices
    are present and cannot be disambiguated (the caller should fall back to
    accessibility-based capture which supports UDID selection natively).
    """
    if not _enable_ios_screen_capture():
        return None

    # Resolve UDID → USB product name (e.g. "iPad") for matching
    target_name = _get_usb_product_name(udid) if udid else None
    if udid and target_name:
        logger.debug("AVFoundation: UDID %s…%s → USB product '%s'",
                      udid[:8], udid[-4:], target_name)

    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _run_loop_tick(1.0)
        discovery = _AVF.AVCaptureDeviceDiscoverySession \
            .discoverySessionWithDeviceTypes_mediaType_position_(
                [_AVF.AVCaptureDeviceTypeExternal],
                _AVF.AVMediaTypeMuxed,
                _AVF.AVCaptureDevicePositionUnspecified,
            )
        devices = list(discovery.devices() or [])
        if not devices:
            continue
        if len(devices) == 1:
            return devices[0]
        # Multiple devices — try to match by USB product name
        if target_name:
            matches = [d for d in devices
                       if str(d.localizedName() or "") == target_name]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                # Multiple devices with same name — AVFoundation cannot
                # disambiguate (no UDID exposed through CMIO).  Return
                # None so the caller falls back to accessibility capture
                # which targets the correct device via the service provider.
                logger.info(
                    "AVFoundation: %d devices named '%s' — cannot match "
                    "by UDID.  Falling back to accessibility capture.",
                    len(matches), target_name)
                return None
        # No UDID given — use first device
        if not udid:
            names = [str(d.localizedName()) for d in devices]
            logger.warning("AVFoundation: multiple devices %s — pass "
                           "--udid to select a specific device.", names)
            return devices[0]
        # UDID given but no product name resolved — can't match
        return None
    return None


# ---------------------------------------------------------------------------
# Camera TCC helper
# ---------------------------------------------------------------------------


def _request_camera_access() -> bool:
    """Request Camera TCC access, blocking until the user responds.

    On macOS, Camera permission is attributed to the **parent terminal**
    (Terminal.app, iTerm2, etc.).  When ``requestAccessForMediaType:`` is
    called for the first time, macOS shows a system dialog asking the user
    to grant Camera access to the terminal app.  Once granted, all future
    processes launched from that terminal inherit the permission.
    """
    if not _PYOBJC:
        return False

    status = _AVF.AVCaptureDevice.authorizationStatusForMediaType_(
        _AVF.AVMediaTypeVideo
    )
    if status == 3:  # already authorized
        return True
    if status == 2:  # denied — user must re-enable in System Settings
        return False

    # status 0 (notDetermined) — trigger the system prompt
    import threading
    event = threading.Event()
    granted_box: list[bool] = [False]

    def handler(granted: bool) -> None:
        granted_box[0] = granted
        event.set()

    logger.info("Requesting Camera permission (grant access to your terminal app)…")
    _AVF.AVCaptureDevice.requestAccessForMediaType_completionHandler_(
        _AVF.AVMediaTypeVideo, handler
    )
    event.wait(timeout=120)  # wait up to 2 minutes for user to respond
    return granted_box[0]


# ---------------------------------------------------------------------------
# Dispatch queue helper
# ---------------------------------------------------------------------------


def _create_dispatch_queue():
    """Create a serial GCD queue for AVFoundation frame callbacks."""
    # On macOS 26+ libdispatch.dylib is in the dyld shared cache and cannot be
    # loaded by path.  The symbols are already in every process, so we load from
    # the default symbol space with ``ctypes.CDLL(None)``.
    try:
        lib = ctypes.CDLL(None)
        lib.dispatch_queue_create.restype = ctypes.c_void_p
        lib.dispatch_queue_create.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        ptr = lib.dispatch_queue_create(b"com.pymobiledevice3.avfcapture", None)
        if not ptr:
            return None
        # dispatch_queue_t is an ObjC object since macOS 10.8
        return _objc.objc_object(c_void_p=ptr)
    except Exception as exc:
        logger.debug("dispatch_queue_create failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# ObjC sample-buffer delegate
# ---------------------------------------------------------------------------

if _PYOBJC:
    class _FrameDelegate(_NSObject):
        """AVCaptureVideoDataOutputSampleBufferDelegate that converts frames to JPEG.

        Uses a persistent CIContext for GPU-accelerated JPEG encoding, bypassing
        the slower NSBitmapImageRep intermediate path.
        """

        def initWithQueue_quality_(self, frame_queue: queue.Queue, jpeg_quality: float):
            self = _objc.super(_FrameDelegate, self).init()
            if self is not None:
                self._q = frame_queue
                self._ci_ctx = _Q.CIContext.context()
                self._colorspace = _Q.CGColorSpaceCreateDeviceRGB()
                self._jpeg_opts = {
                    _Q.kCGImageDestinationLossyCompressionQuality: jpeg_quality,
                }
            return self

        def captureOutput_didOutputSampleBuffer_fromConnection_(
            self, output, sample_buffer, connection
        ):
            try:
                pixel_buf = _CM.CMSampleBufferGetImageBuffer(sample_buffer)
                if pixel_buf is None:
                    return
                ci = _Q.CIImage.imageWithCVPixelBuffer_(pixel_buf)
                if ci is None:
                    return
                data = self._ci_ctx.JPEGRepresentationOfImage_colorSpace_options_(
                    ci, self._colorspace, self._jpeg_opts,
                )
                if data is None:
                    return
                jpeg = bytes(data)
                # Drop stale frame if queue is full
                try:
                    self._q.get_nowait()
                except queue.Empty:
                    pass
                self._q.put_nowait(jpeg)
            except Exception:
                pass  # hot path — never log per-frame


# ---------------------------------------------------------------------------
# Public capture class
# ---------------------------------------------------------------------------


class AVFoundationCapture:
    """Capture iOS screen via AVFoundation / CoreMediaIO.

    Usage::

        cap = AVFoundationCapture()
        if cap.start():
            while True:
                jpeg = await cap.get_frame()
                ...
            cap.stop()
    """

    def __init__(self, jpeg_quality: float = 0.6, udid: Optional[str] = None) -> None:
        self._jpeg_quality = jpeg_quality
        self._udid = udid
        self._queue: queue.Queue[bytes] = queue.Queue(maxsize=2)
        self._session: object = None
        self._delegate: object = None  # prevent GC
        self._running = False
        self.width: int = 0
        self.height: int = 0
        self.device_name: str = ""

    def start(self) -> bool:
        """Find an iOS device over USB and start capturing. Returns *True* on success."""
        if not _PYOBJC:
            logger.debug("PyObjC not available — AVFoundation capture disabled")
            return False

        # ---- Camera TCC ----
        if not _request_camera_access():
            logger.info("AVFoundation: Camera permission not granted. "
                        "Enable Camera access for your terminal app in "
                        "System Settings → Privacy & Security → Camera.")
            return False

        # ---- discover iOS device (spins the run loop for plugin loading) ----
        device = _discover_ios_device(udid=self._udid, timeout=8.0)
        if device is None:
            logger.info("AVFoundation: no iOS device found "
                        "(is it connected via USB and trusted?)")
            return False

        self.device_name = str(device.localizedName() or "iOS device")
        logger.info("AVFoundation: found '%s'", self.device_name)

        # ---- resolution ----
        try:
            desc = device.activeFormat().formatDescription()
            dims = _CM.CMVideoFormatDescriptionGetDimensions(desc)
            self.width = dims.width
            self.height = dims.height
            logger.info("AVFoundation: %dx%d", self.width, self.height)
        except Exception:
            pass

        # ---- session ----
        session = _AVF.AVCaptureSession.alloc().init()

        result = _AVF.AVCaptureDeviceInput.deviceInputWithDevice_error_(device, None)
        inp = result[0] if isinstance(result, tuple) else result
        if inp is None or not session.canAddInput_(inp):
            logger.error("AVFoundation: cannot create device input "
                         "(Camera permission may be required)")
            return False
        session.addInput_(inp)

        out = _AVF.AVCaptureVideoDataOutput.alloc().init()
        out.setAlwaysDiscardsLateVideoFrames_(True)
        out.setVideoSettings_({
            str(_Q.kCVPixelBufferPixelFormatTypeKey):
                int(_Q.kCVPixelFormatType_32BGRA),
        })

        delegate = _FrameDelegate.alloc().initWithQueue_quality_(
            self._queue, self._jpeg_quality
        )

        dq = _create_dispatch_queue()
        if dq is None:
            logger.error("AVFoundation: cannot create dispatch queue")
            return False
        out.setSampleBufferDelegate_queue_(delegate, dq)

        if not session.canAddOutput_(out):
            logger.error("AVFoundation: cannot add video output")
            return False
        session.addOutput_(out)

        session.startRunning()
        self._session = session
        self._delegate = delegate
        self._running = True
        logger.info("AVFoundation: capture started")
        return True

    def stop(self) -> None:
        """Stop the capture session."""
        if self._session is not None and self._running:
            self._session.stopRunning()
            self._running = False
            logger.info("AVFoundation: capture stopped")

    async def get_frame(self, timeout: float = 0.5) -> Optional[bytes]:
        """Await the next JPEG frame. Returns ``None`` on timeout."""
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(
                None, lambda: self._queue.get(timeout=timeout),
            )
        except queue.Empty:
            return None
