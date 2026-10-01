"""Public Valeria capture service - iOS H.264 screen capture over USB.

Currently macOS-only via :mod:`valeria_cmio` (CoreMediaIO, pure ctypes - no
PyObjC). Speaks the QuickTime USB protocol the device exposes and emits
:class:`H264Frame` objects. Decode/render is the consumer's responsibility.
"""
from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Callable, Iterator, Literal, Optional

from pymobiledevice3.exceptions import (
    BackendUnavailableError,
    DeviceNotFoundError,
    MultipleDevicesError,
    ScreenRecordingPermissionError,
)

# Re-exported for callers that import them via the service module.
__all__ = [
    "BackendUnavailableError",
    "DeviceNotFoundError",
    "H264Frame",
    "ValeriaScreenCapture",
    "MultipleDevicesError",
    "ScreenRecordingPermissionError",
]


class H264Frame:
    """One H.264 access unit as it came off the device.

    ``nalu_data`` is a concatenation of AVCC-framed NAL units (each
    prefixed with a 4-byte big-endian length). ``sps`` / ``pps`` are
    carried on keyframes so the decoder can re-init mid-stream.
    """

    __slots__ = ("nalu_data", "sps", "pps", "width", "height",
                 "pts_value", "pts_scale")

    def __init__(self) -> None:
        self.nalu_data: bytes = b""
        self.sps: bytes = b""
        self.pps: bytes = b""
        self.width: int = 0
        self.height: int = 0
        self.pts_value: int = 0
        self.pts_scale: int = 0

    @property
    def is_keyframe(self) -> bool:
        """A frame is treated as a keyframe iff both SPS and PPS are present
        (the iOS encoder emits parameter sets only with IDR frames)."""
        return bool(self.sps and self.pps)

    @property
    def pts_ns(self) -> int:
        """Presentation timestamp in nanoseconds, derived from the CMTime
        value/scale pair. Returns 0 if scale is unset."""
        if self.pts_scale == 0:
            return 0
        return self.pts_value * 1_000_000_000 // self.pts_scale

    def to_annex_b(self) -> bytes:
        """Return Annex-B-framed bytes (``0x00000001`` start codes), with
        SPS/PPS prepended when present. Suitable for piping to FFmpeg or
        feeding a hardware decoder."""
        start_code = b"\x00\x00\x00\x01"
        parts: list[bytes] = []
        if self.sps:
            parts.append(start_code + self.sps)
        if self.pps:
            parts.append(start_code + self.pps)
        pos = 0
        data = self.nalu_data
        while pos + 4 <= len(data):
            nalu_len = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            if nalu_len <= 0 or pos + nalu_len > len(data):
                break
            parts.append(start_code + data[pos:pos + nalu_len])
            pos += nalu_len
        return b"".join(parts)


Backend = Literal["auto", "cmio"]


class ValeriaScreenCapture(ABC):
    """Abstract base class. The macOS implementation lives in
    :mod:`valeria_cmio`.

    Concrete implementations push :class:`H264Frame` objects onto an
    internal bounded queue (capacity 90) and drain the queue on overflow
    so consumers resync at the next IDR.
    """

    @classmethod
    def create(cls, udid: Optional[str] = None,
               backend: Backend = "auto") -> "ValeriaScreenCapture":
        """Construct the appropriate backend.

        :param udid: Match a specific iDevice by UDID. ``None`` selects
            the sole attached device (raises :class:`MultipleDevicesError`
            if there are multiple).
        :param backend: ``"auto"`` (default) or ``"cmio"``. Both currently
            resolve to the CoreMediaIO backend; the parameter is reserved
            for forward-compat as additional backends are added.

        Raises :class:`BackendUnavailableError` on non-macOS platforms.
        """
        if backend not in ("auto", "cmio"):
            raise ValueError(
                f"backend must be one of 'auto', 'cmio'; got {backend!r}"
            )

        if sys.platform != "darwin":
            raise BackendUnavailableError(
                "ValeriaScreenCapture currently requires macOS "
                "(CoreMediaIO is Apple-only)"
            )
        try:
            from pymobiledevice3.services.valeria_cmio import ValeriaCMIO
        except ImportError as exc:
            raise BackendUnavailableError(
                f"cmio backend module not available: {exc}"
            ) from exc
        return ValeriaCMIO(udid=udid)

    @abstractmethod
    def start(self) -> None:
        """Open the device, negotiate the H.264 stream, begin capture.

        Raises :class:`DeviceNotFoundError`, :class:`MultipleDevicesError`,
        or :class:`ScreenRecordingPermissionError` on the relevant failures.

        On macOS the CoreMediaIO backend blocks the calling thread for up to
        ~10 s the first time it runs (DAL plugin load). When calling from
        inside an asyncio context, use :meth:`astart` so the event loop
        stays responsive during the wait."""

    async def astart(self) -> None:
        """Async-friendly :meth:`start`. The default just calls
        :meth:`start` synchronously - backends with a long blocking startup
        (CMIO) override this to yield to the event loop between internal
        waits so other coroutines (lockdown keep-alives etc.) keep running."""
        self.start()

    @abstractmethod
    def stop(self) -> None:
        """Close the stream and release device resources."""

    @property
    @abstractmethod
    def width(self) -> int:
        """Stream width in pixels. 0 until the first frame is parsed."""

    @property
    @abstractmethod
    def height(self) -> int:
        """Stream height in pixels. 0 until the first frame is parsed."""

    @property
    @abstractmethod
    def device_name(self) -> str:
        """Human-readable device name."""

    @abstractmethod
    def frames(self) -> Iterator[H264Frame]:
        """Blocking iterator that yields frames until :meth:`stop` is called.

        ``frames()`` and :meth:`aframes` drain the same internal queue - use
        one or the other per session, not both."""

    @abstractmethod
    def aframes(self) -> AsyncIterator[H264Frame]:
        """Async iterator counterpart of :meth:`frames`. Same queue rules apply."""

    def run(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Invoke ``fn(*args, **kwargs)`` under whatever threading context
        this backend prefers, returning ``fn``'s return value.

        The CoreMediaIO backend on macOS commandeers the calling thread to
        drive ``CFRunLoopRun()`` continuously while ``fn`` runs on a worker
        thread - required because the iOS DAL plugin dispatches its
        callbacks only via the main thread's CFRunLoop. ``fn`` can iterate
        :meth:`frames` / :meth:`aframes` event-driven (no polling) inside
        this wrapper.

        Use it any time you'd loop over frames in a long-running program::

            cap.start()
            try:
                cap.run(lambda: [process(f) for f in cap.frames()])
            finally:
                cap.stop()
        """
        return fn(*args, **kwargs)
