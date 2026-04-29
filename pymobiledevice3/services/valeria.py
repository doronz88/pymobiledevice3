"""Public Valeria capture service — unified iOS H.264 screen capture over USB.

Two implementations (selected by :py:meth:`IOSScreenCapture.create`):

- ``valeria_cmio`` — macOS via CoreMediaIO (pure ctypes, no PyObjC).
- ``valeria_libusb`` — Linux/Windows via libusb claiming the QuickTime alt-config.

Both speak the same QuickTime USB protocol the iPad exposes and emit identical
:class:`H264Frame` objects. Decode/render is the consumer's responsibility.
"""
from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from typing import AsyncIterator, Iterator, Literal, Optional


class DeviceNotFoundError(RuntimeError):
    """No iOS device matched the (optional) UDID, or no device is connected."""


class MultipleDevicesError(RuntimeError):
    """More than one device is present and the requested one cannot be
    disambiguated. Common on macOS without root when two same-model devices
    are attached. Pass ``--udid`` and re-run as root, or unplug all but one."""


class ScreenRecordingPermissionError(RuntimeError):
    """The macOS Screen Recording TCC privilege is not granted to the parent
    process (Terminal/iTerm/VS Code/etc.). Open System Settings → Privacy &
    Security → Screen Recording, tick the terminal app, and fully quit + relaunch."""


class BackendUnavailableError(RuntimeError):
    """The requested backend cannot run on this platform (e.g. ``backend='cmio'``
    on Linux, or ``backend='libusb'`` on macOS where libusb cannot claim Apple
    USB interfaces on macOS 15+)."""


class H264Frame:
    """One H.264 access unit as it came off the device.

    Storage matches the existing ``valeria_libusb`` backend: ``nalu_data`` is
    a concatenation of AVCC-framed NAL units (each prefixed with a 4-byte
    big-endian length). ``sps`` / ``pps`` are carried on keyframes so the
    decoder can re-init mid-stream.
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


_Backend = Literal["auto", "cmio", "libusb"]


class IOSScreenCapture(ABC):
    """Abstract base class. Concrete implementations live in
    ``valeria_cmio`` (macOS) and ``valeria_libusb`` (Linux/Windows)."""

    @classmethod
    def create(cls, udid: Optional[str] = None,
               backend: _Backend = "auto") -> "IOSScreenCapture":
        """Construct the appropriate backend.

        ``backend='auto'`` picks ``cmio`` on macOS and ``libusb`` everywhere
        else. Explicit values raise :class:`BackendUnavailableError` when the
        platform doesn't support them — there is no silent fallback.
        """
        if backend not in ("auto", "cmio", "libusb"):
            raise ValueError(
                f"backend must be one of 'auto', 'cmio', 'libusb' — got {backend!r}"
            )

        is_mac = sys.platform == "darwin"
        if backend == "auto":
            backend = "cmio" if is_mac else "libusb"

        if backend == "cmio":
            if not is_mac:
                raise BackendUnavailableError(
                    "backend='cmio' requires macOS (CoreMediaIO is Apple-only)"
                )
            from pymobiledevice3.services.valeria_cmio import ValeriaCMIO
            return ValeriaCMIO(udid=udid)

        # libusb
        if is_mac:
            raise BackendUnavailableError(
                "backend='libusb' is not usable on macOS — libusb cannot claim "
                "Apple USB interfaces on macOS 15+. Use backend='cmio' instead."
            )
        from pymobiledevice3.services.valeria_libusb import ValeriaLibusb
        return ValeriaLibusb(udid=udid)

    @abstractmethod
    def start(self) -> None:
        """Open the device, negotiate the H.264 stream, begin capture.

        Raises :class:`DeviceNotFoundError`, :class:`MultipleDevicesError`,
        or :class:`ScreenRecordingPermissionError` on the relevant failures."""

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
        """Human-readable device name (e.g. 'iPad Pro')."""

    @abstractmethod
    def frames(self) -> Iterator[H264Frame]:
        """Blocking iterator that yields frames until :meth:`stop` is called.

        ``frames()`` and :meth:`aframes` drain the same internal queue — use
        one or the other per session, not both."""

    @abstractmethod
    def aframes(self) -> AsyncIterator[H264Frame]:
        """Async iterator counterpart of :meth:`frames`. Same queue rules apply."""
