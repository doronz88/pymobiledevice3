"""
AAC-ELD -> s16le 48 kHz stereo PCM decoder via macOS AudioToolbox.

Used by both the browser screen-stream path (screen_stream.py, which
forwards PCM to /audio.bin subscribers) and the VNC path
(vnc_server.py, which feeds PCM to an AudioQueue for local playback).

Why not pyav / ffmpeg's aac_at wrapper? Both go through the same
AudioToolbox under the hood, but the wrappers don't surface
``mFramesPerPacket`` -- AAC-ELD uses 480-sample frames, but if the
converter is left at its 1024-default it interprets each input AU as
a longer block and produces clipped garbage (peak hits int16 max on
every packet). Driving AudioConverter directly lets us pin the field.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Optional

# Standard AudioSpecificConfig for AAC-ELD @ 48 kHz stereo, 480 samples/frame.
# Used as the decompression magic cookie ("dmgc") when constructing the
# AudioConverter from compressed AAC-ELD to LPCM. The 4-byte cookie is what
# the device's encoder advertises, captured from a Mirror handshake.
AAC_ELD_ASC_48K_STEREO_480: bytes = bytes([0xF8, 0xE6, 0x40, 0x00])


class AACELDDecoder:
    """Apple AudioToolbox AAC-ELD -> s16le 48 kHz stereo PCM converter.
    macOS only. Each call to :meth:`decode` consumes ONE AAC-ELD AU and
    emits its 480-sample stereo PCM (1920 bytes)."""

    _DYLIB = "/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox"
    _FRAMES = 480
    _PCM_BYTES = _FRAMES * 4  # stereo s16

    def __init__(self, magic_cookie: bytes = AAC_ELD_ASC_48K_STEREO_480) -> None:
        if sys.platform != "darwin":
            raise RuntimeError("AAC-ELD decode requires macOS (AudioToolbox)")

        def fourcc(s: str) -> int:
            return int.from_bytes(s.encode(), "big")

        class _ASBD(ctypes.Structure):
            _fields_ = [
                ("mSampleRate", ctypes.c_double),
                ("mFormatID", ctypes.c_uint32),
                ("mFormatFlags", ctypes.c_uint32),
                ("mBytesPerPacket", ctypes.c_uint32),
                ("mFramesPerPacket", ctypes.c_uint32),
                ("mBytesPerFrame", ctypes.c_uint32),
                ("mChannelsPerFrame", ctypes.c_uint32),
                ("mBitsPerChannel", ctypes.c_uint32),
                ("mReserved", ctypes.c_uint32),
            ]

        class _AudioBuffer(ctypes.Structure):
            _fields_ = [
                ("mNumberChannels", ctypes.c_uint32),
                ("mDataByteSize", ctypes.c_uint32),
                ("mData", ctypes.c_void_p),
            ]

        class _BufferList(ctypes.Structure):
            _fields_ = [
                ("mNumberBuffers", ctypes.c_uint32),
                ("mBuffers", _AudioBuffer * 1),
            ]

        class _APD(ctypes.Structure):
            _fields_ = [
                ("mStartOffset", ctypes.c_int64),
                ("mVariableFramesInPacket", ctypes.c_uint32),
                ("mDataByteSize", ctypes.c_uint32),
            ]

        self._BufferList = _BufferList
        self._AudioBuffer = _AudioBuffer
        self._APD = _APD

        AT = ctypes.CDLL(self._DYLIB)
        self._AT = AT

        # Source: AAC-ELD, 48 kHz stereo, 480 samples/packet
        src = _ASBD(48000.0, fourcc("aace"), 0, 0, self._FRAMES, 0, 2, 0, 0)
        # Destination: signed 16-bit packed interleaved stereo PCM
        flags = (1 << 2) | (1 << 3)  # kLinearPCMFormatFlagIsSignedInteger | IsPacked
        dst = _ASBD(48000.0, fourcc("lpcm"), flags, 4, 1, 4, 2, 16, 0)

        conv = ctypes.c_void_p()
        res = AT.AudioConverterNew(ctypes.byref(src), ctypes.byref(dst), ctypes.byref(conv))
        if res != 0:
            raise RuntimeError(f"AudioConverterNew failed: 0x{res:x}")
        self._conv = conv

        # Decompression magic cookie = AudioSpecificConfig (AAC-ELD 48k stereo 480)
        AT.AudioConverterSetProperty(conv, fourcc("dmgc"), len(magic_cookie), magic_cookie)

        # InputProc bound once -- holds a reference to the current AU
        self._InputCB = ctypes.CFUNCTYPE(
            ctypes.c_int32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(_BufferList),
            ctypes.POINTER(ctypes.POINTER(_APD)),
            ctypes.c_void_p,
        )
        self._pending: Optional[bytes] = None
        self._pending_buf = None
        self._pending_pd = _APD(0, 0, 0)

        def _input_proc(decoder, ioN, ioData, outPD, _):
            au = self._pending
            if au is None:
                ioN[0] = 0
                return 0
            self._pending = None  # one-shot per FillComplexBuffer call
            self._pending_buf = ctypes.create_string_buffer(au)
            ioN[0] = 1
            ioData[0].mNumberBuffers = 1
            ioData[0].mBuffers[0].mNumberChannels = 2
            ioData[0].mBuffers[0].mDataByteSize = len(au)
            ioData[0].mBuffers[0].mData = ctypes.cast(self._pending_buf, ctypes.c_void_p)
            self._pending_pd = _APD(0, 0, len(au))
            if outPD:
                outPD[0] = ctypes.cast(ctypes.pointer(self._pending_pd), ctypes.POINTER(_APD))
            return 0

        self._cb_obj = _input_proc  # keep python ref
        self._cb = self._InputCB(_input_proc)

        AT.AudioConverterFillComplexBuffer.argtypes = [
            ctypes.c_void_p,
            self._InputCB,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(_BufferList),
            ctypes.c_void_p,
        ]

        self._out_buf = (ctypes.c_uint8 * self._PCM_BYTES)()

    def decode(self, au: bytes) -> bytes:
        """Decode one AAC-ELD AU. Returns 1920 bytes of PCM (480 stereo
        s16 samples = 10 ms @ 48 kHz). Returns empty bytes if the
        converter consumed the AU without emitting (latency frames)."""
        self._pending = au
        n = ctypes.c_uint32(self._FRAMES)
        ad = self._BufferList()
        ad.mNumberBuffers = 1
        ad.mBuffers[0].mNumberChannels = 2
        ad.mBuffers[0].mDataByteSize = self._PCM_BYTES
        ad.mBuffers[0].mData = ctypes.cast(self._out_buf, ctypes.c_void_p)
        res = self._AT.AudioConverterFillComplexBuffer(
            self._conv, self._cb, None, ctypes.byref(n), ctypes.byref(ad), None
        )
        if res != 0:
            raise RuntimeError(f"AudioConverterFillComplexBuffer: 0x{res:x}")
        size = ad.mBuffers[0].mDataByteSize
        return bytes(self._out_buf[:size]) if size else b""

    def __del__(self):
        try:
            if getattr(self, "_conv", None):
                self._AT.AudioConverterDispose(self._conv)
        except Exception:
            pass
