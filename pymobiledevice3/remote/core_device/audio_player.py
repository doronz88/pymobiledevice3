"""
CoreAudio AudioQueue PCM playback (macOS only, pure ctypes).

Used by :mod:`vnc_server` to play AAC-ELD-decoded PCM through the host
Mac's speakers while the user views the device screen via VNC. RFB has
no audio of its own; the host-local playback is the same pattern macOS
Screen Sharing.app uses for audio over its own private encodings.

Lossy on backpressure: :meth:`AudioQueuePlayer.play` drops the PCM if
no free AudioQueueBuffer is available rather than blocking. Audio
glitches are preferable to stalling the asyncio RTP recv loop.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import logging
import queue as _queue
from ctypes import (
    CFUNCTYPE,
    POINTER,
    Structure,
    byref,
    c_double,
    c_int32,
    c_uint32,
    c_void_p,
)

logger = logging.getLogger(__name__)

at = ctypes.CDLL(ctypes.util.find_library("AudioToolbox"))

OSStatus = c_int32


class _ASBD(Structure):
    _fields_ = [
        ("mSampleRate", c_double),
        ("mFormatID", c_uint32),
        ("mFormatFlags", c_uint32),
        ("mBytesPerPacket", c_uint32),
        ("mFramesPerPacket", c_uint32),
        ("mBytesPerFrame", c_uint32),
        ("mChannelsPerFrame", c_uint32),
        ("mBitsPerChannel", c_uint32),
        ("mReserved", c_uint32),
    ]


class _AudioQueueBuffer(Structure):
    _fields_ = [
        ("mAudioDataBytesCapacity", c_uint32),
        ("mAudioData", c_void_p),
        ("mAudioDataByteSize", c_uint32),
        ("mUserData", c_void_p),
        ("mPacketDescriptionCapacity", c_uint32),
        ("mPacketDescriptions", c_void_p),
        ("mPacketDescriptionCount", c_uint32),
    ]


_AudioQueueBufferRef = POINTER(_AudioQueueBuffer)
_AudioQueueRef = c_void_p

_AudioQueueOutputCallback = CFUNCTYPE(None, c_void_p, _AudioQueueRef, _AudioQueueBufferRef)

at.AudioQueueNewOutput.restype = OSStatus
at.AudioQueueNewOutput.argtypes = [
    POINTER(_ASBD),
    _AudioQueueOutputCallback,
    c_void_p,
    c_void_p,  # CFRunLoopRef -- NULL = AudioQueue picks an internal thread
    c_void_p,  # CFStringRef
    c_uint32,
    POINTER(_AudioQueueRef),
]
at.AudioQueueAllocateBuffer.restype = OSStatus
at.AudioQueueAllocateBuffer.argtypes = [_AudioQueueRef, c_uint32, POINTER(_AudioQueueBufferRef)]
at.AudioQueueEnqueueBuffer.restype = OSStatus
at.AudioQueueEnqueueBuffer.argtypes = [_AudioQueueRef, _AudioQueueBufferRef, c_uint32, c_void_p]
at.AudioQueueStart.restype = OSStatus
at.AudioQueueStart.argtypes = [_AudioQueueRef, c_void_p]
at.AudioQueueStop.restype = OSStatus
at.AudioQueueStop.argtypes = [_AudioQueueRef, c_uint32]
at.AudioQueueDispose.restype = OSStatus
at.AudioQueueDispose.argtypes = [_AudioQueueRef, c_uint32]


class AudioQueuePlayer:
    """Output-side AudioQueue wrapper for interleaved s16le PCM.

    Defaults to 48 kHz stereo with eight 1920-byte buffers (~80 ms of
    headroom), which matches the AAC-ELD pipeline used by the device's
    audio stream (480 stereo samples / 10 ms per packet).
    """

    def __init__(
        self,
        *,
        sample_rate: int = 48000,
        channels: int = 2,
        buffer_byte_size: int = 1920,
        # 24 buffers x 1920 bytes = 240 ms of headroom. The previous
        # default of 8 buffers (80 ms) dropped ~5 % of packets steadily
        # under real device load: RTP audio arrives in UDP bursts, and
        # an 80 ms pool isn't big enough to absorb the bursts when the
        # AudioQueue callback thread is contending with the asyncio
        # thread for the GIL. Audible "choppy". The pool only matters
        # for absorbing jitter -- AudioQueue drains at exactly the
        # source rate, so steady-state in-flight count stays small and
        # latency doesn't track pool size.
        num_buffers: int = 24,
    ) -> None:
        fmt = _ASBD(
            mSampleRate=float(sample_rate),
            mFormatID=int.from_bytes(b"lpcm", "big"),
            mFormatFlags=(1 << 2) | (1 << 3),  # SignedInteger | IsPacked
            mBytesPerPacket=channels * 2,
            mFramesPerPacket=1,
            mBytesPerFrame=channels * 2,
            mChannelsPerFrame=channels,
            mBitsPerChannel=16,
            mReserved=0,
        )

        self._aq = _AudioQueueRef(0)
        # Keep Python refs alive for the lifetime of the queue: the
        # callback CFUNCTYPE thunk and the per-buffer pointers, plus
        # the close-side flag the callback checks.
        self._cb = _AudioQueueOutputCallback(self._on_buffer_consumed)
        st = at.AudioQueueNewOutput(byref(fmt), self._cb, None, None, None, 0, byref(self._aq))
        if st != 0:
            raise RuntimeError(f"AudioQueueNewOutput failed: OSStatus={st}")

        self._free: _queue.Queue = _queue.Queue()
        self._all_buffers: list[_AudioQueueBufferRef] = []
        for _ in range(num_buffers):
            buf_ref = _AudioQueueBufferRef()
            st = at.AudioQueueAllocateBuffer(self._aq, buffer_byte_size, byref(buf_ref))
            if st != 0:
                raise RuntimeError(f"AudioQueueAllocateBuffer failed: OSStatus={st}")
            self._all_buffers.append(buf_ref)
            self._free.put(buf_ref)
        self._buffer_byte_size = buffer_byte_size
        self._closed = False
        self._dropped = 0
        self._played = 0
        self._enqueue_errors = 0

        st = at.AudioQueueStart(self._aq, None)
        if st != 0:
            raise RuntimeError(f"AudioQueueStart failed: OSStatus={st}")
        latency_ms = num_buffers * buffer_byte_size * 1000 / (sample_rate * channels * 2)
        logger.info(
            "AudioQueuePlayer started: %d Hz x %d ch, %d buffers x %d bytes (%.0f ms total)",
            sample_rate,
            channels,
            num_buffers,
            buffer_byte_size,
            latency_ms,
        )

    def _on_buffer_consumed(self, user, aq, buf_ref):
        # Called on AudioQueue's internal thread when it's done with
        # this buffer. queue.Queue is thread-safe.
        if not self._closed:
            self._free.put(buf_ref)

    def play(self, pcm: bytes) -> None:
        """Enqueue ``pcm`` for playback. Drops on backpressure."""
        if self._closed or not pcm:
            return
        try:
            buf_ref = self._free.get_nowait()
        except _queue.Empty:
            self._dropped += 1
            return
        buf = buf_ref.contents
        n = min(len(pcm), self._buffer_byte_size)
        ctypes.memmove(buf.mAudioData, pcm, n)
        buf.mAudioDataByteSize = n
        st = at.AudioQueueEnqueueBuffer(self._aq, buf_ref, 0, None)
        if st != 0:
            self._enqueue_errors += 1
            if self._enqueue_errors <= 3 or self._enqueue_errors % 100 == 0:
                logger.warning(
                    "AudioQueueEnqueueBuffer failed: OSStatus=%d (%d total)",
                    st,
                    self._enqueue_errors,
                )
            # Queue may have been stopped behind our back; recycle the
            # buffer so we don't leak it out of the pool.
            self._free.put(buf_ref)
            return
        self._played += 1

    def stats(self) -> tuple[int, int, int]:
        """``(played, dropped, enqueue_errors)`` since construction."""
        return self._played, self._dropped, self._enqueue_errors

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            at.AudioQueueStop(self._aq, 1)  # immediate
        with contextlib.suppress(Exception):
            at.AudioQueueDispose(self._aq, 1)

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close()
