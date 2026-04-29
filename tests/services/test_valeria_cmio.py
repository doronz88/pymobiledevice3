"""Live-device integration test for the CoreMediaIO backend.

Skipped off macOS and when no iOS device is attached or Screen Recording
TCC is missing.
"""
import sys
import time
import pytest

from pymobiledevice3.services.valeria import H264Frame, IOSScreenCapture


@pytest.mark.skipif(sys.platform != "darwin", reason="CMIO is macOS only")
class TestValeriaCMIO:
    def test_capture_yields_frames(self):
        cap = IOSScreenCapture.create(backend="cmio")
        try:
            cap.start()
        except Exception as e:
            pytest.skip(f"no iOS device, TCC missing, or activation failed: {e}")

        frames_seen = 0
        keyframes = 0
        deadline = time.monotonic() + 12.0
        try:
            for frame in cap.frames():
                assert isinstance(frame, H264Frame)
                assert frame.nalu_data
                frames_seen += 1
                if frame.is_keyframe:
                    keyframes += 1
                if frames_seen >= 30 or time.monotonic() > deadline:
                    break
        finally:
            cap.stop()

        assert frames_seen >= 10, (
            f"expected ≥10 frames, got {frames_seen}"
        )
        assert keyframes >= 1, "no keyframe (SPS/PPS) seen — decoder couldn't init"
        assert cap.width > 0 and cap.height > 0
