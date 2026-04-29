"""Live-device integration test for the libusb backend.

Skipped on macOS (libusb can't claim Apple USB interfaces) and when no iOS
device is attached.
"""
import sys
import time
import pytest

from pymobiledevice3.services.valeria import H264Frame, IOSScreenCapture


@pytest.mark.skipif(sys.platform == "darwin",
                    reason="libusb cannot claim Apple USB interfaces on macOS")
class TestValeriaLibusb:
    def test_capture_yields_frames(self):
        cap = IOSScreenCapture.create(backend="libusb")
        try:
            cap.start()
        except Exception as e:
            pytest.skip(f"no iOS device attached or activation failed: {e}")

        frames_seen = 0
        keyframes = 0
        deadline = time.monotonic() + 8.0
        try:
            for frame in cap.frames():
                assert isinstance(frame, H264Frame)
                assert frame.nalu_data
                frames_seen += 1
                if frame.is_keyframe:
                    keyframes += 1
                if frames_seen >= 10 or time.monotonic() > deadline:
                    break
        finally:
            cap.stop()

        assert frames_seen >= 5, (
            f"expected at least 5 frames in 8 s, got {frames_seen}"
        )
        assert keyframes >= 1, "no keyframe (SPS/PPS) seen — decoder couldn't init"
        assert cap.width > 0 and cap.height > 0
