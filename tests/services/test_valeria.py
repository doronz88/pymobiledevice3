"""Unit tests for the public valeria types. No hardware required."""
import pytest

from pymobiledevice3.services.valeria import (
    BackendUnavailableError,
    DeviceNotFoundError,
    H264Frame,
    IOSScreenCapture,
    MultipleDevicesError,
    ScreenRecordingPermissionError,
)


class TestH264Frame:
    def test_default_construction(self):
        f = H264Frame()
        assert f.nalu_data == b""
        assert f.sps == b""
        assert f.pps == b""
        assert f.width == 0
        assert f.height == 0
        assert f.pts_value == 0
        assert f.pts_scale == 0

    def test_is_keyframe_true_when_both_parameter_sets_present(self):
        f = H264Frame()
        f.sps = b"\x67\x42"
        f.pps = b"\x68\xce"
        assert f.is_keyframe is True

    def test_is_keyframe_false_when_either_missing(self):
        f = H264Frame()
        f.sps = b"\x67\x42"
        assert f.is_keyframe is False
        f.sps = b""
        f.pps = b"\x68\xce"
        assert f.is_keyframe is False

    def test_pts_ns_conversion(self):
        f = H264Frame()
        f.pts_value = 1500
        f.pts_scale = 1_000_000   # microseconds
        assert f.pts_ns == 1_500_000  # 1.5 ms in ns

    def test_pts_ns_zero_scale_returns_zero(self):
        f = H264Frame()
        f.pts_value = 12345
        f.pts_scale = 0
        assert f.pts_ns == 0   # avoid ZeroDivisionError on uninitialized frames

    def test_to_annex_b_includes_parameter_sets_for_keyframe(self):
        f = H264Frame()
        f.sps = b"\x67\x42\x00\x1f"
        f.pps = b"\x68\xce\x06\xe2"
        f.nalu_data = b"\x00\x00\x00\x04\x65\x88\x84\x00"  # one 4-byte NAL
        out = f.to_annex_b()
        assert out.startswith(b"\x00\x00\x00\x01\x67\x42\x00\x1f")  # SPS
        assert b"\x00\x00\x00\x01\x68\xce\x06\xe2" in out          # PPS
        assert out.endswith(b"\x00\x00\x00\x01\x65\x88\x84\x00")   # NAL


class TestExceptions:
    def test_all_inherit_from_runtime_error(self):
        for cls in (DeviceNotFoundError, MultipleDevicesError,
                    ScreenRecordingPermissionError, BackendUnavailableError):
            assert issubclass(cls, RuntimeError)


class TestCreateFactoryDispatch:
    """create() picks the right backend by platform; full lifecycle tested
    against hardware in test_valeria_cmio.py / test_valeria_libusb.py."""

    def test_cmio_explicit_on_non_mac_raises_backend_unavailable(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        with pytest.raises(BackendUnavailableError, match="cmio.*macOS"):
            IOSScreenCapture.create(backend="cmio")

    def test_libusb_explicit_on_mac_raises_backend_unavailable(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        with pytest.raises(BackendUnavailableError, match="libusb.*macOS"):
            IOSScreenCapture.create(backend="libusb")

    def test_unknown_backend_value_raises_value_error(self):
        with pytest.raises(ValueError, match="backend"):
            IOSScreenCapture.create(backend="quicktime")  # type: ignore[arg-type]
