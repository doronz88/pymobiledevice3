import pytest

from pymobiledevice3.exceptions import DevicePathError
from pymobiledevice3.safe_paths import device_file_path, resolve_device_path, validate_device_filename


@pytest.mark.parametrize(
    "name",
    [
        "/tmp/file",
        "../file",
        "a/../file",
        r"C:\file",
        "C:file",
        r"\\host\share",
        r"a\..\file",
        r"..\file",
        "a\0b",
    ],
)
def test_rejects_absolute_and_escaping_paths(tmp_path, name):
    with pytest.raises(DevicePathError):
        resolve_device_path(tmp_path, name)


@pytest.mark.parametrize("name", ["device/00/file", "./logs/file", "file:stream", "with space", "NUL"])
def test_accepts_relative_paths(tmp_path, name):
    assert resolve_device_path(tmp_path, name) == tmp_path / name


def test_resolves_root_itself(tmp_path):
    assert resolve_device_path(tmp_path, ".") == tmp_path


@pytest.mark.parametrize("target", ["outside", "missing"])
def test_rejects_links_that_leave_the_root(tmp_path, target):
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(tmp_path / target)
    with pytest.raises(DevicePathError):
        resolve_device_path(root, "link/file")


def test_accepts_links_that_stay_inside_the_root(tmp_path):
    (tmp_path / "inside").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "inside")
    # the plain join is returned, so callers act on the link rather than on its target
    assert resolve_device_path(tmp_path, "link/file") == tmp_path / "link" / "file"


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", r"a\b", "/file", "C:file", "a\0b"])
def test_rejects_invalid_filename(name):
    with pytest.raises(DevicePathError):
        validate_device_filename(name)


@pytest.mark.parametrize("name", ["00008110-001234567890001E", "fe80::1c2b:3aff:fe4d:5e6f%en0", "192.168.1.5"])
def test_accepts_identifiers(name):
    assert validate_device_filename(name) == name


def test_device_file_path(tmp_path):
    assert device_file_path(tmp_path, "fe80::1%en0", ".plist") == tmp_path / "fe80::1%en0.plist"
    with pytest.raises(DevicePathError):
        device_file_path(tmp_path, "../victim", ".plist")
