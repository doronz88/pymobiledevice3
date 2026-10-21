import pytest

from pymobiledevice3 import common
from pymobiledevice3.osu.os_utils import OsUtils
from pymobiledevice3.osu.posix_util import Linux


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # Path.home() resolves through USERPROFILE on Windows
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return tmp_path


@pytest.fixture
def chowned(monkeypatch):
    """Records every path passed to chown_to_non_sudo_if_needed."""
    calls = []
    monkeypatch.setattr(common._OS_UTILS, "chown_to_non_sudo_if_needed", calls.append)
    return calls


@pytest.fixture
def set_home_folder(monkeypatch):
    def _set(path):
        monkeypatch.setattr(common, "_HOMEFOLDER", path)
        return path

    return _set


def test_default_home_folder_is_legacy_dotfolder(home):
    assert OsUtils().get_home_folder_path() == home / ".pymobiledevice3"


def test_linux_home_folder_prefers_existing_legacy_dotfolder(home):
    (home / ".pymobiledevice3").mkdir()
    assert Linux().get_home_folder_path() == home / ".pymobiledevice3"


def test_linux_home_folder_ignores_stray_file_at_legacy_path(home):
    (home / ".pymobiledevice3").touch()
    assert Linux().get_home_folder_path() == home / ".local" / "share" / "pymobiledevice3"


def test_linux_home_folder_defaults_to_xdg_data_home(home):
    assert Linux().get_home_folder_path() == home / ".local" / "share" / "pymobiledevice3"


def test_linux_home_folder_honors_xdg_data_home(home, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg-data"))
    assert Linux().get_home_folder_path() == home / "xdg-data" / "pymobiledevice3"


def test_linux_home_folder_ignores_relative_xdg_data_home(home, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "relative/data")
    assert Linux().get_home_folder_path() == home / ".local" / "share" / "pymobiledevice3"


def test_linux_home_folder_honors_absolute_xdg_data_home_under_sudo(home, tmp_path_factory, monkeypatch):
    # sudo -E carries the invoking user's own XDG_DATA_HOME; it is honored as-is so
    # sudo and non-sudo runs agree on where pair records live
    data = tmp_path_factory.mktemp("xdg-data")
    monkeypatch.setattr(Linux, "get_homedir", lambda self: home)
    monkeypatch.setenv("SUDO_USER", "invoking-user")
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    assert Linux().get_home_folder_path() == data / "pymobiledevice3"


def test_get_home_folder_chowns_created_parents_within_home(home, chowned, set_home_folder):
    target = set_home_folder(home / ".local" / "share" / "pymobiledevice3")

    assert common.get_home_folder() == target
    # every directory that mkdir(parents=True) created is chowned, but not the
    # pre-existing home directory itself
    assert set(chowned) == {target, target.parent, target.parent.parent}


def test_get_home_folder_chowns_created_parents_through_symlinked_home(
    home, tmp_path_factory, chowned, set_home_folder, monkeypatch
):
    # e.g. Fedora Silverblue: /home is a symlink to /var/home, so the homedir from
    # passwd and an XDG_DATA_HOME path may spell the same directory differently
    real_home = tmp_path_factory.mktemp("real-home")
    link_home = home / "link-home"
    link_home.symlink_to(real_home)
    monkeypatch.setattr(common._OS_UTILS, "get_homedir", lambda: link_home)
    target = set_home_folder(real_home / ".local" / "share" / "pymobiledevice3")

    assert common.get_home_folder() == target
    assert set(chowned) == {target, target.parent, target.parent.parent}


def test_get_home_folder_does_not_chown_parents_outside_home(home, tmp_path_factory, chowned, set_home_folder):
    outside = tmp_path_factory.mktemp("xdg-data")
    target = set_home_folder(outside / "nested" / "pymobiledevice3")

    assert common.get_home_folder() == target
    # only the leaf is chowned; ancestors outside the invoking user's home are left alone
    assert chowned == [target]


def test_get_home_folder_chowns_only_leaf_when_folder_exists(home, chowned, set_home_folder):
    target = set_home_folder(home / ".pymobiledevice3")
    target.mkdir()

    assert common.get_home_folder() == target
    # the unconditional leaf chown self-heals a root-owned folder left by an
    # interrupted sudo run
    assert chowned == [target]


def test_get_home_folder_fails_loudly_on_stray_file(home, chowned, set_home_folder):
    target = set_home_folder(home / ".pymobiledevice3")
    target.touch()

    with pytest.raises(FileExistsError):
        common.get_home_folder()


class _IOEntry:
    def __init__(self, properties, parents=None):
        self.properties = properties
        self._parents = parents or {}

    def get_parent_by_type(self, plane, parent_type):
        if parent_type not in self._parents:
            raise _NoParentError(parent_type)
        return self._parents[parent_type]


class _NoParentError(Exception):
    pass


# the host-side MAC of a real iPhone's private NCM link (its device answers at fe80::bc5a:3eff:fec4:9be9)
_HOST_MAC = bytes.fromhex("be5a3ec49b16")


def _ncm_interface(name, serial, flags, link_status=3, vendor="Apple Inc.", mac=_HOST_MAC):
    device = _IOEntry({"USB Vendor Name": vendor, "USB Serial Number": serial})
    controller = _IOEntry({"NetworkInterfaceFlags": flags, "IOLinkStatus": link_status, "IOMACAddress": mac})
    return _IOEntry({"BSD Name": name}, {"IOUSBHostDevice": device, "IONetworkController": controller})


def test_darwin_usb_rsd_addresses_follow_remoted(monkeypatch):
    # Only the private NCM function serves RSD, once its link is active and the host side holds its
    # link-local; the device's address is derived from the host MAC (values from a real iPhone).
    from types import SimpleNamespace

    from pymobiledevice3.osu import posix_util

    serial = "00008150001074523440401C"
    entries = [
        _ncm_interface("anri0", serial, flags=0x20000000),
        _ncm_interface("en29", serial, flags=0),
        _ncm_interface("anri1", "0000FE01F07564571CF86456", flags=0x20000000, link_status=1),
        _ncm_interface("anri2", "0000FE01F07564571CF86457", flags=0x20000000),
        _ncm_interface("en40", "SOMEDONGLE", flags=0x20000000, vendor="ASIX"),
        _IOEntry({"BSD Name": "en0"}),
    ]
    adapters = [
        SimpleNamespace(nice_name=name, ips=[SimpleNamespace(is_IPv4=False, ip=("fe80::1", 0, 0))])
        for name in ("anri0", "en29", "anri1", "en40", "en0")
    ]
    monkeypatch.setattr(posix_util, "get_io_services_by_type", lambda service_type: iter(entries))
    monkeypatch.setattr(posix_util, "IORegistryException", _NoParentError, raising=False)
    monkeypatch.setattr(posix_util, "get_adapters", lambda: adapters)

    assert posix_util.Darwin().usb_rsd_addresses() == {
        "00008150-001074523440401C": "fe80::bc5a:3eff:fec4:9be9%anri0",
    }


def test_darwin_usb_rsd_addresses_cannot_tell_without_a_private_ncm_function(monkeypatch):
    # macOS releases without the private/public split: remoted finds such devices over bonjour on the
    # public interface, so the caller must browse too rather than report no devices.
    from types import SimpleNamespace

    from pymobiledevice3.osu import posix_util

    entries = [
        _ncm_interface("anri0", "00008150001074523440401C", flags=0x20000000),
        _ncm_interface("en24", "0000FE01F07564571CF86456", flags=0),
        _ncm_interface("en25", "0000FE01F07564571CF86456", flags=0),
    ]
    adapters = [
        SimpleNamespace(nice_name=name, ips=[SimpleNamespace(is_IPv4=False, ip=("fe80::1", 0, 0))])
        for name in ("anri0", "en24", "en25")
    ]
    monkeypatch.setattr(posix_util, "get_io_services_by_type", lambda service_type: iter(entries))
    monkeypatch.setattr(posix_util, "IORegistryException", _NoParentError, raising=False)
    monkeypatch.setattr(posix_util, "get_adapters", lambda: adapters)

    assert posix_util.Darwin().usb_rsd_addresses() is None
