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
