import pytest

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


def test_default_home_folder_is_legacy_dotfolder(home):
    assert OsUtils().get_home_folder_path() == home / ".pymobiledevice3"


def test_linux_home_folder_prefers_existing_legacy_dotfolder(home):
    (home / ".pymobiledevice3").mkdir()
    assert Linux().get_home_folder_path() == home / ".pymobiledevice3"


def test_linux_home_folder_defaults_to_xdg_data_home(home):
    assert Linux().get_home_folder_path() == home / ".local" / "share" / "pymobiledevice3"


def test_linux_home_folder_honors_xdg_data_home(home, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg-data"))
    assert Linux().get_home_folder_path() == home / "xdg-data" / "pymobiledevice3"


def test_linux_home_folder_ignores_relative_xdg_data_home(home, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "relative/data")
    assert Linux().get_home_folder_path() == home / ".local" / "share" / "pymobiledevice3"


def test_linux_home_folder_ignores_foreign_xdg_data_home_under_sudo(home, tmp_path_factory, monkeypatch):
    # Under sudo the environment may carry root's XDG_DATA_HOME while get_homedir()
    # resolves the invoking user's home
    root_data = tmp_path_factory.mktemp("root-data")
    monkeypatch.setattr(Linux, "get_homedir", lambda self: home)
    monkeypatch.setenv("SUDO_USER", "invoking-user")
    monkeypatch.setenv("XDG_DATA_HOME", str(root_data))
    assert Linux().get_home_folder_path() == home / ".local" / "share" / "pymobiledevice3"


def test_linux_home_folder_honors_own_xdg_data_home_under_sudo(home, monkeypatch):
    monkeypatch.setattr(Linux, "get_homedir", lambda self: home)
    monkeypatch.setenv("SUDO_USER", "invoking-user")
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg-data"))
    assert Linux().get_home_folder_path() == home / "xdg-data" / "pymobiledevice3"


def test_get_home_folder_chowns_created_parents(home, monkeypatch):
    from pymobiledevice3 import common

    target = home / ".local" / "share" / "pymobiledevice3"
    chowned = []
    monkeypatch.setattr(common, "_HOMEFOLDER", target)
    monkeypatch.setattr(common._OS_UTILS, "chown_to_non_sudo_if_needed", chowned.append)

    assert common.get_home_folder() == target
    # every directory that mkdir(parents=True) created is chowned, but not the
    # pre-existing home directory itself
    assert set(chowned) == {target, target.parent, target.parent.parent}


def test_get_home_folder_chowns_only_leaf_when_parents_exist(home, monkeypatch):
    from pymobiledevice3 import common

    target = home / ".pymobiledevice3"
    chowned = []
    monkeypatch.setattr(common, "_HOMEFOLDER", target)
    monkeypatch.setattr(common._OS_UTILS, "chown_to_non_sudo_if_needed", chowned.append)

    assert common.get_home_folder() == target
    assert chowned == [target]
