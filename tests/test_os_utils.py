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
