from pathlib import Path

from pymobiledevice3.osu.os_utils import get_os_utils

_OS_UTILS = get_os_utils()
_HOMEFOLDER = _OS_UTILS.get_home_folder_path()


def get_home_folder() -> Path:
    created_parents = [folder for folder in _HOMEFOLDER.parents if not folder.exists()]
    _HOMEFOLDER.mkdir(exist_ok=True, parents=True)
    # mkdir(parents=True) may create intermediate directories (e.g. ~/.local and
    # ~/.local/share) as root under sudo; chown everything that was created, not just the leaf
    for folder in created_parents:
        _OS_UTILS.chown_to_non_sudo_if_needed(folder)
    _OS_UTILS.chown_to_non_sudo_if_needed(_HOMEFOLDER)
    return _HOMEFOLDER
