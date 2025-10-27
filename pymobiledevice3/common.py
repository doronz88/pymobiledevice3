from pathlib import Path

from pymobiledevice3.osu.os_utils import get_os_utils

_OS_UTILS = get_os_utils()
_HOMEFOLDER = _OS_UTILS.get_homedir() / ".pymobiledevice3"


def get_home_folder() -> Path:
    _HOMEFOLDER.mkdir(exist_ok=True, parents=True)
    _OS_UTILS.chown_to_non_sudo_if_needed(_HOMEFOLDER)
    return _HOMEFOLDER
