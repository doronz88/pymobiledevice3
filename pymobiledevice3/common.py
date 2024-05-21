from pathlib import Path

from pymobiledevice3.osu.os_utils import get_os_utils

_HOMEFOLDER = get_os_utils().get_homedir() / '.pymobiledevice3'


def get_home_folder() -> Path:
    _HOMEFOLDER.mkdir(exist_ok=True, parents=True)
    return _HOMEFOLDER
