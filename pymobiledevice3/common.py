from pathlib import Path

_HOMEFOLDER = Path.home() / '.pymobiledevice3'


def get_home_folder() -> Path:
    _HOMEFOLDER.mkdir(exist_ok=True, parents=True)
    return _HOMEFOLDER
