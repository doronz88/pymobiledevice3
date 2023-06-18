import logging
import os
import platform
import plistlib
import sys
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Mapping, Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import MuxException, NotPairedError
from pymobiledevice3.usbmux import PlistMuxConnection

PAIR_RECORDS_PATH = {
    'win32': Path(os.environ.get('ALLUSERSPROFILE', ''), 'Apple', 'Lockdown'),
    'darwin': Path('/var/db/lockdown/'),
    'linux': Path('/var/lib/lockdown/'),
}

logger = logging.getLogger(__name__)


def generate_host_id(hostname: str = None) -> str:
    hostname = platform.node() if hostname is None else hostname
    host_id = uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
    return str(host_id).upper()


def get_itunes_pairing_record(identifier: str) -> Optional[Mapping]:
    platform_type = 'linux' if not sys.platform.startswith('linux') else sys.platform
    filename = PAIR_RECORDS_PATH[platform_type] / f'{identifier}.plist'
    try:
        with open(filename, 'rb') as f:
            pair_record = plistlib.load(f)
    except (PermissionError, FileNotFoundError, plistlib.InvalidFileException):
        return None
    return pair_record


def get_local_pairing_record(identifier: str, pairing_records_cache_folder: Path) -> Optional[Mapping]:
    logger.debug('Looking for pymobiledevice3 pairing record')
    path = pairing_records_cache_folder / f'{identifier}.plist'
    if not path.exists():
        logger.debug(f'No pymobiledevice3 pairing record found for device {identifier}')
        return None
    return plistlib.loads(path.read_bytes())


def get_preferred_pair_record(identifier: str, pairing_records_cache_folder: Path) -> Mapping:
    """
    look for an existing pair record to connected device by following order:
    - usbmuxd
    - iTunes
    - local storage
    """

    # usbmuxd
    with suppress(NotPairedError, MuxException):
        with usbmux.create_mux() as mux:
            if isinstance(mux, PlistMuxConnection):
                pair_record = mux.get_pair_record(identifier)
                if pair_record is not None:
                    return pair_record

    # iTunes
    pair_record = get_itunes_pairing_record(identifier)
    if pair_record is not None:
        return pair_record

    # local storage
    return get_local_pairing_record(identifier, pairing_records_cache_folder)


def create_pairing_records_cache_folder(pairing_records_cache_folder: Path = None) -> Path:
    if pairing_records_cache_folder is None:
        pairing_records_cache_folder = get_home_folder()
    else:
        pairing_records_cache_folder.mkdir(parents=True, exist_ok=True)
    return pairing_records_cache_folder
