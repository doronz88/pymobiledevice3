import logging
import platform
import plistlib
import uuid
from collections.abc import Generator
from contextlib import suppress
from pathlib import Path
from typing import Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import MuxException, NotPairedError
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.usbmux import PlistMuxConnection

logger = logging.getLogger(__name__)
OSUTILS = get_os_utils()
PAIRING_RECORD_EXT = "plist"


def generate_host_id(hostname: Optional[str] = None) -> str:
    """
    Generate a unique host ID based on the hostname.

    :param hostname: The hostname to use for generating the host ID.
                     If None, the current hostname is used.
    :type hostname: str, optional
    :return: The generated host ID.
    :rtype: str
    """
    hostname = platform.node() if hostname is None else hostname
    host_id = uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
    return str(host_id).upper()


def get_usbmux_pairing_record(identifier: str, usbmux_address: Optional[str] = None):
    """
    Retrieve the pairing record from usbmuxd.

    :param identifier: The identifier of the device.
    :type identifier: str
    :param usbmux_address: The address of the usbmuxd server.
    :type usbmux_address: Optional[str], optional
    :return: The pairing record if found, otherwise None.
    :rtype: dict or None
    """
    with suppress(NotPairedError, MuxException), usbmux.create_mux(usbmux_address=usbmux_address) as mux:
        if isinstance(mux, PlistMuxConnection):
            pair_record = mux.get_pair_record(identifier)
            if pair_record is not None:
                return pair_record
    return None


def get_itunes_pairing_record(identifier: str) -> Optional[dict]:
    """
    Retrieve the pairing record from iTunes.

    :param identifier: The identifier of the device.
    :type identifier: str
    :return: The pairing record if found, otherwise None.
    :rtype: Optional[dict]
    """
    filename = OSUTILS.pair_record_path / f"{identifier}.plist"
    try:
        with open(filename, "rb") as f:
            pair_record = plistlib.load(f)
    except (PermissionError, FileNotFoundError, plistlib.InvalidFileException):
        return None
    return pair_record


def get_local_pairing_record(identifier: str, pairing_records_cache_folder: Path) -> Optional[dict]:
    """
    Retrieve the pairing record from local storage.

    :param identifier: The identifier of the device.
    :type identifier: str
    :param pairing_records_cache_folder: The path to the local pairing records cache folder.
    :type pairing_records_cache_folder: Path
    :return: The pairing record if found, otherwise None.
    :rtype: Optional[dict]
    """
    logger.debug("Looking for pymobiledevice3 pairing record")
    path = pairing_records_cache_folder / f"{identifier}.{PAIRING_RECORD_EXT}"
    if not path.exists():
        logger.debug(f"No pymobiledevice3 pairing record found for device {identifier}")
        return None
    return plistlib.loads(path.read_bytes())


def get_preferred_pair_record(
    identifier: str, pairing_records_cache_folder: Path, usbmux_address: Optional[str] = None
) -> dict:
    """
    Look for an existing pair record for the connected device in the following order:
    - usbmuxd
    - iTunes
    - local storage

    :param identifier: The identifier of the device.
    :type identifier: str
    :param pairing_records_cache_folder: The path to the local pairing records cache folder.
    :type pairing_records_cache_folder: Path
    :param usbmux_address: The address of the usbmuxd server.
    :type usbmux_address: Optional[str], optional
    :return: The preferred pairing record.
    :rtype: dict
    """
    # usbmuxd
    pair_record = get_usbmux_pairing_record(identifier=identifier, usbmux_address=usbmux_address)
    if pair_record is not None:
        return pair_record

    # iTunes
    pair_record = get_itunes_pairing_record(identifier)
    if pair_record is not None:
        return pair_record

    # local storage
    return get_local_pairing_record(identifier, pairing_records_cache_folder)


def create_pairing_records_cache_folder(pairing_records_cache_folder: Optional[Path] = None) -> Path:
    """
    Create the pairing records cache folder if it does not exist.

    :param pairing_records_cache_folder: The path to the local pairing records cache folder.
                                         If None, the home folder is used.
    :type pairing_records_cache_folder: Path, optional
    :return: The path to the pairing records cache folder.
    :rtype: Path
    """
    if pairing_records_cache_folder is None:
        pairing_records_cache_folder = get_home_folder()
    else:
        pairing_records_cache_folder.mkdir(parents=True, exist_ok=True)
    OSUTILS.chown_to_non_sudo_if_needed(pairing_records_cache_folder)
    return pairing_records_cache_folder


def get_remote_pairing_record_filename(identifier: str) -> str:
    """
    Generate the filename for the remote pairing record.

    :param identifier: The identifier of the device.
    :type identifier: str
    :return: The filename for the remote pairing record.
    :rtype: str
    """
    return f"remote_{identifier}"


def iter_remote_pair_records() -> Generator[Path, None, None]:
    """
    Iterate over the remote pairing records in the home folder.

    :return: A generator yielding paths to the remote pairing records.
    :rtype: Generator[Path, None, None]
    """
    return get_home_folder().glob("remote_*")


def iter_remote_paired_identifiers() -> Generator[str, None, None]:
    """
    Iterate over the identifiers of the remote paired devices.

    :return: A generator yielding the identifiers of the remote paired devices.
    :rtype: Generator[str, None, None]
    """
    for file in iter_remote_pair_records():
        yield file.parts[-1].split("remote_", 1)[1].split(".", 1)[0]
