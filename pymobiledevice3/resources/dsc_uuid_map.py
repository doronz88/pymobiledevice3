# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "coloredlogs",
#     "typer",
# ]
# ///
import json
import logging
import os.path
from pathlib import Path
from typing import Annotated, Any, Optional, cast
from uuid import UUID

import coloredlogs
import typer

MAGIC = b"\x0b\x10\x00\x00"
DYLD_MAGIC = b"dyld_v1"
MAP_FILENAME = os.path.join(os.path.dirname(__file__), "dsc_uuid_map.json")
PARTITIONS = ("/System", "/usr", "/Applications", "/private")
DYLD_UUID_OFFSET = 0x58
UUID_SIZE = 0x10

logger = logging.getLogger(__name__)


def get_dsc_map(dsc_uuid: str):
    with open(MAP_FILENAME) as f:
        uuid_map = json.load(f)

    return uuid_map.get(dsc_uuid)


def sanitize_path(path: str) -> Optional[str]:
    for partition in PARTITIONS:
        if path.startswith(partition):
            return path

    for partition in PARTITIONS:
        if partition in path:
            return partition + path.split(partition, 1)[1]


def main(
    dyld_uuid: UUID,
    dsc_path: Annotated[Path, typer.Argument(metavar="DSC", dir_okay=False, exists=True)],
    force: Annotated[bool, typer.Option("-f", "--force")] = False,
) -> None:
    """
    Simple utility to get all UUIDs used for symbolication from given DSC.
    The UUID of `/usr/lib/dyld` still needs manual insertion.
    """
    with open(MAP_FILENAME) as f:
        uuid_map = json.load(f)

    dsc = dsc_path.read_bytes()

    if not dsc.startswith(DYLD_MAGIC):
        logging.error("invalid dsc file")
        return

    dsc_uuid = str(UUID(bytes=dsc[DYLD_UUID_OFFSET : DYLD_UUID_OFFSET + UUID_SIZE]))

    if dsc_uuid in uuid_map:
        logger.warning(f"dsc {dsc_uuid} is already found in dsc_uuid_map")
        if not force:
            logger.info("exiting. use --force to force update")
            return
    else:
        uuid_map[dsc_uuid] = {str(dyld_uuid): "/usr/lib/dyld"}

    for i in range(0, len(dsc) - 4, 4):
        # we can assume MAGIC is always aligned to 4

        if dsc[i : i + 4] != MAGIC:
            continue

        # skip NULLs for filename pad
        j = i - 1
        while dsc[j] == 0:
            j -= 1

        # read filename backwards
        filename = ""
        c = chr(dsc[j])
        while c.isprintable():
            filename = c + filename
            j -= 1
            c = chr(dsc[j])

        if "/" not in filename:
            continue

        filename = sanitize_path(filename)

        # read uuid
        uuid = UUID(bytes=dsc[i + 4 : i + 4 + UUID_SIZE])

        logging.info(f"offset: 0x{i:x} image: {filename} uuid: {uuid}")

        uuid_map[dsc_uuid][str(uuid)] = filename

    with open(MAP_FILENAME, "w") as f:
        json.dump(uuid_map, f, indent=4)


if __name__ == "__main__":
    cast(Any, coloredlogs).install(level=logging.DEBUG)
    typer.run(main)
