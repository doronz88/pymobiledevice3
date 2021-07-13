import json
import logging
import os.path
from uuid import UUID

import click
import coloredlogs

coloredlogs.install(level=logging.DEBUG)

MAGIC = b'\x0b\x10\x00\x00'
DYLD_MAGIC = b'dyld_v1'
MAP_FILENAME = os.path.join(os.path.dirname(__file__), 'dsc_uuid_map.json')
PARTITIONS = ('/System', '/usr', '/Applications', '/private')
DYLD_UUID_OFFSET = 0x58
UUID_SIZE = 0x10


def get_dsc_map(dsc_uuid):
    with open(MAP_FILENAME, 'r') as f:
        uuid_map = json.load(f)

    return uuid_map.get(dsc_uuid)


def sanitize_path(path):
    for partition in PARTITIONS:
        if path.startswith(partition):
            return path

    for partition in PARTITIONS:
        if partition in path:
            return partition + path.split(partition, 1)[1]


@click.command()
@click.argument('dyld_uuid', type=click.UUID)
@click.argument('dsc', type=click.File('rb'))
@click.option('-f', '--force', is_flag=True)
def main(dsc, dyld_uuid, force):
    """
    Simple utility to get all UUIDs used for symbolication from given DSC.
    The UUID of `/usr/lib/dyld` still needs manual insertion.
    """
    with open(MAP_FILENAME, 'r') as f:
        uuid_map = json.load(f)

    dsc = dsc.read()

    if not dsc.startswith(DYLD_MAGIC):
        logging.error('invalid dsc file')
        return

    dsc_uuid = str(UUID(bytes=dsc[DYLD_UUID_OFFSET:DYLD_UUID_OFFSET + UUID_SIZE]))

    if dsc_uuid in uuid_map:
        logging.warning(f'dsc {dsc_uuid} is already found in dsc_uuid_map')
        if not force:
            logging.info('exiting. use --force to force update')
            return
    else:
        uuid_map[dsc_uuid] = {str(dyld_uuid): '/usr/lib/dyld'}

    for i in range(0, len(dsc) - 4, 4):
        # we can assume MAGIC is always aligned to 4

        if dsc[i:i + 4] != MAGIC:
            continue

        # skip NULLs for filename pad
        j = i - 1
        while dsc[j] == 0:
            j -= 1

        # read filename backwards
        filename = ''
        c = chr(dsc[j])
        while c.isprintable():
            filename = c + filename
            j -= 1
            c = chr(dsc[j])

        if '/' not in filename:
            continue

        filename = sanitize_path(filename)

        # read uuid
        uuid = UUID(bytes=dsc[i + 4:i + 4 + UUID_SIZE])

        logging.info(f'offset: 0x{i:x} image: {filename} uuid: {uuid}')

        uuid_map[dsc_uuid][str(uuid)] = filename

    with open(MAP_FILENAME, 'w') as f:
        json.dump(uuid_map, f, indent=4)


if __name__ == '__main__':
    main()
