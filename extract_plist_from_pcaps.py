#!/usr/local/bin/python3
import plistlib
import pprint
import xml

import click
import pcapy

BPLIST_MAGIC = b'bplist'
PLIST_MAGIC = b'<plist'


@click.command()
@click.argument('pcap', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.argument('out', type=click.File('wt'))
def main(pcap, out):
    pcap = pcapy.open_offline(pcap)
    while True:
        packet = pcap.next()[1]
        if BPLIST_MAGIC in packet:
            try:
                plist = plistlib.loads(packet[packet.find(BPLIST_MAGIC):])
                print(plist)
                out.write('---\n')
                out.write(pprint.pformat(plist))
                out.write('\n---\n')
            except plistlib.InvalidFileException:
                pass
        if PLIST_MAGIC in packet:
            try:
                plist = plistlib.loads(packet[packet.find(PLIST_MAGIC):])
                print(plist)
                out.write('---\n')
                out.write(pprint.pformat(plist))
                out.write('\n---\n')
            except xml.parsers.expat.ExpatError:
                pass


if __name__ == '__main__':
    main()
