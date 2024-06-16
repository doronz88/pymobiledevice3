import plistlib
import pprint
import xml
from typing import IO, Mapping, Optional, TextIO

import click
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff

BPLIST_MAGIC = b'bplist'
PLIST_MAGIC = b'<plist'


class PcapSniffer:
    def __init__(self, file: Optional[TextIO] = None):
        self.file = file

    def process_packet(self, packet: Packet) -> None:
        packet = packet[Raw].load

        if BPLIST_MAGIC in packet:
            try:
                plist = plistlib.loads(packet[packet.find(BPLIST_MAGIC):])
                self.report(plist)
            except plistlib.InvalidFileException:
                pass
        if PLIST_MAGIC in packet:
            try:
                plist = plistlib.loads(packet[packet.find(PLIST_MAGIC):])
                self.report(plist)
            except xml.parsers.expat.ExpatError:
                pass

    def report(self, plist: Mapping) -> None:
        try:
            print(plist)
            if self.file is not None:
                self.file.write('---\n')
                self.file.write(pprint.pformat(plist))
                self.file.write('\n---\n')
        except ValueError:
            print('failed to print plist')


@click.group()
def cli():
    """ Parse RemoteXPC traffic """
    pass


@cli.command()
@click.argument('pcap', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option('-o', '--out', type=click.File('wt'))
def offline(pcap: str, out: IO):
    """ Parse plists traffic from a .pcap file """
    sniffer = PcapSniffer(out)
    for p in sniff(offline=pcap):
        sniffer.process_packet(p)


@cli.command()
@click.argument('iface')
@click.option('-o', '--out', type=click.File('wt'))
def live(iface: str, out: IO):
    """ Parse plists live from a given network interface """
    sniffer = PcapSniffer(out)
    sniff(iface=iface, prn=sniffer.process_packet)


if __name__ == '__main__':
    cli()
