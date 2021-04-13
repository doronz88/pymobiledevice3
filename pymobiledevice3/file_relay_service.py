from tempfile import mkstemp
from optparse import OptionParser
from io import BytesIO
import logging
import gzip

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.util.cpio import CpioArchive
from pymobiledevice3.util import MultipleOption
from pymobiledevice3.plist_service import ConnectionFailedException

SRCFILES = """Baseband
CrashReporter
MobileAsset
VARFS
HFSMeta
Lockdown
MobileBackup
MobileDelete
MobileInstallation
MobileNotes
Network
UserDatabases
WiFi
WirelessAutomation
NANDDebugInfo
SystemConfiguration
Ubiquity
tmp
WirelessAutomation"""


class DeviceVersionNotSupported(Exception):
    pass


class FileRelayService(object):
    SERVICE_NAME = 'com.apple.mobile.file_relay'

    def __init__(self, lockdown: LockdownClient,):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)
        self.packet_num = 0

    def stop_session(self):
        self.logger.info("Disconecting...")
        self.service.close()

    def request_sources(self, sources=["UserDatabases"]):
        self.service.send_plist({"Sources": sources})
        while 1:
            res = self.service.recv_plist()
            if res:
                s = res.get("Status")
                if s == "Acknowledged":
                    z = ""
                    while True:
                        x = self.service.recv()
                        if not x:
                            break
                        z += x
                    return z
                else:
                    print(res.get("Error"))
                    break
        return None


if __name__ == "__main__":
    parser = OptionParser(option_class=MultipleOption, usage="%prog")
    parser.add_option("-s", "--sources",
                      action="extend",
                      dest="sources",
                      metavar='SOURCES',
                      choices=SRCFILES.split("\n"),
                      help="comma separated list of file relay source to dump")
    parser.add_option("-e", "--extract", dest="extractpath", default=False,
                      help="Extract archive to specified location", type="string")
    parser.add_option("-o", "--output", dest="outputfile", default=False,
                      help="Output location", type="string")

    (options, args) = parser.parse_args()

    sources = []
    if options.sources:
        sources = options.sources
    else:
        sources = ["UserDatabases"]
    print("Downloading: %s" % "".join([str(item) + " " for item in sources]))
    fc = None
    try:
        fc = FileRelayService()
    except ConnectionFailedException:
        print(
            'Failed to connect to FileRelay service. '
            'Device with product vertion >= 8.0 does not allow access to fileRelay service')
        exit()

    data = fc.request_sources(sources)

    if data:
        if options.outputfile:
            path = options.outputfile
        else:
            _, path = mkstemp(prefix="fileRelay_dump_", suffix=".gz", dir=".")

        open(path, 'wb').write(data)
        fc.logger.info("Data saved to:  %s ", path)

    if options.extractpath:
        with open(path, 'r') as f:
            gz = gzip.GzipFile(mode='rb', fileobj=f)
            cpio = CpioArchive(fileobj=BytesIO(gz.read()))
            cpio.extract_files(files=None, outpath=options.extractpath)
