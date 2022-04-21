import logging
import posixpath

from cmd2 import with_argparser, Cmd2ArgumentParser
from pycrashreport.crash_report import CrashReport

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService, AfcShell
from pymobiledevice3.services.os_trace import OsTraceService


class CrashReportsManager:
    COPY_MOBILE_NAME = 'com.apple.crashreportcopymobile'
    CRASH_MOVER_NAME = 'com.apple.crashreportmover'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.afc = AfcService(lockdown, service_name=self.COPY_MOBILE_NAME)

    def clear(self):
        """
        Clear all crash reports.
        """
        for filename in self.ls('/'):
            self.afc.rm(filename, force=True)

    def ls(self, path: str = '/', depth: int = 1):
        """
        List file and folder in the crash reports directory.
        :param path: Path to list, relative to the crash reports directory.
        :param depth: Listing depth, -1 to list infinite.
        :return: List of files listed.
        """
        return list(self.afc.dirlist(path, depth))[1:]

    def pull(self, out: str, entry: str = '/', erase: bool = False):
        """
        Pull crash reports from the device.
        :param out: Directory to pull crash reports to.
        :param entry: File or Folder to pull.
        :param erase: Whether to erase the original file from the CrashReports directory.
        """

        def log(src, dst):
            self.logger.info(f'{src} --> {dst}')

        self.afc.pull(entry, out, callback=log)

        if erase:
            if posixpath.normpath(entry) in ('.', '/'):
                self.clear()
            else:
                self.afc.rm(entry, force=True)

    def flush(self):
        """ Trigger com.apple.crashreportmover to flush all products into CrashReports directory """
        ack = b'ping\x00'
        assert ack == self.lockdown.start_service(self.CRASH_MOVER_NAME).recvall(len(ack))

    def watch(self, name: str = None, raw: bool = False):
        """
        Monitor creation of new crash reports for a given process name.

        Return value can either be the raw crash string, or parsed result containing a more human-friendly
        representation for the crash.
        """
        for syslog_entry in OsTraceService(lockdown=self.lockdown).syslog():
            if (posixpath.basename(syslog_entry.filename) != 'osanalyticshelper') or \
                    (posixpath.basename(syslog_entry.image_name) != 'OSAnalytics') or \
                    not syslog_entry.message.startswith('Saved type '):
                # skip non-ips creation syslog lines
                continue

            filename = posixpath.basename(syslog_entry.message.split()[-1])
            self.logger.debug(f'crash report: {filename}')

            if posixpath.splitext(filename)[-1] not in ('.ips', '.panic'):
                continue

            crash_report_raw = self.afc.get_file_contents(filename).decode()
            crash_report = CrashReport(crash_report_raw, filename=filename)

            if name is None or crash_report.name == name:
                if raw:
                    yield crash_report_raw
                else:
                    yield crash_report

    def get_new_sysdiagnose(self, out: str, erase: bool = True):
        """
        Monitor the creation of a newly created sysdiagnose archive and pull it
        :param out: filename
        :param erase: remove after pulling
        """
        sysdiagnose_filename = None

        for syslog_entry in OsTraceService(lockdown=self.lockdown).syslog():
            if (posixpath.basename(syslog_entry.filename) != 'sysdiagnose') or \
                    (posixpath.basename(syslog_entry.image_name) != 'sysdiagnose'):
                # filter only sysdianose lines
                continue

            message = syslog_entry.message

            if message.startswith('SDArchive: Successfully created tar at '):
                self.logger.info('sysdiagnose creation has begun')
                for filename in self.ls('DiagnosticLogs/sysdiagnose'):
                    # search for an IN_PROGRESS archive
                    if 'IN_PROGRESS_' in filename and filename.endswith('.tar.gz'):
                        sysdiagnose_filename = filename.replace('IN_PROGRESS_', '')
                        break
                break

        self.afc.wait_exists(sysdiagnose_filename)
        self.pull(out, entry=sysdiagnose_filename, erase=erase)


parse_parser = Cmd2ArgumentParser(description='parse given crash report file')
parse_parser.add_argument('filename')

clear_parser = Cmd2ArgumentParser(description='remove all crash reports')


class CrashReportsShell(AfcShell):
    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, service_name=CrashReportsManager.COPY_MOBILE_NAME)
        self.manager = CrashReportsManager(lockdown)
        self.complete_parse = self._complete_first_arg

    @with_argparser(parse_parser)
    def do_parse(self, args):
        self.poutput(CrashReport(self.afc.get_file_contents(args.filename).decode(), filename=args.filename))

    @with_argparser(clear_parser)
    def do_clear(self, args):
        self.manager.clear()
