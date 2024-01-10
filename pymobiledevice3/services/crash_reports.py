import logging
import posixpath
from typing import Generator, List

from pycrashreport.crash_report import get_crash_report_from_buf
from xonsh.built_ins import XSH
from xonsh.cli_utils import Annotated, Arg

from pymobiledevice3.exceptions import AfcException
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService, AfcShell, path_completer
from pymobiledevice3.services.os_trace import OsTraceService

SYSDIAGNOSE_PROCESS_NAMES = ('sysdiagnose', 'sysdiagnosed')
SYSDIAGNOSE_DIR = 'DiagnosticLogs/sysdiagnose'

# on iOS17, we need to wait for a moment before tryint to fetch the sysdiagnose archive
IOS17_SYSDIAGNOSE_DELAY = 1


class CrashReportsManager:
    COPY_MOBILE_NAME = 'com.apple.crashreportcopymobile'
    RSD_COPY_MOBILE_NAME = 'com.apple.crashreportcopymobile.shim.remote'

    CRASH_MOVER_NAME = 'com.apple.crashreportmover'
    RSD_CRASH_MOVER_NAME = 'com.apple.crashreportmover.shim.remote'

    APPSTORED_PATH = '/com.apple.appstored'
    IN_PROGRESS_SYSDIAGNOSE_EXTENSIONS = ['.tmp', '.tar.gz']

    def __init__(self, lockdown: LockdownServiceProvider):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

        if isinstance(lockdown, LockdownClient):
            self.copy_mobile_service_name = self.COPY_MOBILE_NAME
            self.crash_mover_service_name = self.CRASH_MOVER_NAME
        else:
            self.copy_mobile_service_name = self.RSD_COPY_MOBILE_NAME
            self.crash_mover_service_name = self.RSD_CRASH_MOVER_NAME

        self.afc = AfcService(lockdown, service_name=self.copy_mobile_service_name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        self.afc.close()

    def clear(self) -> None:
        """
        Clear all crash reports.
        """
        undeleted_items = []
        for filename in self.ls('/'):
            undeleted_items.extend(self.afc.rm(filename, force=True))

        for item in undeleted_items:
            # special case of file that sometimes created automatically right after delete,
            # and then we can't delete the folder because it's not empty
            if item != self.APPSTORED_PATH:
                raise AfcException(f'failed to clear crash reports directory, undeleted items: {undeleted_items}', None)

    def ls(self, path: str = '/', depth: int = 1) -> List[str]:
        """
        List file and folder in the crash report's directory.
        :param path: Path to list, relative to the crash report's directory.
        :param depth: Listing depth, -1 to list infinite.
        :return: List of files listed.
        """
        return list(self.afc.dirlist(path, depth))[1:]  # skip the root path '/'

    def pull(self, out: str, entry: str = '/', erase: bool = False) -> None:
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

    def flush(self) -> None:
        """ Trigger com.apple.crashreportmover to flush all products into CrashReports directory """
        ack = b'ping\x00'
        assert ack == self.lockdown.start_lockdown_service(self.crash_mover_service_name).recvall(len(ack))

    def watch(self, name: str = None, raw: bool = False) -> Generator[str, None, None]:
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
            crash_report = get_crash_report_from_buf(crash_report_raw, filename=filename)

            if name is None or crash_report.name == name:
                if raw:
                    yield crash_report_raw
                else:
                    yield crash_report

    def get_new_sysdiagnose(self, out: str, erase: bool = True) -> None:
        """
        Monitor the creation of a newly created sysdiagnose archive and pull it
        :param out: filename
        :param erase: remove after pulling
        """
        sysdiagnose_filename = self._get_new_sysdiagnose_filename()
        self.logger.info('sysdiagnose tarball creation has been started')
        self._wait_for_sysdiagnose_to_finish()
        self.pull(out, entry=sysdiagnose_filename, erase=erase)

    @staticmethod
    def _sysdiagnose_complete_syslog_match(message: str) -> bool:
        return message == 'sysdiagnose (full) complete' or 'Sysdiagnose completed' in message

    def _wait_for_sysdiagnose_to_finish(self) -> None:
        with OsTraceService(self.lockdown) as os_trace:
            for entry in os_trace.syslog():
                if CrashReportsManager._sysdiagnose_complete_syslog_match(entry.message):
                    break

    def _get_new_sysdiagnose_filename(self) -> str:
        sysdiagnose_filename = None

        while sysdiagnose_filename is None:
            try:
                for filename in self.afc.listdir(SYSDIAGNOSE_DIR):
                    # search for an IN_PROGRESS archive
                    if 'IN_PROGRESS_' in filename:
                        for ext in self.IN_PROGRESS_SYSDIAGNOSE_EXTENSIONS:
                            if filename.endswith(ext):
                                sysdiagnose_filename = filename.rsplit(ext)[0]
                                sysdiagnose_filename = sysdiagnose_filename.replace('IN_PROGRESS_', '')
                                sysdiagnose_filename = f'{sysdiagnose_filename}.tar.gz'
                                return posixpath.join(SYSDIAGNOSE_DIR,  sysdiagnose_filename)
            except AfcException:
                pass


class CrashReportsShell(AfcShell):
    @classmethod
    def create(cls, service_provider: LockdownServiceProvider, **kwargs):
        manager = CrashReportsManager(service_provider)
        XSH.ctx['_manager'] = manager
        super(CrashReportsShell, CrashReportsShell).create(service_provider, service=manager.afc)

    def _setup_shell_commands(self):
        super()._setup_shell_commands()
        self._register_arg_parse_alias('parse', self._do_parse)
        self._register_arg_parse_alias('clear', self._do_clear)

    def _do_parse(self, filename: Annotated[str, Arg(completer=path_completer)]) -> None:
        print(get_crash_report_from_buf(self.afc.get_file_contents(filename).decode(), filename=filename))

    def _do_clear(self) -> None:
        XSH.ctx['_manager'].clear()
