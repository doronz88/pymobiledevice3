import json
import logging
import posixpath
from collections import namedtuple
from typing import List, Optional

import click
from cached_property import cached_property
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.os_trace import OsTraceService

Frame = namedtuple('Frame', 'image symbol offset')
Register = namedtuple('Register', 'name value')


class CrashReport:
    def __init__(self, buf: str):
        self._metadata, self._data = buf.split('\n', 1)
        self._metadata = json.loads(self._metadata)
        self._parse()

    def _parse(self):
        self._is_json = False
        try:
            self._data = json.loads(self._data)
            self._is_json = True
        except json.decoder.JSONDecodeError:
            pass

    def _parse_field(self, name: str) -> str:
        name += ':'
        for line in self._data.split('\n'):
            if line.startswith(name):
                field = line.split(name, 1)[1]
                field = field.strip()
                return field

    @cached_property
    def bug_type(self):
        return self._metadata['bug_type']

    @cached_property
    def incident_id(self):
        return self._metadata['incident_id']

    @cached_property
    def timestamp(self):
        return self._metadata['timestamp']

    @cached_property
    def name(self) -> str:
        return self._metadata['name']

    @cached_property
    def faulting_thread(self) -> int:
        if self._is_json:
            return self._data['faultingThread']
        else:
            return int(self._parse_field('Triggered by Thread'))

    @cached_property
    def frames(self) -> List[Frame]:
        result = []
        if self._is_json:
            thread_index = self.faulting_thread
            images = self._data['usedImages']
            for frame in self._data['threads'][thread_index]['frames']:
                image = images[frame['imageIndex']]
                result.append(
                    Frame(image=image['path'], symbol=hex(image['base']), offset=frame['imageOffset']))
        else:
            in_frames = False
            for line in self._data.split('\n'):
                if in_frames:
                    splitted = line.split()

                    if len(splitted) == 0:
                        break

                    assert splitted[-2] == '+'
                    result.append(Frame(image=splitted[1], symbol=splitted[-3], offset=int(splitted[-1])))

                if line.startswith(f'Thread {self.faulting_thread} Crashed:'):
                    in_frames = True

        return result

    @cached_property
    def registers(self) -> List[Register]:
        result = []
        if self._is_json:
            thread_index = self._data['faultingThread']
            thread_state = self._data['threads'][thread_index]['threadState']

            for i, reg in enumerate(thread_state['x']):
                result.append(Register(name=f'x{i}', value=reg['value']))

            additional_regs = ('lr', 'cpsr', 'fp', 'sp', 'esr', 'pc', 'far')

            for reg in additional_regs:
                result.append(Register(name=reg, value=thread_state[reg]['value']))
        else:
            in_frames = False
            for line in self._data.split('\n'):
                if in_frames:
                    splitted = line.split()

                    if len(splitted) == 0:
                        break

                    for i in range(0, len(splitted), 2):
                        register_name = splitted[i]
                        if not register_name.endswith(':'):
                            break

                        register_name = register_name[:-1]
                        register_value = int(splitted[i + 1], 16)

                        result.append(Register(name=register_name, value=register_value))

                if line.startswith(f'Thread {self.faulting_thread} crashed with ARM Thread State'):
                    in_frames = True

        return result

    @cached_property
    def exception_type(self):
        if self._is_json:
            return self._data['exception'].get('type')
        else:
            return self._parse_field('Exception Type')

    @cached_property
    def exception_subtype(self) -> Optional[str]:
        if self._is_json:
            return self._data['exception'].get('subtype')
        else:
            return self._parse_field('Exception Subtype')

    @cached_property
    def application_specific_information(self) -> str:
        result = ''
        if self._is_json:
            return str(self._data.get('asi'))
        else:
            in_frames = False
            for line in self._data.split('\n'):
                if in_frames:
                    line = line.strip()
                    if len(line) == 0:
                        break

                    result += line + '\n'

                if line.startswith('Application Specific Information:'):
                    in_frames = True

        return result

    def __str__(self):
        result = ''

        result += click.style(f'{self.incident_id} {self.timestamp}\n\n', fg='cyan')

        if self.bug_type not in ('109', '309', '327', '385'):
            # these crashes aren't crash dumps
            return result

        result += click.style(f'Exception: {self.exception_type}\n', bold=True)

        if self.exception_subtype:
            result += click.style('Exception Subtype: ', bold=True)
            result += f'{self.exception_subtype}\n'

        if self.application_specific_information:
            result += click.style('Application Specific Information: ', bold=True)
            result += self.application_specific_information

        result += '\n'

        result += click.style('Registers:', bold=True)
        for i, register in enumerate(self.registers):
            if i % 4 == 0:
                result += '\n'

            result += f'{register.name} = 0x{register.value:016x} '.rjust(30)

        result += '\n\n'

        result += click.style('Frames:\n', bold=True)
        for frame in self.frames:
            result += f'\t[{frame.image}] {frame.symbol} + 0x{frame.offset:x}\n'

        return result


class CrashReports:
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
            crash_report = CrashReport(crash_report_raw)

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
