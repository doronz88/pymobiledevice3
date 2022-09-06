# flake8: noqa: C901
import json
import logging
import os
import posixpath
import shlex
import signal
from collections import namedtuple
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List

import click
from click.exceptions import MissingParameter, UsageError
from pykdebugparser.pykdebugparser import PyKdebugParser
from termcolor import colored

import pymobiledevice3
from pymobiledevice3.cli.cli_common import print_json, Command, default_json_encoder, wait_return, BASED_INT
from pymobiledevice3.exceptions import DvtDirListError, ExtractingStackshotError, UnrecognizedSelectorError, \
    DeviceAlreadyInUseError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit
from pymobiledevice3.services.debugserver_applist import DebugServerAppList
from pymobiledevice3.services.device_arbitration import DtDeviceArbitration
from pymobiledevice3.services.dtfetchsymbols import DtFetchSymbols
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.activity_trace_tap import ActivityTraceTap, decode_message_format
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.energy_monitor import EnergyMonitor
from pymobiledevice3.services.dvt.instruments.graphics import Graphics
from pymobiledevice3.services.dvt.instruments.network_monitor import NetworkMonitor, ConnectionDetectionEvent
from pymobiledevice3.services.dvt.instruments.notifications import Notifications
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.remote_server import RemoteServer
from pymobiledevice3.services.screenshot import ScreenshotService
from pymobiledevice3.services.simulate_location import DtSimulateLocation
from pymobiledevice3.tcp_forwarder import TcpForwarder

BSC_SUBCLASS = 0x40c
BSC_CLASS = 0x4
VFS_AND_TRACES_SET = {0x03010000, 0x07ff0000}
logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ developer cli """
    pass


@cli.group()
def developer():
    """
    developer options.

    These options require the DeveloperDiskImage.dmg to be mounted on the device prior
    to execution. You can achieve this using:

    pymobiledevice3 mounter mount
    """
    pass


@developer.command('shell', cls=Command)
@click.argument('service')
@click.option('-r', '--remove-ssl-context', is_flag=True)
def developer_shell(lockdown: LockdownClient, service, remove_ssl_context):
    """ Launch developer shell. """
    with RemoteServer(lockdown, service, remove_ssl_context) as service:
        service.shell()


@developer.group()
def dvt():
    """ dvt operations """
    pass


@dvt.command('proclist', cls=Command)
@click.option('--color/--no-color', default=True)
def proclist(lockdown: LockdownClient, color):
    """ show process list """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        processes = DeviceInfo(dvt).proclist()
        for process in processes:
            if 'startDate' in process:
                process['startDate'] = str(process['startDate'])

        print_json(processes, colored=color)


@dvt.command('applist', cls=Command)
@click.option('--color/--no-color', default=True)
def applist(lockdown: LockdownClient, color):
    """ show application list """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        apps = ApplicationListing(dvt).applist()
        print_json(apps, colored=color)


@dvt.command('signal', cls=Command)
@click.argument('pid', type=click.INT)
@click.argument('sig', type=click.INT, required=False)
@click.option('-s', '--signal-name', type=click.Choice([s.name for s in signal.Signals]))
def send_signal(lockdown, pid, sig, signal_name):
    """ Send SIGNAL to process by its PID """
    if not sig and not signal_name:
        raise MissingParameter(param_type='argument|option', param_hint='\'SIG|SIGNAL-NAME\'')
    if sig and signal_name:
        raise UsageError(message='Cannot give SIG and SIGNAL-NAME together')
    sig = sig or signal.Signals[signal_name].value
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ProcessControl(dvt).signal(pid, sig)


@dvt.command('kill', cls=Command)
@click.argument('pid', type=click.INT)
def kill(lockdown: LockdownClient, pid):
    """ Kill a process by its pid. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ProcessControl(dvt).kill(pid)


@dvt.command('pkill', cls=Command)
@click.argument('expression')
def pkill(lockdown: LockdownClient, expression):
    """ kill all processes containing `expression` in their name. """
    processes = OsTraceService(lockdown=lockdown).get_pid_list()['Payload']
    if len(processes) == 0:
        # no point at trying to use DvtSecureSocketProxyService if no processes
        # were matched
        return

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        process_control = ProcessControl(dvt)
        for pid, process_info in processes.items():
            process_name = process_info['ProcessName']
            if expression in process_name:
                logger.info(f'killing {process_name}({pid})')
                process_control.kill(pid)


@dvt.command('launch', cls=Command)
@click.argument('arguments', type=click.STRING)
@click.option('--kill-existing/--no-kill-existing', default=True,
              help='Whether to kill an existing instance of this process')
@click.option('--suspended', is_flag=True, help='Same as WaitForDebugger')
@click.option('--env', multiple=True, type=click.Tuple((str, str)),
              help='Environment variables to pass to process given as a list of key value')
def launch(lockdown: LockdownClient, arguments: str, kill_existing: bool, suspended: bool, env: tuple):
    """ Launch a process. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        parsed_arguments = shlex.split(arguments)
        pid = ProcessControl(dvt).launch(bundle_id=parsed_arguments[0], arguments=parsed_arguments[1:],
                                         kill_existing=kill_existing, start_suspended=suspended,
                                         environment=dict(env))
        print(f'Process launched with pid {pid}')


@dvt.command('shell', cls=Command)
def dvt_shell(lockdown: LockdownClient):
    """ Launch developer shell. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        dvt.shell()


def show_dirlist(device_info: DeviceInfo, dirname, recursive=False):
    try:
        filenames = device_info.ls(dirname)
    except DvtDirListError:
        return

    for filename in filenames:
        filename = posixpath.join(dirname, filename)
        print(filename)
        if recursive:
            show_dirlist(device_info, filename, recursive=recursive)


@dvt.command('ls', cls=Command)
@click.argument('path', type=click.Path(exists=False))
@click.option('-r', '--recursive', is_flag=True)
def ls(lockdown: LockdownClient, path, recursive):
    """ List directory. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        show_dirlist(DeviceInfo(dvt), path, recursive=recursive)


@dvt.command('device-information', cls=Command)
@click.option('--color/--no-color', default=True)
def device_information(lockdown: LockdownClient, color):
    """ Print system information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)
        info = {
            'hardware': device_info.hardware_information(),
            'network': device_info.network_information(),
            'kernel-name': device_info.mach_kernel_name(),
            'kpep-database': device_info.kpep_database(),
        }
        try:
            info['system'] = device_info.system_information()
        except UnrecognizedSelectorError:
            pass
        print_json(info, colored=color)


@dvt.command('netstat', cls=Command)
def netstat(lockdown: LockdownClient):
    """ Print information about current network activity. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with NetworkMonitor(dvt) as monitor:
            for event in monitor:
                if isinstance(event, ConnectionDetectionEvent):
                    logger.info(
                        f'Connection detected: {event.local_address.data.address}:{event.local_address.port} -> '
                        f'{event.remote_address.data.address}:{event.remote_address.port}')


@dvt.command('screenshot', cls=Command)
@click.argument('out', type=click.File('wb'))
def screenshot(lockdown: LockdownClient, out):
    """ get device screenshot """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        out.write(Screenshot(dvt).get_screenshot())


@dvt.group('sysmon')
def sysmon():
    """ System monitor options. """


@sysmon.group('process')
def sysmon_process():
    """ Process monitor options. """


@sysmon_process.command('monitor', cls=Command)
@click.argument('threshold', type=click.FLOAT)
def sysmon_process_monitor(lockdown: LockdownClient, threshold):
    """ monitor all most consuming processes by given cpuUsage threshold. """

    Process = namedtuple('process', 'pid name cpuUsage')

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with Sysmontap(dvt) as sysmon:
            for process_snapshot in sysmon.iter_processes():
                entries = []
                for process in process_snapshot:
                    if (process['cpuUsage'] is not None) and (process['cpuUsage'] >= threshold):
                        entries.append(Process(pid=process['pid'], name=process['name'], cpuUsage=process['cpuUsage']))

                logger.info(entries)


@sysmon_process.command('single', cls=Command)
@click.option('-f', '--fields', help='show only given field names splitted by ",".')
@click.option('-a', '--attributes', multiple=True,
              help='filter processes by given attribute value given as key=value')
def sysmon_process_single(lockdown: LockdownClient, fields, attributes):
    """ show a single snapshot of currently running processes. """

    if fields is not None:
        fields = fields.split(',')

    count = 0

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)

        with Sysmontap(dvt) as sysmon:
            for process_snapshot in sysmon.iter_processes():
                count += 1

                if count < 2:
                    # first sample doesn't contain an initialized value for cpuUsage
                    continue

                for process in process_snapshot:
                    skip = False
                    if attributes is not None:
                        for filter_attr in attributes:
                            filter_attr, filter_value = filter_attr.split('=')
                            if str(process[filter_attr]) != filter_value:
                                skip = True
                                break

                    if skip:
                        continue

                    # adding "artificially" the execName field
                    process['execName'] = device_info.execname_for_pid(process['pid'])

                    print(f'{process["name"]} ({process["pid"]})')
                    for name, value in process.items():
                        if (fields is None) or (name in fields):
                            print(f'\t{name}: {value}')

                # exit after single snapshot
                return


@sysmon.command('system', cls=Command)
@click.option('-f', '--fields', help='field names splitted by ",".')
def sysmon_system(lockdown: LockdownClient, fields):
    """ show current system stats. """

    if fields is not None:
        fields = fields.split(',')

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        sysmontap = Sysmontap(dvt)
        with sysmontap as sysmon:
            for row in sysmon:
                if 'System' in row:
                    system = sysmon.system_attributes_cls(*row['System'])
                    break

    attrs_dict = asdict(system)
    for name, value in attrs_dict.items():
        if (fields is None) or (name in fields):
            print(f'{name}: {value}')


@dvt.group('core-profile-session')
def core_profile_session():
    """ Core profile session options. """


bsc_filter = click.option('--bsc/--no-bsc', default=False, help='Whether to print BSC events or not.')
class_filter = click.option('-cf', '--class-filters', multiple=True, type=BASED_INT,
                            help='Events class filter. Omit for all.')
subclass_filter = click.option('-sf', '--subclass-filters', multiple=True, type=BASED_INT,
                               help='Events subclass filter. Omit for all.')


def parse_filters(subclasses: List[int], classes: List[int]):
    if not subclasses and not classes:
        return None
    parsed = set()
    for subclass in subclasses:
        if subclass == BSC_SUBCLASS:
            parsed |= VFS_AND_TRACES_SET
        parsed.add(subclass << 16)
    for class_ in classes:
        if class_ == BSC_CLASS:
            parsed |= VFS_AND_TRACES_SET
        parsed.add((class_ << 24) | 0x00ff0000)
    return parsed


@core_profile_session.command('live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@bsc_filter
@class_filter
@subclass_filter
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--timestamp/--no-timestamp', default=True, help='Whether to print timestamp or not.')
@click.option('--event-name/--no-event-name', default=True, help='Whether to print event name or not.')
@click.option('--func-qual/--no-func-qual', default=True, help='Whether to print function qualifier or not.')
@click.option('--show-tid/--no-show-tid', default=True, help='Whether to print thread id or not.')
@click.option('--process-name/--no-process-name', default=True, help='Whether to print process name or not.')
@click.option('--args/--no-args', default=True, help='Whether to print event arguments or not.')
def live_profile_session(lockdown: LockdownClient, count, bsc, class_filters, subclass_filters, tid, timestamp,
                         event_name, func_qual, show_tid, process_name, args):
    """ Print kevents received from the device in real time. """

    parser = PyKdebugParser()
    parser.filter_class = class_filters
    if bsc:
        subclass_filters = list(subclass_filters) + [BSC_SUBCLASS]
    parser.filter_subclass = subclass_filters
    filters = parse_filters(subclass_filters, class_filters)
    parser.filter_tid = tid
    parser.show_timestamp = timestamp
    parser.show_name = event_name
    parser.show_func_qual = func_qual
    parser.show_tid = show_tid
    parser.show_process = process_name
    parser.show_args = args
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()
        time_config = CoreProfileSessionTap.get_time_config(dvt)
        parser.numer = time_config['numer']
        parser.denom = time_config['denom']
        parser.mach_absolute_time = time_config['mach_absolute_time']
        parser.usecs_since_epoch = time_config['usecs_since_epoch']
        parser.timezone = time_config['timezone']
        with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            i = 0
            for event in parser.formatted_kevents(tap.get_kdbuf_stream(), trace_codes_map):
                print(event)
                i += 1
                if i == count:
                    break


@core_profile_session.command('save', cls=Command)
@click.argument('out', type=click.File('wb'))
@bsc_filter
@class_filter
@subclass_filter
def save_profile_session(lockdown: LockdownClient, out, bsc, class_filters, subclass_filters):
    """ Dump core profiling information. """
    if bsc:
        subclass_filters = list(subclass_filters) + [BSC_SUBCLASS]
    filters = parse_filters(subclass_filters, class_filters)
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with CoreProfileSessionTap(dvt, {}, filters) as tap:
            tap.dump(out)


@core_profile_session.command('stackshot', cls=Command)
@click.option('--out', type=click.File('w'), default=None)
@click.option('--color/--no-color', default=True)
def stackshot(lockdown: LockdownClient, out, color):
    """ Dump stackshot information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with CoreProfileSessionTap(dvt, {}) as tap:
            try:
                data = tap.get_stackshot()
            except ExtractingStackshotError:
                logger.error(f'Extracting stackshot failed')
                return

            if out is not None:
                json.dump(data, out, indent=4, default=default_json_encoder)
            else:
                print_json(data, colored=color)


@core_profile_session.command('parse-live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
@bsc_filter
@class_filter
@subclass_filter
@click.option('--process', default=None, help='Process ID / name to filter. Omit for all.')
@click.option('--color/--no-color', default=True)
def parse_live_profile_session(lockdown: LockdownClient, count, tid, show_tid, bsc, class_filters, subclass_filters,
                               process, color):
    """ Print traces (syscalls, thread events, etc.) received from the device in real time. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        print('Receiving time information')
        time_config = CoreProfileSessionTap.get_time_config(dvt)
        parser = PyKdebugParser()
        parser.filter_class = list(class_filters)
        if bsc:
            subclass_filters = list(subclass_filters) + [BSC_SUBCLASS]
        parser.filter_subclass = subclass_filters
        filters = parse_filters(subclass_filters, class_filters)
        parser.numer = time_config['numer']
        parser.denom = time_config['denom']
        parser.mach_absolute_time = time_config['mach_absolute_time']
        parser.usecs_since_epoch = time_config['usecs_since_epoch']
        parser.timezone = time_config['timezone']
        parser.filter_tid = tid
        parser.filter_process = process
        parser.color = color
        parser.show_tid = show_tid

        with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            if show_tid:
                print('{:^32}|{:^11}|{:^33}|   Event'.format('Time', 'Thread', 'Process'))
            else:
                print('{:^32}|{:^33}|   Event'.format('Time', 'Process'))

            i = 0
            for trace in parser.formatted_traces(tap.get_kdbuf_stream()):
                print(trace)
                i += 1
                if i == count:
                    break


def get_image_name(dsc_uuid_map, image_uuid, current_dsc_map):
    if not current_dsc_map:
        for dsc_mapping in dsc_uuid_map.values():
            if image_uuid in dsc_mapping:
                current_dsc_map.update(dsc_mapping)

    return current_dsc_map.get(image_uuid, image_uuid)


def format_callstack(callstack, dsc_uuid_map, current_dsc_map):
    lines = callstack.splitlines()
    for i, line in enumerate(lines[1:]):
        if ':' in line:
            uuid = line.split(':')[0].strip()
            lines[i + 1] = line.replace(uuid, get_image_name(dsc_uuid_map, uuid, current_dsc_map))
    return '\n'.join(lines)


@core_profile_session.command('callstacks-live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('--process', default=None, help='Process to filter. Omit for all.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
@click.option('--color/--no-color', default=True)
def callstacks_live_profile_session(lockdown: LockdownClient, count, process, tid, show_tid, color):
    """ Print callstacks received from the device in real time. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        print('Receiving time information')
        time_config = CoreProfileSessionTap.get_time_config(dvt)
        parser = PyKdebugParser()
        parser.numer = time_config['numer']
        parser.denom = time_config['denom']
        parser.mach_absolute_time = time_config['mach_absolute_time']
        parser.usecs_since_epoch = time_config['usecs_since_epoch']
        parser.timezone = time_config['timezone']
        parser.filter_tid = tid
        parser.filter_process = process
        parser.color = color
        parser.show_tid = show_tid

        with open(os.path.join(pymobiledevice3.__path__[0], 'resources', 'dsc_uuid_map.json'), 'r') as fd:
            dsc_uuid_map = json.load(fd)

        current_dsc_map = {}
        with CoreProfileSessionTap(dvt, time_config) as tap:
            i = 0
            for callstack in parser.formatted_callstacks(tap.get_kdbuf_stream()):
                print(format_callstack(callstack, dsc_uuid_map, current_dsc_map))
                i += 1
                if i == count:
                    break


@dvt.command('trace-codes', cls=Command)
@click.option('--color/--no-color', default=True)
def dvt_trace_codes(lockdown: LockdownClient, color):
    """ Print KDebug trace codes. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)
        print_json({hex(k): v for k, v in device_info.trace_codes().items()}, colored=color)


@dvt.command('name-for-uid', cls=Command)
@click.argument('uid', type=click.INT)
def dvt_name_for_uid(lockdown: LockdownClient, uid):
    """ Print the assiciated username for the given uid. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)
        print(device_info.name_for_uid(uid))


@dvt.command('name-for-gid', cls=Command)
@click.argument('gid', type=click.INT)
def dvt_name_for_gid(lockdown: LockdownClient, gid):
    """ Print the assiciated group name for the given gid. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)
        print(device_info.name_for_gid(gid))


@dvt.command('oslog', cls=Command)
@click.option('--color/--no-color', default=True)
@click.option('--pid', type=click.INT)
def dvt_oslog(lockdown: LockdownClient, color, pid):
    """ oslog. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with ActivityTraceTap(dvt) as tap:
            for message in tap:
                message_pid = message.process
                # without message_type maybe signpost have event_type
                message_type = message.message_type if hasattr(message, 'message_type') else message.event_type \
                    if hasattr(message, 'event_type') else 'unknown'
                sender_image_path = message.sender_image_path
                image_name = os.path.basename(sender_image_path)
                subsystem = message.subsystem
                category = message.category
                timestamp = datetime.now()

                if pid is not None and message_pid != pid:
                    continue

                if message.message:
                    formatted_message = decode_message_format(message.message)
                else:
                    formatted_message = message.name

                if color:
                    timestamp = colored(str(timestamp), attrs=['bold'])
                    message_pid = colored(str(message_pid), 'magenta')
                    subsystem = colored(subsystem, 'green')
                    category = colored(category, 'green')
                    image_name = colored(image_name, 'yellow')
                    message_type = colored(message_type, 'cyan')

                print(f'[{timestamp}][{subsystem}][{category}][{message_pid}][{image_name}] '
                      f'<{message_type}>: {formatted_message}')


@dvt.command('energy', cls=Command)
@click.argument('pid-list', nargs=-1)
def dvt_energy(lockdown: LockdownClient, pid_list):
    """ energy monitoring for given pid list. """

    if len(pid_list) == 0:
        logger.error('pid_list must not be empty')
        return

    pid_list = [int(pid) for pid in pid_list]

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with EnergyMonitor(dvt, pid_list) as energy_monitor:
            for telemetry in energy_monitor:
                logger.info(telemetry)


@dvt.command('notifications', cls=Command)
def dvt_notifications(lockdown: LockdownClient):
    """ monitor memory and app notifications """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with Notifications(dvt) as notifications:
            for notification in notifications:
                logger.info(notification)


@dvt.command('graphics', cls=Command)
def dvt_notifications(lockdown: LockdownClient):
    """ monitor graphics statistics """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with Graphics(dvt) as graphics:
            for stats in graphics:
                logger.info(stats)


@developer.group('fetch-symbols')
def fetch_symbols():
    """ fetch-symbols options. """
    pass


@fetch_symbols.command('list', cls=Command)
@click.option('--color/--no-color', default=True)
def fetch_symbols_list(lockdown: LockdownClient, color: bool):
    """ list of files to be downloaded """
    print_json(DtFetchSymbols(lockdown).list_files(), colored=color)


@fetch_symbols.command('download', cls=Command)
@click.argument('out', type=click.Path(dir_okay=True, file_okay=False))
def fetch_symbols_download(lockdown: LockdownClient, out):
    """ download the linker and dyld cache to a specified directory """
    fetch_symbols = DtFetchSymbols(lockdown)
    files = fetch_symbols.list_files()
    out = Path(out)

    if not os.path.exists(out):
        os.makedirs(out)

    downloaded_files = set()

    for i, file in enumerate(files):
        if file.startswith('/'):
            # trim root to allow relative download
            file = file[1:]
        file = out / file

        if file not in downloaded_files:
            # first time the file was seen in list, means we can safely remove any old copy if any
            file.unlink(missing_ok=True)

        downloaded_files.add(file)
        file.parent.mkdir(parents=True, exist_ok=True)
        with open(file, 'ab') as f:
            # same file may appear twice, so we'll need to append data into it
            logger.info(f'writing to: {file}')
            fetch_symbols.get_file(i, f)


@developer.group('simulate-location')
def simulate_location():
    """ simulate-location options. """
    pass


@simulate_location.command('clear', cls=Command)
def simulate_location_clear(lockdown: LockdownClient):
    """ clear simulated location """
    DtSimulateLocation(lockdown).clear()


@simulate_location.command('set', cls=Command)
@click.argument('latitude', type=click.FLOAT)
@click.argument('longitude', type=click.FLOAT)
def simulate_location_set(lockdown: LockdownClient, latitude, longitude):
    """
    set a simulated location.
    try:
        ... set -- 40.690008 -74.045843 for liberty island
    """
    DtSimulateLocation(lockdown).set(latitude, longitude)


@simulate_location.command('play', cls=Command)
@click.argument('filename', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option('--disable-sleep', is_flag=True, default=False)
def simulate_location_play(lockdown: LockdownClient, filename, disable_sleep):
    """
    play a .gpx file
    """
    DtSimulateLocation(lockdown).play_gpx_file(filename, disable_sleep=disable_sleep)


@developer.group('accessibility')
def accessibility():
    """ accessibility options. """
    pass


@accessibility.command('capabilities', cls=Command)
def accessibility_capabilities(lockdown: LockdownClient):
    """ display accessibility capabilities """
    print_json(AccessibilityAudit(lockdown).device_capabilities())


@accessibility.group('settings')
def accessibility_settings():
    """ accessibility settings. """
    pass


@accessibility_settings.command('show', cls=Command)
def accessibility_settings_show(lockdown: LockdownClient):
    """ show current settings """
    for setting in AccessibilityAudit(lockdown).get_current_settings():
        print(setting)


@accessibility_settings.command('set', cls=Command)
@click.argument('setting', type=click.Choice(
    ['INVERT_COLORS', 'INCREASE_CONTRAST', 'REDUCE_TRANSPARENCY', 'REDUCE_MOTION', 'FONT_SIZE']))
@click.argument('value', type=click.INT)
def accessibility_settings_set(lockdown: LockdownClient, setting, value):
    """ show current settings """
    service = AccessibilityAudit(lockdown)
    service.set_setting(setting, value)
    wait_return()


@accessibility.command('shell', cls=Command)
def accessibility_shell(lockdown: LockdownClient):
    """ start and ipython accessibility shell """
    AccessibilityAudit(lockdown).shell()


@accessibility.command('notifications', cls=Command)
@click.option('-c', '--cycle-focus', is_flag=True)
def accessibility_notifications(lockdown: LockdownClient, cycle_focus):
    """ show notifications """

    service = AccessibilityAudit(lockdown)
    if cycle_focus:
        service.move_focus_next()
    for name, data in service.iter_notifications():
        if name in ('hostAppStateChanged:',
                    'hostInspectorCurrentElementChanged:',):
            for focus_item in data:
                logger.info(focus_item)

            if name == 'hostInspectorCurrentElementChanged:':
                if cycle_focus:
                    service.move_focus_next()


@accessibility.command('list-items', cls=Command)
def accessibility_list_items(lockdown: LockdownClient):
    """ list items available in currently shown menu """

    service = AccessibilityAudit(lockdown)
    iterator = service.iter_notifications()
    service.move_focus_next()

    first_item = None

    for name, data in iterator:
        if name != 'hostInspectorCurrentElementChanged:':
            continue

        current_item = data[0]

        if first_item is None:
            first_item = current_item
        else:
            if first_item.caption == current_item.caption:
                return

        print(f'{current_item.caption}: {current_item.element.identifier}')
        service.move_focus_next()


@developer.group('condition')
def condition():
    """ condition inducer options. """
    pass


@condition.command('list', cls=Command)
def condition_list(lockdown: LockdownClient):
    """ list all available conditions """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        print_json(ConditionInducer(dvt).list())


@condition.command('clear', cls=Command)
def condition_clear(lockdown: LockdownClient):
    """ clear current condition """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ConditionInducer(dvt).clear()


@condition.command('set', cls=Command)
@click.argument('profile_identifier')
def condition_set(lockdown: LockdownClient, profile_identifier):
    """ set a specific condition """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ConditionInducer(dvt).set(profile_identifier)
        wait_return()


@developer.command(cls=Command)
@click.argument('out', type=click.File('wb'))
def screenshot(lockdown: LockdownClient, out):
    """ take a screenshot in PNG format """
    out.write(ScreenshotService(lockdown=lockdown).take_screenshot())


@developer.group('debugserver')
def debugserver():
    """ debugserver options. """
    pass


@debugserver.command('applist', cls=Command)
def debugserver_applist(lockdown: LockdownClient):
    """ get applist xml """
    print_json(DebugServerAppList(lockdown).get())


@debugserver.command('start-server', cls=Command)
@click.argument('local_port', type=click.INT)
def debugserver_start_server(lockdown: LockdownClient, local_port):
    """
    start a debugserver at remote listening on a given port locally.

    Please note the connection must be done soon afterwards using your own lldb client.
    This can be done using the following commands within lldb shell:

    (lldb) platform select remote-ios

    (lldb) platform connect connect://localhost:<local_port>
    """
    attr = lockdown.get_service_connection_attributes('com.apple.debugserver.DVTSecureSocketProxy')
    TcpForwarder(lockdown, local_port, attr['Port'], attr.get('EnableServiceSSL', False)).start()


@developer.group('arbitration')
def arbitration():
    """ arbitration options. """
    pass


@arbitration.command('version', cls=Command)
@click.option('--color/--no-color', default=True)
def version(lockdown: LockdownClient, color):
    """ get arbitration version """
    with DtDeviceArbitration(lockdown) as device_arbitration:
        print_json(device_arbitration.version, colored=color)


@arbitration.command('check-in', cls=Command)
@click.argument('hostname')
@click.option('-f', '--force', default=False, is_flag=True)
def check_in(lockdown: LockdownClient, hostname, force):
    """ owner check-in """
    with DtDeviceArbitration(lockdown) as device_arbitration:
        try:
            device_arbitration.check_in(hostname, force=force)
            wait_return()
        except DeviceAlreadyInUseError as e:
            logger.error(e.message)


@arbitration.command('check-out', cls=Command)
def check_out(lockdown: LockdownClient):
    """ owner check-out """
    with DtDeviceArbitration(lockdown) as device_arbitration:
        device_arbitration.check_out()
