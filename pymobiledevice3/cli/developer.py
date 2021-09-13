# flake8: noqa: C901
import json
import logging
import os
import posixpath
import shlex
from collections import namedtuple
from dataclasses import asdict

import click
from pykdebugparser.pykdebugparser import PyKdebugParser
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from termcolor import colored

import pymobiledevice3
from pymobiledevice3.cli.cli_common import print_json, Command, default_json_encoder
from pymobiledevice3.exceptions import DvtDirListError, ExtractingStackshotError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.debugserver_applist import DebugServerAppList
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
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.remote_server import RemoteServer
from pymobiledevice3.services.screenshot import ScreenshotService
from pymobiledevice3.services.dtfetchsymbols import DtFetchSymbols
from pymobiledevice3.services.simulate_location import DtSimulateLocation
from pymobiledevice3.tcp_forwarder import TcpForwarder


def wait_return():
    input('> Hit RETURN to exit')


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
                logging.info(f'killing {process_name}({pid})')
                process_control.kill(pid)


@dvt.command('launch', cls=Command)
@click.argument('arguments', type=click.STRING)
@click.option('--kill-existing/--no-kill-existing', default=True)
@click.option('--suspended', is_flag=True)
def launch(lockdown: LockdownClient, arguments: str, kill_existing: bool, suspended: bool):
    """
    Launch a process.
    :param lockdown: Lockdown client.
    :param arguments: Arguments of process to launch, the first argument is the bundle id.
    :param kill_existing: Whether to kill an existing instance of this process.
    :param suspended: Same as WaitForDebugger.
    """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        parsed_arguments = shlex.split(arguments)
        pid = ProcessControl(dvt).launch(parsed_arguments[0], parsed_arguments[1:], kill_existing, suspended)
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
        print_json({
            'system': device_info.system_information(),
            'hardware': device_info.hardware_information(),
            'network': device_info.network_information(),
        }, colored=color)


@dvt.command('netstat', cls=Command)
def netstat(lockdown: LockdownClient):
    """ Print information about current network activity. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with NetworkMonitor(dvt) as monitor:
            for event in monitor:
                if isinstance(event, ConnectionDetectionEvent):
                    logging.info(
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

                logging.info(entries)


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


def parse_filters(filters):
    if not filters:
        return None
    parsed = set()
    for filter_ in filters:
        print(filter_)
        if filter_.lower() == 'bsc':
            parsed |= {0x03010000, 0x040c0000, 0x07ff0000}  # VFS_LOOKUP, BSC operations, TRACE
        else:
            parsed.add(int(filter_, 16) << 16)

    return parsed


@core_profile_session.command('live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('-f', '--filters', multiple=True, help='Events filter. Omit for all.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--timestamp/--no-timestamp', default=True, help='Whether to print timestamp or not.')
@click.option('--event-name/--no-event-name', default=True, help='Whether to print event name or not.')
@click.option('--func-qual/--no-func-qual', default=True, help='Whether to print function qualifier or not.')
@click.option('--show-tid/--no-show-tid', default=True, help='Whether to print thread id or not.')
@click.option('--process-name/--no-process-name', default=True, help='Whether to print process name or not.')
@click.option('--args/--no-args', default=True, help='Whether to print event arguments or not.')
def live_profile_session(lockdown: LockdownClient, count, filters, tid, timestamp, event_name, func_qual,
                         show_tid, process_name, args):
    """ Print kevents received from the device in real time. """
    filters = parse_filters(filters)
    parser = PyKdebugParser()
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
@click.option('-f', '--filters', multiple=True, help='Events filter. Omit for all.')
def save_profile_session(lockdown: LockdownClient, out, filters):
    """ Dump core profiling information. """
    filters = parse_filters(filters)
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
                logging.error(f'Extracting stackshot failed')
                return

            if out is not None:
                json.dump(data, out, indent=4, default=default_json_encoder)
            else:
                print_json(data, colored=color)


@core_profile_session.command('parse-live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
@click.option('-f', '--filters', multiple=True, help='Events filter. Omit for all.')
@click.option('--color/--no-color', default=True)
def parse_live_profile_session(lockdown: LockdownClient, count, tid, show_tid, filters, color):
    """ Print traces (syscalls, thread events, etc.) received from the device in real time. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        filters = parse_filters(filters)
        print('Receiving time information')
        time_config = CoreProfileSessionTap.get_time_config(dvt)
        parser = PyKdebugParser()
        parser.numer = time_config['numer']
        parser.denom = time_config['denom']
        parser.mach_absolute_time = time_config['mach_absolute_time']
        parser.usecs_since_epoch = time_config['usecs_since_epoch']
        parser.timezone = time_config['timezone']
        parser.filter_tid = tid
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
def trace_codes(lockdown: LockdownClient, color):
    """ Print system information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)
        print_json({hex(k): v for k, v in device_info.trace_codes().items()}, colored=color)


@dvt.command('oslog', cls=Command)
@click.option('--color/--no-color', default=True)
@click.option('--pid', type=click.INT)
def dvt_oslog(lockdown: LockdownClient, color, pid):
    """ oslog. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with ActivityTraceTap(dvt) as tap:
            for message in tap:
                message_pid = message.process
                message_type = message.message_type
                sender_image_path = message.sender_image_path
                image_name = os.path.basename(sender_image_path)
                subsystem = message.subsystem
                category = message.category

                if pid is not None and message_pid != pid:
                    continue

                try:
                    formatted_message = decode_message_format(message.message).decode()
                except Exception:
                    print('error decoding')

                if color:
                    message_pid = colored(str(message_pid), 'magenta')
                    subsystem = colored(subsystem, 'green')
                    category = colored(category, 'green')
                    image_name = colored(image_name, 'yellow')
                    message_type = colored(message_type, 'cyan')

                print(f'[{subsystem}][{category}][{message_pid}][{image_name}] <{message_type}>: {formatted_message}')


@dvt.command('energy', cls=Command)
@click.argument('pid-list', nargs=-1)
def dvt_energy(lockdown: LockdownClient, pid_list):
    """ energy monitoring for given pid list. """

    if len(pid_list) == 0:
        logging.error('pid_list must not be empty')
        return

    pid_list = [int(pid) for pid in pid_list]

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with EnergyMonitor(dvt, pid_list) as energy_monitor:
            for telemetry in energy_monitor:
                logging.info(telemetry)


@dvt.command('notifications', cls=Command)
def dvt_notifications(lockdown: LockdownClient):
    """ monitor memory and app notifications """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with Notifications(dvt) as notifications:
            for notification in notifications:
                logging.info(notification)


@dvt.command('graphics', cls=Command)
def dvt_notifications(lockdown: LockdownClient):
    """ monitor graphics statistics """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with Graphics(dvt) as graphics:
            for stats in graphics:
                logging.info(stats)


@developer.command('fetch-symbols', cls=Command)
@click.argument('out', type=click.Path(dir_okay=True, file_okay=False))
def developer_fetch_symbols(lockdown: LockdownClient, out):
    """ download the linker and dyld cache to a specified directory """
    fetch_symbols = DtFetchSymbols(lockdown)
    files = fetch_symbols.list_files()

    if not os.path.exists(out):
        os.makedirs(out)

    for i, filename in enumerate(files):
        filename = os.path.join(out, os.path.basename(filename))
        with open(filename, 'wb') as f:
            logging.info(f'writing to: {filename}')
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

    def callback(name, data):
        if name in ('hostAppStateChanged:',
                    'hostInspectorCurrentElementChanged:',):
            for focus_item in data:
                logging.info(focus_item)

            if name == 'hostInspectorCurrentElementChanged:':
                if cycle_focus:
                    service.move_focus_next()

    service = AccessibilityAudit(lockdown)
    service.register_notifications_callback(callback)
    if cycle_focus:
        service.move_focus_next()
    service.listen_for_notifications()


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
def debugserver_shell(lockdown: LockdownClient, local_port):
    """
    start a debugserver at remote listening on a given port locally.

    Please note the connection must be done soon afterwards using your own lldb client.
    This can be done using the following commands within lldb shell:

    - platform select remote-ios

    - platform connect connect://localhost:<local_port>
    """
    attr = lockdown.get_service_connection_attributes('com.apple.debugserver.DVTSecureSocketProxy')
    TcpForwarder(lockdown, local_port, attr['Port'], attr.get('EnableServiceSSL', False)).start()
