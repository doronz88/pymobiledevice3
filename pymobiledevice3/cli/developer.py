# flake8: noqa: C901
import json
import logging
import os
import posixpath
import shlex
from collections import namedtuple
from dataclasses import asdict
from functools import partial

import click
from pygments import highlight, lexers, formatters
from pymobiledevice3.cli.cli_common import print_json, Command
from pymobiledevice3.exceptions import DvtDirListError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.activity_trace_tap import ActivityTraceTap, decode_message_format
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap, DgbFuncQual, \
    ProcessData
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.energy_monitor import EnergyMonitor
from pymobiledevice3.services.dvt.instruments.kdebug_events_parser import KdebugEventsParser
from pymobiledevice3.services.dvt.instruments.network_monitor import NetworkMonitor, ConnectionDetectionEvent
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
from pymobiledevice3.services.dvt.instruments.audit import Audit
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.screenshot import ScreenshotService
from pymobiledevice3.services.dtfetchsymbols import DtFetchSymbols
from pymobiledevice3.services.simulate_location import DtSimulateLocation
from termcolor import colored


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


@developer.command(cls=Command)
@click.argument('out', type=click.File('wb'))
def screenshot(lockdown, out):
    """ take a screenshot in PNG format """
    out.write(ScreenshotService(lockdown=lockdown).take_screenshot())


@developer.command('proclist', cls=Command)
@click.option('--nocolor', is_flag=True)
def proclist(lockdown, nocolor):
    """ show process list """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        processes = DeviceInfo(dvt).proclist()
        for process in processes:
            if 'startDate' in process:
                process['startDate'] = str(process['startDate'])

        print_json(processes, colored=not nocolor)


@developer.command('applist', cls=Command)
@click.option('--nocolor', is_flag=True)
def applist(lockdown, nocolor):
    """ show application list """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        apps = ApplicationListing(dvt).applist()
        print_json(apps, colored=not nocolor)


@developer.command('kill', cls=Command)
@click.argument('pid', type=click.INT)
def kill(lockdown, pid):
    """ Kill a process by its pid. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ProcessControl(dvt).kill(pid)


@developer.command('pkill', cls=Command)
@click.argument('expression')
def pkill(lockdown, expression):
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


@developer.command('launch', cls=Command)
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


@developer.command('shell', cls=Command)
def shell(lockdown):
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


@developer.command('ls', cls=Command)
@click.argument('path', type=click.Path(exists=False))
@click.option('-r', '--recursive', is_flag=True)
def ls(lockdown, path, recursive):
    """ List directory. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        show_dirlist(DeviceInfo(dvt), path, recursive=recursive)


@developer.command('device-information', cls=Command)
@click.option('--nocolor', is_flag=True)
def device_information(lockdown, nocolor):
    """ Print system information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)
        print_json({
            'system': device_info.system_information(),
            'hardware': device_info.hardware_information(),
            'network': device_info.network_information(),
        }, colored=not nocolor)


@developer.command('netstat', cls=Command)
def netstat(lockdown):
    """ Print information about current network activity. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with NetworkMonitor(dvt) as monitor:
            for event in monitor:
                if isinstance(event, ConnectionDetectionEvent):
                    logging.info(
                        f'Connection detected: {event.local_address.data.address}:{event.local_address.port} -> '
                        f'{event.remote_address.data.address}:{event.remote_address.port}')


@developer.group('sysmon')
def sysmon():
    """ System monitor options. """


@sysmon.group('process')
def sysmon_process():
    """ Process monitor options. """


@sysmon_process.command('monitor', cls=Command)
@click.argument('threshold', type=click.FLOAT)
def sysmon_process_monitor(lockdown, threshold):
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
def sysmon_process_single(lockdown, fields, attributes):
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
def sysmon_system(lockdown, fields):
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


@developer.group('core-profile-session')
def core_profile_session():
    """ Core profile session options. """


def parse_filters(filters):
    if not filters:
        return None
    parsed = set()
    for filter_ in filters:
        print(filter_)
        if filter_ == 'fs_usage':
            parsed |= {0x03010000, 0x040c0000, 0x07ff0000}  # VFS_LOOKUP, BSC operations, TRACE
        else:
            parsed.add(int(filter_, 16) << 16)

    return parsed


def format_timestamp(core_session_tap, timestamp):
    time_string = core_session_tap.parse_event_time(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
    return f'{time_string:<27}'


@core_profile_session.command('live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('-f', '--filters', multiple=True, help='Events filter. Omit for all.')
@click.option('--pid', type=click.INT, default=None, help='Process ID to filter. Omit for all.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--timestamp/--no-timestamp', default=True, help='Whether to print timestamp or not.')
@click.option('--event-name/--no-event-name', default=True, help='Whether to print event name or not.')
@click.option('--func-qual/--no-func-qual', default=True, help='Whether to print function qualifier or not.')
@click.option('--show-tid/--no-show-tid', default=True, help='Whether to print thread id or not.')
@click.option('--process-name/--no-process-name', default=True, help='Whether to print process name or not.')
@click.option('--args/--no-args', default=True, help='Whether to print event arguments or not.')
def live_profile_session(lockdown, count, filters, pid, tid, timestamp, event_name, func_qual,
                         show_tid, process_name, args):
    """ Print core profiling information. """
    filters = parse_filters(filters)
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()
        print('Receiving time information')
        time_config = CoreProfileSessionTap.get_time_config(dvt)
        with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            for event in tap.watch_events(count):
                if event.eventid in trace_codes_map:
                    name = trace_codes_map[event.eventid] + f' ({hex(event.eventid)})'
                else:
                    # Some event IDs are not public.
                    name = hex(event.eventid)
                if tid is not None and event.tid != tid:
                    continue
                try:
                    process = tap.thread_map[event.tid]
                except KeyError:
                    process = ProcessData(pid=-1, name='')
                if pid is not None and process.pid != pid:
                    continue
                formatted_data = ''
                if timestamp:
                    formatted_data += format_timestamp(tap, event.timestamp)
                formatted_data += f'{name:<58}' if event_name else ''
                if func_qual:
                    try:
                        formatted_data += f'{DgbFuncQual(event.func_qualifier).name:<15}'
                    except ValueError:
                        formatted_data += f'''{'Error':<16}'''
                formatted_data += f'{hex(event.tid):<12}' if show_tid else ''
                if process_name:
                    process_rep = (f'{process.name}({process.pid})'
                                   if process.pid != -1
                                   else f'Error: tid {event.tid}')
                    formatted_data += f'{process_rep:<27}' if process_name else ''
                formatted_data += f'{str(event.data):<34}' if args else ''
                print(formatted_data)


@core_profile_session.command('save', cls=Command)
@click.argument('out', type=click.File('wb'))
@click.option('-f', '--filters', multiple=True, help='Events filter. Omit for all.')
def save_profile_session(lockdown, out, filters):
    """ Dump core profiling information. """
    filters = parse_filters(filters)
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with CoreProfileSessionTap(dvt, {}, filters) as tap:
            tap.dump(out)


@core_profile_session.command('stackshot', cls=Command)
@click.option('--out', type=click.File('w'), default=None)
@click.option('--nocolor', is_flag=True)
def stackshot(lockdown, out, nocolor):
    """ Dump stackshot information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with CoreProfileSessionTap(dvt, {}) as tap:
            data = tap.get_stackshot()
            if out is not None:
                json.dump(data, out, indent=4)
            else:
                print_json(data, colored=not nocolor)


def parse_live_print(tap, pid, show_tid, parsed, nocolor):
    tid = parsed.ktraces[0].tid
    try:
        process = tap.thread_map[tid]
    except KeyError:
        process = ProcessData(pid=-1, name='')
    if pid is not None and process.pid != pid:
        return
    if parsed is None:
        return

    formatted_data = format_timestamp(tap, parsed.ktraces[0].timestamp)
    formatted_data += f'{tid:>11} ' if show_tid else ''
    process_rep = (f'{process.name}({process.pid})'
                   if process.pid != -1
                   else f'Error: tid {tid}')
    formatted_data += f'{process_rep:<34}'
    if nocolor:
        event_rep = str(parsed)
    else:
        event_rep = highlight(
            str(parsed), lexers.CLexer(), formatters.TerminalTrueColorFormatter(style='stata-dark')).strip()

    print(formatted_data + event_rep)


@core_profile_session.command('parse-live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('--pid', type=click.INT, default=None, help='Process ID to filter. Omit for all.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
@click.option('-f', '--filters', multiple=True, help='Events filter. Omit for all.')
@click.option('--nocolor', is_flag=True, help='disable colors')
def parse_live_profile_session(lockdown, count, pid, tid, show_tid, filters, nocolor):
    """ Parse core profiling information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()

        filters = parse_filters(filters)
        print('Receiving time information')
        time_config = CoreProfileSessionTap.get_time_config(dvt)
        with CoreProfileSessionTap(dvt, time_config, filters) as tap:
            events_callback = partial(parse_live_print, tap, pid, show_tid, nocolor=nocolor)
            events_parser = KdebugEventsParser(events_callback, trace_codes_map, tap.thread_map)
            if show_tid:
                print('{:^26}|{:^11}|{:^33}|   Event'.format('Time', 'Thread', 'Process'))
            else:
                print('{:^26}|{:^33}|   Event'.format('Time', 'Process'))
            for event in tap.watch_events(count):
                if tid is not None and event.tid != tid:
                    continue
                events_parser.feed(event)


@developer.command('trace-codes', cls=Command)
@click.option('--nocolor', is_flag=True)
def trace_codes(lockdown, nocolor):
    """ Print system information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)
        print_json({hex(k): v for k, v in device_info.trace_codes().items()}, colored=not nocolor)


@developer.command('oslog', cls=Command)
@click.option('--nocolor', is_flag=True, help='disable colors')
@click.option('--pid', type=click.INT)
def developer_oslog(lockdown, nocolor, pid):
    """ oslog. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with ActivityTraceTap(dvt) as tap:
            for message in tap:
                message_pid = message.process
                timestamp = message.time
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

                if not nocolor:
                    message_pid = colored(str(message_pid), 'magenta')
                    subsystem = colored(subsystem, 'green')
                    category = colored(category, 'green')
                    image_name = colored(image_name, 'yellow')
                    message_type = colored(message_type, 'cyan')

                print(f'[{subsystem}][{category}][{message_pid}][{image_name}] <{message_type}>: {formatted_message}')


@developer.command('energy', cls=Command)
@click.argument('pid-list', nargs=-1)
def developer_energy(lockdown, pid_list):
    """ energy monitoring for given pid list. """

    if len(pid_list) == 0:
        logging.error('pid_list must not be empty')
        return

    pid_list = [int(pid) for pid in pid_list]

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with EnergyMonitor(dvt, pid_list) as energy_monitor:
            for telemetry in energy_monitor:
                logging.info(telemetry)


@developer.command('fetch-symbols', cls=Command)
@click.argument('out', type=click.Path(dir_okay=True, file_okay=False))
def developer_fetch_symbols(lockdown, out):
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
def simulate_location_clear(lockdown):
    """ clear simulated location """
    DtSimulateLocation(lockdown).clear()


@simulate_location.command('set', cls=Command)
@click.argument('latitude', type=click.FLOAT)
@click.argument('longitude', type=click.FLOAT)
def simulate_location_set(lockdown, latitude, longitude):
    """
    set a simulated location.
    try:
        ... set -- 40.690008 -74.045843 for liberty island
    """
    DtSimulateLocation(lockdown).set(latitude, longitude)


@simulate_location.command('play', cls=Command)
@click.argument('filename', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option('--disable-sleep', is_flag=True, default=False)
def simulate_location_play(lockdown, filename, disable_sleep):
    """
    play a .gpx file
    """
    DtSimulateLocation(lockdown).play_gpx_file(filename, disable_sleep=disable_sleep)


@developer.command('audit-capabilities', cls=Command)
def audit(lockdown):
    """ display audit capabilities """
    print_json(Audit(lockdown).device_capabilities())


@developer.group('condition')
def condition():
    """ condition inducer options. """
    pass


@condition.command('list', cls=Command)
def condition_list(lockdown):
    """ list all available conditions """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        print_json(ConditionInducer(dvt).list())


@condition.command('clear', cls=Command)
def condition_clear(lockdown):
    """ clear current condition """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ConditionInducer(dvt).clear()


@condition.command('set', cls=Command)
@click.argument('profile_identifier')
def condition_set(lockdown, profile_identifier):
    """ set a specific condition """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ConditionInducer(dvt).set(profile_identifier)
        input('> Hit RETURN in order to end the current condition')
