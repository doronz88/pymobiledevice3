# flake8: noqa: C901
import json
import logging
import os
import posixpath
import shlex
from dataclasses import asdict

import click
from pymobiledevice3.cli.cli_common import print_object, Command
from pymobiledevice3.exceptions import DvtDirListError, StartServiceError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.activity_trace_tap import ActivityTraceTap, decode_message_format
from pymobiledevice3.services.dvt.instruments.kdebug_events_parser import KdebugEventsParser
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.core_profile_session_tap import CoreProfileSessionTap, DgbFuncQual, \
    ProcessData
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.network_monitor import NetworkMonitor, ConnectionDetectionEvent
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
from pymobiledevice3.services.screenshot import ScreenshotService
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
    try:
        out.write(ScreenshotService(lockdown=lockdown).take_screenshot())
    except StartServiceError:
        logging.error('failed to connect to required service. make sure DeveloperDiskImage.dmg has been mounted. '
                      'You can do so using: pymobiledevice3 mounter mount')


@developer.command('proclist', cls=Command)
@click.option('--nocolor', is_flag=True)
def proclist(lockdown, nocolor):
    """ show process list """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        processes = DeviceInfo(dvt).proclist()
        for process in processes:
            if 'startDate' in process:
                process['startDate'] = str(process['startDate'])

        print_object(processes, colored=not nocolor)


@developer.command('applist', cls=Command)
@click.option('--nocolor', is_flag=True)
def applist(lockdown, nocolor):
    """ show application list """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        apps = ApplicationListing(dvt).applist()
        print_object(apps, colored=not nocolor)


@developer.command('kill', cls=Command)
@click.argument('pid', type=click.INT)
def kill(lockdown, pid):
    """ Kill a process by its pid. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        ProcessControl(dvt).kill(pid)


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
        print_object({
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


@sysmon.command('processes', cls=Command)
@click.option('-f', '--fields', help='show only given field names splitted by ",".')
@click.option('-a', '--attributes', multiple=True,
              help='filter processes by given attribute value given as key=value')
def sysmon_processes(lockdown, fields, attributes):
    """ show currently running processes information. """

    if fields is not None:
        fields = fields.split(',')

    count = 0

    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        sysmontap = Sysmontap(dvt)
        with sysmontap as sysmon:
            for row in sysmon:
                if 'Processes' in row:
                    processes = row['Processes'].items()
                    count += 1

                    if count > 1:
                        # give some time for cpuUsage field to populate
                        break

        device_info = DeviceInfo(dvt)
        for pid, process in processes:
            attrs = sysmontap.process_attributes_cls(*process)

            skip = False
            if attributes is not None:
                for filter_attr in attributes:
                    filter_attr, filter_value = filter_attr.split('=')
                    if str(getattr(attrs, filter_attr)) != filter_value:
                        skip = True
                        break

            if skip:
                continue

            print(f'{attrs.name} ({attrs.pid})')
            attrs_dict = asdict(attrs)

            attrs_dict['execname'] = device_info.execname_for_pid(pid)

            for name, value in attrs_dict.items():
                if (fields is None) or (name in fields):
                    print(f'\t{name}: {value}')


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


@core_profile_session.command('live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('-cf', '--class-filter', type=click.INT, default=None, help='Events class to filter. Omit for all.')
@click.option('-sf', '--subclass-filter', type=click.INT, default=None, help='Events subclass to filter. Omit for all.')
@click.option('--pid', type=click.INT, default=None, help='Process ID to filter. Omit for all.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--timestamp/--no-timestamp', default=True, help='Whether to print timestamp or not.')
@click.option('--event-name/--no-event-name', default=True, help='Whether to print event name or not.')
@click.option('--func-qual/--no-func-qual', default=True, help='Whether to print function qualifier or not.')
@click.option('--show-tid/--no-show-tid', default=True, help='Whether to print thread id or not.')
@click.option('--process-name/--no-process-name', default=True, help='Whether to print process name or not.')
@click.option('--args/--no-args', default=True, help='Whether to print event arguments or not.')
def live_profile_session(lockdown, count, class_filter, subclass_filter, pid, tid, timestamp, event_name, func_qual,
                         show_tid, process_name, args):
    """ Print core profiling information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()
        with CoreProfileSessionTap(dvt, class_filter, subclass_filter) as tap:
            for event in tap.watch_events(count):
                if event.eventid in trace_codes_map:
                    name = trace_codes_map[event.eventid] + f' ({hex(event.eventid)})'
                else:
                    # Some event IDs are not public.
                    name = hex(event.eventid)
                try:
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
                        formatted_data += f'{str(tap.parse_event_time(event.timestamp)):<27}'
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
                    formatted_data += f'{str(event.args.data):<34}' if args else ''
                    print(formatted_data)
                except (ValueError, KeyError):
                    pass


@core_profile_session.command('save', cls=Command)
@click.argument('out', type=click.File('wb'))
@click.option('-cf', '--class-filter', type=click.INT, default=None, help='Events class to filter. Omit for all.')
@click.option('-sf', '--subclass-filter', type=click.INT, default=None, help='Events subclass to filter. Omit for all.')
def save_profile_session(lockdown, out, class_filter, subclass_filter):
    """ Dump core profiling information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with CoreProfileSessionTap(dvt, class_filter, subclass_filter) as tap:
            tap.dump(out)


@core_profile_session.command('stackshot', cls=Command)
@click.option('--out', type=click.File('w'), default=None)
@click.option('--nocolor', is_flag=True)
def stackshot(lockdown, out, nocolor):
    """ Dump stackshot information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        with CoreProfileSessionTap(dvt) as tap:
            data = tap.get_stackshot()
            if out is not None:
                json.dump(data, out, indent=4)
            else:
                print_object(data, colored=not nocolor)


@core_profile_session.command('parse-live', cls=Command)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('-cf', '--class-filter', type=click.INT, default=None, help='Events class to filter. Omit for all.')
@click.option('-sf', '--subclass-filter', type=click.INT, default=None, help='Events subclass to filter. Omit for all.')
@click.option('--pid', type=click.INT, default=None, help='Process ID to filter. Omit for all.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
def parse_live_profile_session(lockdown, count, class_filter, subclass_filter, pid, tid, show_tid):
    """ Parse core profiling information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        trace_codes_map = DeviceInfo(dvt).trace_codes()
        with CoreProfileSessionTap(dvt, class_filter, subclass_filter) as tap:
            events_parser = KdebugEventsParser(trace_codes_map)
            for event in tap.watch_events(count):
                if tid is not None and event.tid != tid:
                    continue
                try:
                    process = tap.thread_map[event.tid]
                except KeyError:
                    process = ProcessData(pid=-1, name='')
                if pid is not None and process.pid != pid:
                    continue
                events_parser.feed(event)
                parsed = events_parser.fetch()
                if parsed is None:
                    continue
                formatted_data = f'{str(tap.parse_event_time(parsed.ktraces[0].timestamp)):<27}'
                formatted_data += f'{hex(event.tid):<12}' if show_tid else ''
                process_rep = (f'{process.name}({process.pid})'
                               if process.pid != -1
                               else f'Error: tid {event.tid}')
                formatted_data += f'{process_rep:<27}'
                print(formatted_data + str(parsed))


@developer.command('trace-codes', cls=Command)
@click.option('--nocolor', is_flag=True)
def trace_codes(lockdown, nocolor):
    """ Print system information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        device_info = DeviceInfo(dvt)
        print_object({hex(k): v for k, v in device_info.trace_codes().items()}, colored=not nocolor)


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
