# flake8: noqa: C901
import logging
import posixpath
import shlex
from dataclasses import asdict

import click

from pymobiledevice3.cli.cli_common import print_object, Command
from pymobiledevice3.exceptions import DvtDirListError, StartServiceError
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.application_listing import ApplicationListing
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.network_monitor import NetworkMonitor, ConnectionDetectionEvent
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
from pymobiledevice3.services.screenshot import ScreenshotService


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
def launch(lockdown, arguments: str, kill_existing: bool, suspended: bool):
    """
    Launch a process.
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
