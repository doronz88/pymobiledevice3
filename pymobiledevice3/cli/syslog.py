import os

import click
from termcolor import colored

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.syslog import SyslogService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def syslog():
    """ syslog options """
    pass


@syslog.command('live-old', cls=Command)
def syslog_live_old(lockdown):
    """ view live syslog lines in raw bytes form from old relay """
    for line in SyslogService(lockdown=lockdown).watch():
        print(line)


@syslog.command('live', cls=Command)
@click.option('-o', '--out', type=click.File('wt'), help='log file')
@click.option('--nocolor', is_flag=True, help='disable colors')
@click.option('--pid', type=click.INT, default=-1, help='pid to filter. -1 for all')
@click.option('-m', '--match', help='match expression')
@click.option('include_label', '--label', is_flag=True, help='should include label')
def syslog_live(lockdown, out, nocolor, pid, match, include_label):
    """ view live syslog lines """

    log_level_colors = {
        'Notice': 'white',
        'Error': 'red',
        'Fault': 'red',
        'Warning': 'yellow',
    }

    for syslog_entry in OsTraceService(lockdown=lockdown).syslog(pid=pid):
        pid = syslog_entry.pid
        timestamp = syslog_entry.timestamp
        level = syslog_entry.level
        filename = syslog_entry.filename
        image_name = os.path.basename(syslog_entry.image_name)
        message = syslog_entry.message
        process_name = os.path.basename(filename)
        label = ''
        if syslog_entry.label is not None:
            label = f'[{syslog_entry.label.bundle_id}][{syslog_entry.label.identifier}]'

        if not nocolor:
            timestamp = colored(str(timestamp), 'green')
            process_name = colored(process_name, 'magenta')
            if len(image_name) > 0:
                image_name = colored(image_name, 'magenta')
            pid = colored(syslog_entry['pid'], 'cyan')

            if level in syslog_entry:
                level = colored(level, log_level_colors[level])

            label = colored(label, 'cyan')
            message = colored(syslog_entry['message'], 'white')

        line_format = '{timestamp} {process_name}{{{image_name}}}[{pid}] <{level}>: {message}'

        if include_label:
            line_format += f' {label}'

        line = line_format.format(timestamp=timestamp, process_name=process_name, image_name=image_name, pid=pid,
                                  level=level, label=label, message=message)

        if match and match not in line:
            continue

        print(line)

        if out:
            out.write(line)


@syslog.command('archive', cls=Command)
@click.argument('out', type=click.File('wb'))
def syslog_archive(lockdown, out):
    """
    create PAX archive.
    use `pax -r < filename` for extraction.
    """
    result, tar = OsTraceService(lockdown=lockdown).create_archive()
    out.write(tar)
