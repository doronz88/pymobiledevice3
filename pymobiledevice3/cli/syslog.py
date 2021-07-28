import logging
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


def format_line(color, pid, syslog_entry, include_label):
    log_level_colors = {
        'Notice': 'white',
        'Error': 'red',
        'Fault': 'red',
        'Warning': 'yellow',
    }

    syslog_pid = syslog_entry.pid
    timestamp = syslog_entry.timestamp
    level = syslog_entry.level
    filename = syslog_entry.filename
    image_name = os.path.basename(syslog_entry.image_name)
    message = syslog_entry.message
    process_name = os.path.basename(filename)
    label = ''

    if (pid != -1) and (syslog_pid != pid):
        return None

    if syslog_entry.label is not None:
        label = f'[{syslog_entry.label.subsystem}][{syslog_entry.label.category}]'

    if color:
        timestamp = colored(str(timestamp), 'green')
        process_name = colored(process_name, 'magenta')
        if len(image_name) > 0:
            image_name = colored(image_name, 'magenta')
        syslog_pid = colored(syslog_entry['pid'], 'cyan')

        if level in syslog_entry:
            level = colored(level, log_level_colors[level])

        label = colored(label, 'cyan')
        message = colored(syslog_entry['message'], 'white')

    line_format = '{timestamp} {process_name}{{{image_name}}}[{pid}] <{level}>: {message}'

    if include_label:
        line_format += f' {label}'

    line = line_format.format(timestamp=timestamp, process_name=process_name, image_name=image_name, pid=syslog_pid,
                              level=level, message=message)

    return line


@syslog.command('live', cls=Command)
@click.option('-o', '--out', type=click.File('wt'), help='log file')
@click.option('--color/--no-color', default=True, help='disable colors')
@click.option('--pid', type=click.INT, default=-1, help='pid to filter. -1 for all')
@click.option('-m', '--match', multiple=True, help='match expression')
@click.option('-mi', '--match-insensitive', multiple=True, help='insensitive match expression')
@click.option('include_label', '--label', is_flag=True, help='should include label')
def syslog_live(lockdown, out, color, pid, match, match_insensitive, include_label):
    """ view live syslog lines """

    for syslog_entry in OsTraceService(lockdown=lockdown).syslog(pid=pid):
        line = format_line(color, pid, syslog_entry, include_label)

        skip = False

        if match is not None:
            for m in match:
                match_line = line
                if m not in match_line:
                    skip = True
                    break
                else:
                    if color:
                        match_line = match_line.replace(m, colored(m, attrs=['bold', 'underline']))
                        line = match_line

        if match_insensitive is not None:
            for m in match_insensitive:
                m = m.lower()
                if m not in line.lower():
                    skip = True
                    break
                else:
                    if color:
                        start = line.lower().index(m)
                        end = start + len(m)
                        line = line[:start] + colored(m, attrs=['bold', 'underline']) + line[end:]

        if skip:
            continue

        print(line)

        if out:
            out.write(line)


@syslog.command('collect', cls=Command)
@click.argument('out', type=click.Path(exists=False, dir_okay=True, file_okay=True))
def syslog_collect(lockdown, out):
    """
    Collect the system logs into a .logarchive that can be viewed later with tools such as log or Console.
    If the filename doesn't exist, system_logs.logarchive will be created in the given directory.
    """

    if os.path.isdir(out):
        out = os.path.join(out, 'system_logs.logarchive')

    if not os.path.exists(out):
        os.makedirs(out)

    if not out.endswith('.logarchive'):
        logging.warning('given out path doesn\'t end with a .logarchive - consider renaming to be able to view'
                        'the file with the likes of the Console.app and the `log show` utilities')

    OsTraceService(lockdown=lockdown).collect(out)
