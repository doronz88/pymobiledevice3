import logging
import os
import posixpath
import re

import click

from pymobiledevice3.cli.cli_common import Command, get_last_used_terminal_formatting, user_requested_colored_output
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.os_trace import OsTraceService, SyslogLogLevel
from pymobiledevice3.services.syslog import SyslogService

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ syslog cli """
    pass


@cli.group()
def syslog():
    """ syslog options """
    pass


@syslog.command('live-old', cls=Command)
def syslog_live_old(service_provider: LockdownClient):
    """ view live syslog lines in raw bytes form from old relay """
    for line in SyslogService(service_provider=service_provider).watch():
        print(line)


def format_line(color, pid, syslog_entry, include_label):
    log_level_colors = {
        SyslogLogLevel.NOTICE.name: 'white',
        SyslogLogLevel.INFO.name: 'white',
        SyslogLogLevel.DEBUG.name: 'green',
        SyslogLogLevel.ERROR.name: 'red',
        SyslogLogLevel.FAULT.name: 'red',
        SyslogLogLevel.USER_ACTION.name: 'white',
    }

    syslog_pid = syslog_entry.pid
    timestamp = syslog_entry.timestamp
    level = syslog_entry.level.name
    filename = syslog_entry.filename
    image_name = posixpath.basename(syslog_entry.image_name)
    message = syslog_entry.message
    process_name = posixpath.basename(filename)
    label = ''

    if (pid != -1) and (syslog_pid != pid):
        return None

    if syslog_entry.label is not None:
        label = f'[{syslog_entry.label.subsystem}][{syslog_entry.label.category}]'

    if color:
        timestamp = click.style(str(timestamp), 'green')
        process_name = click.style(process_name, 'magenta')
        if len(image_name) > 0:
            image_name = click.style(image_name, 'magenta')
        syslog_pid = click.style(syslog_pid, 'cyan')
        log_level_color = log_level_colors[level]
        level = click.style(level, log_level_color)
        label = click.style(label, 'cyan')
        message = click.style(message, log_level_color)

    line_format = '{timestamp} {process_name}{{{image_name}}}[{pid}] <{level}>: {message}'

    if include_label:
        line_format += f' {label}'

    line = line_format.format(timestamp=timestamp, process_name=process_name, image_name=image_name, pid=syslog_pid,
                              level=level, message=message)

    return line


@syslog.command('live', cls=Command)
@click.option('-o', '--out', type=click.File('wt'), help='log file')
@click.option('--pid', type=click.INT, default=-1, help='pid to filter. -1 for all')
@click.option('-pn', '--process-name', help='process name to filter')
@click.option('-m', '--match', multiple=True, help='match expression')
@click.option('-mi', '--match-insensitive', multiple=True, help='insensitive match expression')
@click.option('include_label', '--label', is_flag=True, help='should include label')
@click.option('-e', '--regex', multiple=True, help='filter only lines matching given regex')
@click.option('-ei', '--insensitive-regex', multiple=True, help='filter only lines matching given regex (insensitive)')
def syslog_live(service_provider: LockdownClient, out, pid, process_name, match, match_insensitive,
                include_label, regex, insensitive_regex):
    """ view live syslog lines """

    match_regex = [re.compile(f'.*({r}).*', re.DOTALL) for r in regex]
    match_regex += [re.compile(f'.*({r}).*', re.IGNORECASE | re.DOTALL) for r in insensitive_regex]

    def replace(m):
        if len(m.groups()):
            return line.replace(m.group(1), click.style(m.group(1), bold=True, underline=True))
        return None

    for syslog_entry in OsTraceService(lockdown=service_provider).syslog(pid=pid):
        if process_name:
            if posixpath.basename(syslog_entry.filename) != process_name:
                continue

        line_no_style = format_line(False, pid, syslog_entry, include_label)
        line = format_line(user_requested_colored_output(), pid, syslog_entry, include_label)

        skip = False

        if match is not None:
            for m in match:
                match_line = line
                if m not in match_line:
                    skip = True
                    break
                else:
                    if user_requested_colored_output():
                        match_line = match_line.replace(m, click.style(m, bold=True, underline=True))
                        line = match_line

        if match_insensitive is not None:
            for m in match_insensitive:
                m = m.lower()
                if m not in line.lower():
                    skip = True
                    break
                else:
                    if user_requested_colored_output():
                        start = line.lower().index(m)
                        end = start + len(m)
                        last_color_formatting = get_last_used_terminal_formatting(line[:start])
                        line = line[:start] + click.style(line[start:end], bold=True,
                                                          underline=True) + last_color_formatting + line[end:]

        if match_regex:
            skip = True
            for r in match_regex:
                if not r.findall(line_no_style):
                    continue
                line = re.sub(r, replace, line)
                skip = False

        if skip:
            continue

        print(line, flush=True)

        if out:
            if user_requested_colored_output():
                print(line, file=out, flush=True)
            else:
                print(line_no_style, file=out, flush=True)


@syslog.command('collect', cls=Command)
@click.argument('out', type=click.Path(exists=False, dir_okay=True, file_okay=False))
@click.option('--size-limit', type=click.INT)
@click.option('--age-limit', type=click.INT)
@click.option('--start-time', type=click.INT)
def syslog_collect(service_provider: LockdownClient, out, size_limit, age_limit, start_time):
    """
    Collect the system logs into a .logarchive that can be viewed later with tools such as log or Console.
    If the filename doesn't exist, system_logs.logarchive will be created in the given directory.
    """
    if not os.path.exists(out):
        os.makedirs(out)

    if not out.endswith('.logarchive'):
        logger.warning('given out path doesn\'t end with a .logarchive - consider renaming to be able to view '
                       'the file with the likes of the Console.app and the `log show` utilities')

    OsTraceService(lockdown=service_provider).collect(out, size_limit=size_limit, age_limit=age_limit,
                                                      start_time=start_time)
