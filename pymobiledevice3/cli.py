#!/usr/bin/env python3
import os
from pprint import pprint
import logging
import json

from termcolor import colored
import coloredlogs
import IPython
import click
from pygments import highlight, lexers, formatters

from pymobiledevice3.afc import AFCShell
from pymobiledevice3.diagnostics_service import DiagnosticsService
from pymobiledevice3.installation_proxy_service import InstallationProxyService
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.mobile_config import MobileConfigService
from pymobiledevice3.notification_proxy_service import NotificationProxyService
from pymobiledevice3.os_trace_service import OsTraceService
from pymobiledevice3.pcapd_service import PcapdService
from pymobiledevice3.screenshot_service import ScreenshotService
from pymobiledevice3.dvt_secure_socket_proxy import DvtSecureSocketProxyService

coloredlogs.install(level=logging.DEBUG)

logging.getLogger('asyncio').disabled = True
logging.getLogger('parso.cache').disabled = True
logging.getLogger('parso.cache.pickle').disabled = True
logging.getLogger('parso.python.diff').disabled = True
logging.getLogger('humanfriendly.prompts').disabled = True


def print_object(buf, colored=True):
    if colored:
        formatted_json = json.dumps(buf, sort_keys=True, indent=4)
        colorful_json = highlight(formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter())
        print(colorful_json)
    else:
        pprint(buf)


@click.group()
def cli():
    pass


@cli.group()
def apps():
    """ application options """
    pass


@apps.command('list')
@click.option('--udid')
@click.option('-u', '--user', is_flag=True, help='include user apps')
@click.option('-s', '--system', is_flag=True, help='include system apps')
def apps_list(udid, user, system):
    """ list installed apps """
    lockdown = LockdownClient(udid=udid)
    app_types = []
    if user:
        app_types.append('User')
    if system:
        app_types.append('System')
    pprint(InstallationProxyService(lockdown=lockdown).get_apps(app_types))


@apps.command('uninstall')
@click.option('--udid')
@click.argument('bundle_id')
def apps_uninstall(udid, bundle_id):
    """ uninstall app by given bundle_id """
    lockdown = LockdownClient(udid=udid)
    pprint(InstallationProxyService(lockdown=lockdown).uninstall(bundle_id))


@apps.command('install')
@click.option('--udid')
@click.argument('ipa_path', type=click.Path(exists=True))
def apps_install(udid, ipa_path):
    """ install given .ipa """
    lockdown = LockdownClient(udid=udid)
    pprint(InstallationProxyService(lockdown=lockdown).install_from_local(ipa_path))


@cli.group()
def config():
    """ configuration options """
    pass


@config.command('list')
@click.option('--udid')
def config_list(udid):
    """ list installed profiles """
    lockdown = LockdownClient(udid=udid)
    pprint(MobileConfigService(lockdown=lockdown).get_profile_list())


@config.command('install')
@click.option('--udid')
@click.argument('profile', type=click.File('rb'))
def config_install(udid, profile):
    """ install given profile file """
    lockdown = LockdownClient(udid=udid)
    pprint(MobileConfigService(lockdown=lockdown).install_profile(profile.read()))


@config.command('remove')
@click.option('--udid')
@click.argument('name')
def config_remove(udid, name):
    """ remove profile by name """
    lockdown = LockdownClient(udid=udid)
    pprint(MobileConfigService(lockdown=lockdown).remove_profile(name))


@cli.group()
def lockdown():
    """ lockdown options """
    pass


@lockdown.command('recovery')
@click.option('--udid')
def lockdown_recovery(udid):
    """ enter recovery """
    pprint(LockdownClient(udid=udid).enter_recovery())


@lockdown.command('service')
@click.option('--udid')
@click.argument('service_name')
def lockdown_service(udid, service_name):
    """ send-receive raw service messages """
    lockdown = LockdownClient(udid=udid)
    client = lockdown.start_service(service_name)
    logging.info('use `client` variable to interact with the connected service')
    IPython.embed()


@cli.group()
def diagnostics():
    """ diagnostics options """
    pass


@diagnostics.command('restart')
@click.option('--udid')
def diagnostics_restart(udid):
    """ restart device """
    lockdown = LockdownClient(udid=udid)
    DiagnosticsService(lockdown=lockdown).restart()


@diagnostics.command('shutdown')
@click.option('--udid')
def diagnostics_shutdown(udid):
    """ shutdown device """
    lockdown = LockdownClient(udid=udid)
    DiagnosticsService(lockdown=lockdown).shutdown()


@diagnostics.command('sleep')
@click.option('--udid')
def diagnostics_sleep(udid):
    """ put device into sleep """
    lockdown = LockdownClient(udid=udid)
    DiagnosticsService(lockdown=lockdown).sleep()


@diagnostics.command('info')
@click.option('--udid')
def diagnostics_info(udid):
    """ get diagnostics info """
    lockdown = LockdownClient(udid=udid)
    pprint(DiagnosticsService(lockdown=lockdown).info())


@diagnostics.command('ioregistry')
@click.option('--udid')
@click.option('--plane')
@click.option('--name')
@click.option('--ioclass')
def diagnostics_ioregistry(udid, plane, name, ioclass):
    """ get ioregistry info """
    lockdown = LockdownClient(udid=udid)
    pprint(DiagnosticsService(lockdown=lockdown).ioregistry(plane=plane, name=name, ioclass=ioclass))


@diagnostics.command('mg')
@click.option('--udid')
@click.argument('keys', nargs=-1, default=None)
def diagnostics_mg(udid, keys):
    """ get MobileGestalt key values from given list. If empty, return all known. """
    lockdown = LockdownClient(udid=udid)
    pprint(DiagnosticsService(lockdown=lockdown).mobilegestalt(keys=keys))


@cli.group()
def syslog():
    """ syslog options """
    pass


@syslog.command('live')
@click.option('--udid')
@click.option('-o', '--out', type=click.File('wt'), help='log file')
@click.option('--nocolor', is_flag=True, help='disable colors')
@click.option('--pid', type=click.INT, default=-1, help='pid to filter. -1 for all')
@click.option('-m', '--match', help='match expression')
def syslog_live(udid, out, nocolor, pid, match):
    """ view live syslog lines """
    lockdown = LockdownClient(udid=udid)
    for syslog_entry in OsTraceService(lockdown=lockdown).syslog(pid=pid):
        pid = syslog_entry.pid
        timestamp = syslog_entry.timestamp
        level = syslog_entry.level
        filename = syslog_entry.filename
        image_name = os.path.basename(syslog_entry.image_name)
        message = syslog_entry.message
        process_name = os.path.basename(filename)

        if not nocolor:
            timestamp = colored(str(timestamp), 'green')
            process_name = colored(process_name, 'magenta')
            if len(image_name) > 0:
                image_name = colored(image_name, 'magenta')
            pid = colored(syslog_entry['pid'], 'cyan')
            level = colored(syslog_entry['level'], {
                'Notice': 'white',
                'Error': 'red',
                'Fault': 'red',
                'Warning': 'yellow',
            }[level])

            message = colored(syslog_entry['message'], 'white')

        line = '{timestamp} {process_name}{{{image_name}}}[{pid}] <{level}>: {message}'.format(
            timestamp=timestamp, process_name=process_name, image_name=image_name, pid=pid, level=level,
            message=message,
        )

        if match and match not in line:
            continue

        print(line)

        if out:
            out.write(line)


@syslog.command('archive')
@click.option('--udid')
@click.argument('out', type=click.File('wb'))
def syslog_archive(udid, out):
    """
    create PAX archive.
    use `pax -r < filename` for extraction.
    """
    lockdown = LockdownClient(udid=udid)
    result, tar = OsTraceService(lockdown=lockdown).create_archive()
    out.write(tar)


@cli.command()
@click.option('--udid')
@click.argument('out', type=click.File('wb'), required=False)
def pcap(udid, out):
    """ sniff device traffic """
    lockdown = LockdownClient(udid=udid)
    PcapdService(lockdown=lockdown).watch(out=out)


@cli.command()
@click.option('--udid')
@click.argument('out', type=click.File('wb'))
def screenshot(udid, out):
    """ take a screenshot in TIFF format """
    lockdown = LockdownClient(udid=udid)
    out.write(ScreenshotService(lockdown=lockdown).take_screenshot())


@cli.command()
@click.option('--udid')
@click.argument('action', type=click.Choice(['flush', 'shell']))
def crash(udid, action):
    """ crash utils """
    if action == 'flush':
        ack = b'ping\x00'
        lockdown = LockdownClient(udid=udid)
        assert ack == lockdown.start_service('com.apple.crashreportmover').recv_exact(len(ack))
    elif action == 'shell':
        AFCShell(udid=udid, afcname='com.apple.crashreportcopymobile').cmdloop()


@cli.command()
@click.option('--udid')
@click.argument('action', type=click.Choice(['shell']), default='shell')
def afc(udid, action):
    """ FileSystem utils """
    AFCShell(udid=udid, afcname='com.apple.afc').cmdloop()


@cli.command()
@click.option('--udid')
def ps(udid):
    """ show process list """
    lockdown = LockdownClient(udid=udid)
    pprint(OsTraceService(lockdown=lockdown).get_pid_list())


@cli.command()
@click.option('--udid')
@click.argument('action', type=click.Choice(['post', 'observe']))
@click.argument('names', nargs=-1)
def notification(udid, action, names):
    """ API for notify_post() & notify_register_dispatch(). """
    lockdown = LockdownClient(udid=udid)
    service = NotificationProxyService(lockdown=lockdown)
    for name in names:
        if action == 'post':
            service.notify_post(name)
        elif action == 'observe':
            service.notify_register_dispatch(name)

    if action == 'observe':
        for event in service.receive_notification():
            logging.info(event)


@cli.group()
def developer():
    """ developer options """
    pass


@developer.command('proclist')
@click.option('--udid')
@click.option('--nocolor', is_flag=True)
def proclist(udid, nocolor):
    """ show process list """
    lockdown = LockdownClient(udid=udid)
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        processes = dvt.proclist()
        for process in processes:
            if 'startDate' in process:
                process['startDate'] = str(process['startDate'])

        print_object(processes, colored=not(nocolor))


@developer.command('applist')
@click.option('--udid')
@click.option('--nocolor', is_flag=True)
def applist(udid, nocolor):
    """ show application list """
    lockdown = LockdownClient(udid=udid)
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        apps = dvt.applist()
        print_object(apps, colored=not(nocolor))


@developer.command('kill')
@click.option('--udid')
@click.argument('pid', type=click.INT)
def kill(udid, pid):
    """ Kill a process by its pid. """
    lockdown = LockdownClient(udid=udid)
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        dvt.kill(pid)


@developer.command('launch')
@click.option('--udid')
@click.argument('bundle_id', type=click.STRING)
def launch(udid, bundle_id):
    """ Kill a process by its pid. """
    lockdown = LockdownClient(udid=udid)
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        pid = dvt.launch(bundle_id)
        print(f'Procces launched with pid {pid}')


@developer.command('shell')
@click.option('--udid')
def shell(udid):
    """ Launch developer shell. """
    with DvtSecureSocketProxyService(lockdown=LockdownClient(udid=udid)) as dvt:
        dvt.shell()


if __name__ == '__main__':
    cli()
