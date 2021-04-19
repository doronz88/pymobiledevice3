#!/usr/bin/env python3
import json
import logging
import os
import shlex
import tempfile
from pprint import pprint

import click
import coloredlogs
from daemonize import Daemonize
from pygments import highlight, lexers, formatters
from termcolor import colored

from pymobiledevice3.services.afc import AfcShell, AfcService
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.mobile_config import MobileConfigService
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService
from pymobiledevice3.services.notification_proxy import NotificationProxyService
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.pcapd import PcapdService
from pymobiledevice3.services.screenshot import ScreenshotService
from pymobiledevice3.services.syslog import SyslogService
from pymobiledevice3.tcp_forwarder import TcpForwarder

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


class Command(click.Command):
    @staticmethod
    def udid(ctx, param, value):
        return LockdownClient(udid=value)

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('lockdown', '--udid'), callback=self.udid),
        ]


@click.group()
def cli():
    pass


@cli.group()
def mounter():
    """ mounter options """
    pass


@mounter.command('list', cls=Command)
def mounter_list(lockdown):
    """ lookup mounter image type """
    pprint(MobileImageMounterService(lockdown=lockdown).list_images())


@mounter.command('lookup', cls=Command)
@click.argument('image_type')
def mounter_lookup(lockdown, image_type):
    """ lookup mounter image type """
    pprint(MobileImageMounterService(lockdown=lockdown).lookup_image(image_type))


@mounter.command('umount', cls=Command)
def mounter_umount(lockdown):
    """ unmount developer image. """
    image_type = 'Developer'
    mount_path = '/Developer'
    image_mounter = MobileImageMounterService(lockdown=lockdown)
    image_mounter.umount(image_type, mount_path, b'')


@mounter.command('mount', cls=Command)
@click.option('-i', '--image', type=click.Path(exists=True))
@click.option('-s', '--signature', type=click.Path(exists=True))
@click.option('-x', '--xcode', type=click.Path(exists=True, dir_okay=True, file_okay=False),
              default='/Applications/Xcode.app',
              help='Xcode application path used to figure out automatically the DeveloperDiskImage path')
@click.option('-v', '--version', help='use a different DeveloperDiskImage version from the one retrieved by lockdown'
                                      'connection')
def mounter_mount(lockdown, image, signature, xcode, version):
    """ mount developer image. """
    image_type = 'Developer'

    if image and signature:
        logging.info('using given image and signature for mount command')
    else:
        logging.info('trying to figure out the best suited DeveloperDiskImage')
        if version is None:
            version = lockdown.ios_version
        image = f'{xcode}/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/{version}/DeveloperDiskImage.dmg'
        signature = f'{image}.signature'

    with open(image, 'rb') as image:
        image = image.read()

    with open(signature, 'rb') as signature:
        signature = signature.read()

    image_mounter = MobileImageMounterService(lockdown=lockdown)
    image_mounter.upload_image(image_type, image, signature)
    image_mounter.mount(image_type, signature)


@cli.group()
def apps():
    """ application options """
    pass


@apps.command('list', cls=Command)
@click.option('-u', '--user', is_flag=True, help='include user apps')
@click.option('-s', '--system', is_flag=True, help='include system apps')
def apps_list(lockdown, user, system):
    """ list installed apps """
    app_types = []
    if user:
        app_types.append('User')
    if system:
        app_types.append('System')
    pprint(InstallationProxyService(lockdown=lockdown).get_apps(app_types))


@apps.command('uninstall', cls=Command)
@click.argument('bundle_id')
def apps_uninstall(lockdown, bundle_id):
    """ uninstall app by given bundle_id """
    pprint(InstallationProxyService(lockdown=lockdown).uninstall(bundle_id))


@apps.command('install', cls=Command)
@click.argument('ipa_path', type=click.Path(exists=True))
def apps_install(lockdown, ipa_path):
    """ install given .ipa """
    pprint(InstallationProxyService(lockdown=lockdown).install_from_local(ipa_path))


@apps.command('afc', cls=Command)
@click.argument('bundle_id')
def apps_afc(lockdown, bundle_id):
    """ open an AFC shell for given bundle_id, assuming its profile is installed """
    HouseArrestService(lockdown=lockdown).shell(bundle_id)


@cli.group()
def profile():
    """ profile options """
    pass


@profile.command('list', cls=Command)
def profile_list(lockdown):
    """ list installed profiles """
    pprint(MobileConfigService(lockdown=lockdown).get_profile_list())


@profile.command('install', cls=Command)
@click.argument('profile', type=click.File('rb'))
def profile_install(lockdown, profile):
    """ install given profile file """
    pprint(MobileConfigService(lockdown=lockdown).install_profile(profile.read()))


@profile.command('remove', cls=Command)
@click.argument('name')
def profile_remove(lockdown, name):
    """ remove profile by name """
    pprint(MobileConfigService(lockdown=lockdown).remove_profile(name))


@cli.group()
def lockdown():
    """ lockdown options """
    pass


@lockdown.command('forward', cls=Command)
@click.argument('src_port', type=click.IntRange(1, 0xffff))
@click.argument('dst_port', type=click.IntRange(1, 0xffff))
@click.option('-d', '--daemonize', is_flag=True)
def lockdown_forward(lockdown, src_port, dst_port, daemonize):
    """ forward tcp port """
    forwarder = TcpForwarder(lockdown, src_port, dst_port)

    if daemonize:
        with tempfile.NamedTemporaryFile('wt') as pid_file:
            daemon = Daemonize(app=f'forwarder {src_port}->{dst_port}', pid=pid_file.name, action=forwarder.start)
            daemon.start()
    else:
        forwarder.start()


@lockdown.command('recovery', cls=Command)
def lockdown_recovery(lockdown):
    """ enter recovery """
    pprint(lockdown.enter_recovery())


@lockdown.command('service', cls=Command)
@click.argument('service_name')
def lockdown_service(lockdown, service_name):
    """ send-receive raw service messages """
    lockdown.start_service(service_name).shell()


@lockdown.command('info', cls=Command)
def lockdown_info(lockdown):
    """ query all lockdown values """
    pprint(lockdown.all_values)


@cli.group()
def diagnostics():
    """ diagnostics options """
    pass


@diagnostics.command('restart', cls=Command)
def diagnostics_restart(lockdown):
    """ restart device """
    DiagnosticsService(lockdown=lockdown).restart()


@diagnostics.command('shutdown', cls=Command)
def diagnostics_shutdown(lockdown):
    """ shutdown device """
    DiagnosticsService(lockdown=lockdown).shutdown()


@diagnostics.command('sleep', cls=Command)
def diagnostics_sleep(lockdown):
    """ put device into sleep """
    DiagnosticsService(lockdown=lockdown).sleep()


@diagnostics.command('info', cls=Command)
def diagnostics_info(lockdown):
    """ get diagnostics info """
    pprint(DiagnosticsService(lockdown=lockdown).info())


@diagnostics.command('ioregistry', cls=Command)
@click.option('--plane')
@click.option('--name')
@click.option('--ioclass')
def diagnostics_ioregistry(lockdown, plane, name, ioclass):
    """ get ioregistry info """
    pprint(DiagnosticsService(lockdown=lockdown).ioregistry(plane=plane, name=name, ioclass=ioclass))


@diagnostics.command('mg', cls=Command)
@click.argument('keys', nargs=-1, default=None)
def diagnostics_mg(lockdown, keys):
    """ get MobileGestalt key values from given list. If empty, return all known. """
    pprint(DiagnosticsService(lockdown=lockdown).mobilegestalt(keys=keys))


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
def syslog_live(lockdown, out, nocolor, pid, match):
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

        if not nocolor:
            timestamp = colored(str(timestamp), 'green')
            process_name = colored(process_name, 'magenta')
            if len(image_name) > 0:
                image_name = colored(image_name, 'magenta')
            pid = colored(syslog_entry['pid'], 'cyan')

            if level in syslog_entry:
                level = colored(level, log_level_colors[level])

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


@syslog.command('archive', cls=Command)
@click.argument('out', type=click.File('wb'))
def syslog_archive(lockdown, out):
    """
    create PAX archive.
    use `pax -r < filename` for extraction.
    """
    result, tar = OsTraceService(lockdown=lockdown).create_archive()
    out.write(tar)


@cli.command(cls=Command)
@click.argument('out', type=click.File('wb'), required=False)
def pcap(lockdown, out):
    """ sniff device traffic """
    PcapdService(lockdown=lockdown).watch(out=out)


@cli.command(cls=Command)
@click.argument('out', type=click.File('wb'))
def screenshot(lockdown, out):
    """ take a screenshot in PNG format """
    out.write(ScreenshotService(lockdown=lockdown).take_screenshot())


@cli.command(cls=Command)
@click.argument('action', type=click.Choice(['flush', 'shell']))
def crash(lockdown, action):
    """ crash utils """
    if action == 'flush':
        ack = b'ping\x00'
        assert ack == lockdown.start_service('com.apple.crashreportmover').recv_exact(len(ack))
    elif action == 'shell':
        AfcShell(lockdown=lockdown, afcname='com.apple.crashreportcopymobile').cmdloop()


@cli.group()
def afc():
    """ FileSystem utils """
    pass


@afc.command('shell', cls=Command)
def afc_shell(lockdown):
    """ open an AFC shell rooted at /var/mobile/Media """
    AfcShell(lockdown=lockdown, afcname='com.apple.afc').cmdloop()


@afc.command('pull', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
@click.argument('local_file', type=click.File('wb'))
def afc_pull(lockdown, remote_file, local_file):
    """ open an AFC shell rooted at /var/mobile/Media """
    local_file.write(AfcService(lockdown=lockdown).get_file_contents(remote_file))


@afc.command('push', cls=Command)
@click.argument('local_file', type=click.File('rb'))
@click.argument('remote_file', type=click.Path(exists=False))
def afc_push(lockdown, local_file, remote_file):
    """ open an AFC shell rooted at /var/mobile/Media """
    AfcService(lockdown=lockdown).set_file_contents(remote_file, local_file.read())


@afc.command('ls', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
def afc_ls(lockdown, remote_file):
    """ open an AFC shell rooted at /var/mobile/Media """
    pprint(AfcService(lockdown=lockdown).listdir(remote_file))


@afc.command('rm', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
def afc_rm(lockdown, remote_file):
    """ open an AFC shell rooted at /var/mobile/Media """
    AfcService(lockdown=lockdown).rm(remote_file)


@cli.command(cls=Command)
def ps(lockdown):
    """ show process list """
    pprint(OsTraceService(lockdown=lockdown).get_pid_list())


@cli.command(cls=Command)
@click.argument('action', type=click.Choice(['post', 'observe']))
@click.argument('names', nargs=-1)
def notification(lockdown, action, names):
    """ API for notify_post() & notify_register_dispatch(). """
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


@developer.command('proclist', cls=Command)
@click.option('--nocolor', is_flag=True)
def proclist(lockdown, nocolor):
    """ show process list """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        processes = dvt.proclist()
        for process in processes:
            if 'startDate' in process:
                process['startDate'] = str(process['startDate'])

        print_object(processes, colored=not nocolor)


@developer.command('applist', cls=Command)
@click.option('--nocolor', is_flag=True)
def applist(lockdown, nocolor):
    """ show application list """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        apps = dvt.applist()
        print_object(apps, colored=not nocolor)


@developer.command('kill', cls=Command)
@click.argument('pid', type=click.INT)
def kill(lockdown, pid):
    """ Kill a process by its pid. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        dvt.kill(pid)


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
        pid = dvt.launch(parsed_arguments[0], parsed_arguments[1:], kill_existing, suspended)
        print(f'Process launched with pid {pid}')


@developer.command('shell', cls=Command)
def shell(lockdown):
    """ Launch developer shell. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        dvt.shell()


@developer.command('ls', cls=Command)
@click.argument('path', type=click.Path(exists=False))
def ls(lockdown, path):
    """ List directory. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        pprint(dvt.ls(path))


@developer.command('device-information', cls=Command)
@click.option('--nocolor', is_flag=True)
def device_information(lockdown, nocolor):
    """ Print system information. """
    with DvtSecureSocketProxyService(lockdown=lockdown) as dvt:
        print_object({
            'system': dvt.system_information(),
            'hardware': dvt.hardware_information(),
            'network': dvt.network_information(),
        }, colored=not nocolor)


if __name__ == '__main__':
    cli()
