import tempfile

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.heartbeat import HeartbeatService
from pymobiledevice3.tcp_forwarder import TcpForwarder


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group('lockdown')
def lockdown_group():
    """ lockdown options """
    pass


@lockdown_group.command('forward', cls=Command)
@click.argument('src_port', type=click.IntRange(1, 0xffff))
@click.argument('dst_port', type=click.IntRange(1, 0xffff))
@click.option('-d', '--daemonize', is_flag=True)
def lockdown_forward(lockdown: LockdownClient, src_port, dst_port, daemonize):
    """ forward tcp port """
    forwarder = TcpForwarder(lockdown, src_port, dst_port)

    if daemonize:
        try:
            from daemonize import Daemonize
        except ImportError:
            raise NotImplementedError('daemonizing is only supported on unix platforms')

        with tempfile.NamedTemporaryFile('wt') as pid_file:
            daemon = Daemonize(app=f'forwarder {src_port}->{dst_port}', pid=pid_file.name, action=forwarder.start)
            daemon.start()
    else:
        forwarder.start()


@lockdown_group.command('recovery', cls=Command)
def lockdown_recovery(lockdown: LockdownClient):
    """ enter recovery """
    print_json(lockdown.enter_recovery())


@lockdown_group.command('service', cls=Command)
@click.argument('service_name')
def lockdown_service(lockdown: LockdownClient, service_name):
    """ send-receive raw service messages """
    lockdown.start_service(service_name).shell()


@lockdown_group.command('info', cls=Command)
@click.option('--color/--no-color', default=True)
def lockdown_info(lockdown: LockdownClient, color):
    """ query all lockdown values """
    print_json(lockdown.all_values, colored=color)


@lockdown_group.command('unpair', cls=Command)
def lockdown_unpair(lockdown: LockdownClient):
    """ unpair from connected device """
    lockdown.unpair()


@lockdown_group.command('pair', cls=Command)
def lockdown_pair(lockdown: LockdownClient):
    """ pair device """
    lockdown.pair()


@lockdown_group.command('date', cls=Command)
def lockdown_date(lockdown: LockdownClient):
    """ get device date """
    print(lockdown.date)


@lockdown_group.command('heartbeat', cls=Command)
def lockdown_heartbeat(lockdown: LockdownClient):
    """ start heartbeat service """
    HeartbeatService(lockdown).start()


@lockdown_group.command('language', cls=Command)
def lockdown_language(lockdown: LockdownClient):
    """ get current language settings """
    print(f'{lockdown.language} {lockdown.locale}')


@lockdown_group.command('device-name', cls=Command)
@click.argument('new_name', required=False)
def lockdown_device_name(lockdown: LockdownClient, new_name):
    """ get/set current device name """
    if new_name:
        lockdown.set_value(new_name, key='DeviceName')
    else:
        print(f'{lockdown.get_value(key="DeviceName")}')
