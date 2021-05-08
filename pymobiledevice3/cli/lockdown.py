import tempfile
from pprint import pprint

import click

from pymobiledevice3.cli.cli_common import Command
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
def lockdown_forward(lockdown, src_port, dst_port, daemonize):
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
def lockdown_recovery(lockdown):
    """ enter recovery """
    pprint(lockdown.enter_recovery())


@lockdown_group.command('service', cls=Command)
@click.argument('service_name')
def lockdown_service(lockdown, service_name):
    """ send-receive raw service messages """
    lockdown.start_service(service_name).shell()


@lockdown_group.command('info', cls=Command)
def lockdown_info(lockdown):
    """ query all lockdown values """
    pprint(lockdown.all_values)
