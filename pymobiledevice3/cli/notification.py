import logging

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.notification_proxy import NotificationProxyService


@click.group()
def cli():
    """ apps cli """
    pass


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
