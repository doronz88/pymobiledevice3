import logging

import click
from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.resources.firmware_notifications import get_notifications
from pymobiledevice3.services.notification_proxy import NotificationProxyService


@click.group()
def cli():
    """ notification options """
    pass


@cli.group()
def notification():
    """ notification options """
    pass


@notification.command(cls=Command)
@click.argument('names', nargs=-1)
def post(lockdown, names):
    """ API for notify_post(). """
    service = NotificationProxyService(lockdown=lockdown)
    for name in names:
        service.notify_post(name)


@notification.command(cls=Command)
@click.argument('names', nargs=-1)
def observe(lockdown, names):
    """ API for notify_register_dispatch(). """
    service = NotificationProxyService(lockdown=lockdown)
    for name in names:
        service.notify_register_dispatch(name)

    for event in service.receive_notification():
        logging.info(event)


@notification.command('observe-all', cls=Command)
@click.argument('names', nargs=-1)
def observe_all(lockdown, names):
    """ attempt to observe all builtin firmware notifications. """
    service = NotificationProxyService(lockdown=lockdown)
    for notification in get_notifications():
        service.notify_register_dispatch(notification)

    for event in service.receive_notification():
        logging.info(event)
