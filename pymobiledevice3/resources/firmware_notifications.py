import logging
import os
import plistlib

import click
import coloredlogs

NOTIFICATIONS_FILENAME = os.path.join(os.path.dirname(__file__), 'notifications.txt')


def get_notifications():
    with open(NOTIFICATIONS_FILENAME, 'rb') as f:
        return f.read().decode().split('\n')


def save_notifications(notifications: list[str]):
    with open(NOTIFICATIONS_FILENAME, 'wb') as f:
        notifications.sort()
        f.write('\n'.join(notifications).encode())


@click.command()
@click.argument('root_fs', type=click.Path(dir_okay=True, file_okay=False, exists=True))
def main(root_fs):
    """
    Add notifications registered to `com.apple.notifyd.matching` from a given IPSW `root_fs` (extracted filesystem)
    into `notifications.txt`
    """
    launch_daemons = os.path.join(root_fs, 'System', 'Library', 'LaunchDaemons')

    notifications = set(get_notifications())

    for filename in os.listdir(launch_daemons):
        if not filename.endswith('.plist'):
            continue

        filename = os.path.join(launch_daemons, filename)
        try:
            with open(filename, 'rb') as f:
                plist = plistlib.load(f)
        except Exception:
            logging.exception(f'error parsing: {filename}')
            continue

        launch_events = plist.get('LaunchEvents', {})
        notifyd_matching = launch_events.get('com.apple.notifyd.matching', {})

        for v in notifyd_matching.values():
            if not isinstance(v, dict):
                logging.error(f'error parsing: {filename}')
                continue
            notification = v.get('Notification')
            if notification is None:
                continue

            if notification not in notifications:
                logging.info(f'adding notification: {notification}')
                notifications.add(notification)

    save_notifications(list(notifications))


if __name__ == '__main__':
    coloredlogs.install(level=logging.DEBUG)
    main()
