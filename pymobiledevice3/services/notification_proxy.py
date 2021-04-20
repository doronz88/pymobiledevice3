import logging

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient


class NotificationProxyService(object):
    SERVICE_NAME = 'com.apple.mobile.notification_proxy'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)

    def notify_post(self, name):
        """ Send notification to the device's notification_proxy. """
        self.service.send_plist({'Command': 'PostNotification',
                                 'Name': name})

        self.service.send_plist({'Command': 'Shutdown'})
        res = self.service.recv_plist()
        if res.get('Command', None) != 'ProxyDeath':
            raise PyMobileDevice3Exception(f'invalid response: {res}')

    def notify_register_dispatch(self, name):
        """ Tells the device to send a notification on the specified event. """
        self.logger.info('Observing %s', name)
        self.service.send_plist({'Command': 'ObserveNotification',
                                 'Name': name})

    def receive_notification(self):
        while True:
            yield self.service.recv_plist()
