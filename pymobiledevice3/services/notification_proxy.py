from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class NotificationProxyService(BaseService):
    SERVICE_NAME = 'com.apple.mobile.notification_proxy'
    INSECURE_SERVICE_NAME = 'com.apple.mobile.insecure_notification_proxy'

    def __init__(self, lockdown: LockdownClient, insecure=False):
        if insecure:
            super().__init__(lockdown, self.INSECURE_SERVICE_NAME)
        else:
            super().__init__(lockdown, self.SERVICE_NAME)

    def notify_post(self, name: str):
        """ Send notification to the device's notification_proxy. """
        self.service.send_plist({'Command': 'PostNotification',
                                 'Name': name})

    def notify_register_dispatch(self, name: str):
        """ Tells the device to send a notification on the specified event. """
        self.logger.info('Observing %s', name)
        self.service.send_plist({'Command': 'ObserveNotification',
                                 'Name': name})

    def receive_notification(self):
        while True:
            yield self.service.recv_plist()
