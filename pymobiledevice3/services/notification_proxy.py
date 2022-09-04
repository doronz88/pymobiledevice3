import socket

from typing import Union, Generator, Mapping

from pymobiledevice3.exceptions import NotificationTimeoutError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class NotificationProxyService(BaseService):
    SERVICE_NAME = 'com.apple.mobile.notification_proxy'
    INSECURE_SERVICE_NAME = 'com.apple.mobile.insecure_notification_proxy'

    def __init__(self, lockdown: LockdownClient, insecure=False, timeout: Union[float, int] = None):
        if insecure:
            super().__init__(lockdown, self.INSECURE_SERVICE_NAME)
        else:
            super().__init__(lockdown, self.SERVICE_NAME)

        if timeout is not None:
            self.service.socket.settimeout(timeout)

    def notify_post(self, name: str) -> None:
        """ Send notification to the device's notification_proxy. """
        self.service.send_plist({'Command': 'PostNotification',
                                 'Name': name})

    def notify_register_dispatch(self, name: str) -> None:
        """ Tells the device to send a notification on the specified event. """
        self.logger.info(f'Observing {name}')
        self.service.send_plist({'Command': 'ObserveNotification',
                                 'Name': name})

    def receive_notification(self) -> Generator[Mapping, None, None]:
        while True:
            try:
                yield self.service.recv_plist()
            except socket.timeout as e:
                raise NotificationTimeoutError from e
