import socket
from collections.abc import AsyncGenerator
from typing import Any, Optional, Union

from pymobiledevice3.exceptions import NotificationTimeoutError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.lockdown_service import LockdownService


class NotificationProxyService(LockdownService):
    """
    Post and observe Darwin notifications on the device via the notification proxy lockdown service.

    Allows sending notifications to the device, registering interest in notifications so the device
    relays them back, and iterating over the relayed notifications. A secure or insecure variant of
    the service is selected by the ``insecure`` flag, and the RSD/tunnel variant is chosen
    automatically for `RemoteServiceDiscoveryService` providers. This is a lockdown service and is
    used as an async context manager.
    """

    SERVICE_NAME = "com.apple.mobile.notification_proxy"
    RSD_SERVICE_NAME = "com.apple.mobile.notification_proxy.shim.remote"

    INSECURE_SERVICE_NAME = "com.apple.mobile.insecure_notification_proxy"
    RSD_INSECURE_SERVICE_NAME = "com.apple.mobile.insecure_notification_proxy.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider, insecure=False, timeout: Optional[Union[float, int]] = None):
        """
        :param lockdown: service provider used to start the service and reach the device.
        :param insecure: when True, use the insecure notification proxy service instead of the secure one.
        :param timeout: optional socket receive timeout in seconds applied to the service connection.
        """
        if isinstance(lockdown, RemoteServiceDiscoveryService):
            secure_service_name = self.RSD_SERVICE_NAME
            insecure_service_name = self.RSD_INSECURE_SERVICE_NAME
        else:
            secure_service_name = self.SERVICE_NAME
            insecure_service_name = self.INSECURE_SERVICE_NAME

        if insecure:
            super().__init__(lockdown, insecure_service_name)
        else:
            super().__init__(lockdown, secure_service_name)

        if timeout is not None:
            service = self.service
            assert isinstance(service, ServiceConnection)
            assert service.socket is not None
            service.socket.settimeout(timeout)

    async def notify_post(self, name: str) -> None:
        """
        Post a notification on the device.

        Sends a ``PostNotification`` command, causing the device to broadcast the named notification.

        :param name: notification name to post (e.g. a Darwin notification name).
        """
        await self.service.send_plist({"Command": "PostNotification", "Name": name})

    async def notify_register_dispatch(self, name: str) -> None:
        """
        Register interest in a notification so the device relays it back.

        Sends an ``ObserveNotification`` command; once registered, the device sends a message
        whenever the named notification fires, which can be read via `receive_notification`.

        :param name: notification name to observe.
        """
        self.logger.info(f"Observing {name}")
        await self.service.send_plist({"Command": "ObserveNotification", "Name": name})

    async def receive_notification(self) -> AsyncGenerator[dict[str, Any], None]:
        """
        Yield notifications relayed from the device for previously observed names.

        Continuously reads from the service and yields each received message until the connection
        is closed.

        :returns: an async generator of the received notification plists.
        :raises NotificationTimeoutError: if no notification arrives within the configured socket timeout.
        """
        while True:
            try:
                yield await self.service.recv_plist()
            except socket.timeout as e:
                raise NotificationTimeoutError from e
