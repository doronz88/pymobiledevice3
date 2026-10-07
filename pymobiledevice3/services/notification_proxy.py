import dataclasses
import socket
from collections.abc import AsyncGenerator
from typing import Any, Optional, Union

from pymobiledevice3.exceptions import NotificationTimeoutError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.lockdown_service import LockdownService


@dataclasses.dataclass(eq=False, repr=False)
class NotificationEvent(dict[str, Any]):
    """
    A message relayed by the notification proxy.

    It is still the message the device sent, so ``event["Name"]``, ``event.get("State")``,
    comparison with a plain dict and JSON serialization keep working; the fields are typed
    accessors for the same values.
    """

    #: ``RelayNotification`` for an observed notification, ``ProxyDeath`` when the proxy shuts down.
    command: str
    #: Name of the notification, when the message carries one.
    name: Optional[str] = None
    #: The notification's 64-bit ``notify_get_state()`` value. Sent by the secure service since
    #: iOS 27.2; ``None`` otherwise.
    state: Optional[int] = None

    @classmethod
    def from_message(cls, message: dict[str, Any]) -> "NotificationEvent":
        event = cls(command=message.get("Command", ""), name=message.get("Name"), state=message.get("State"))
        event.update(message)
        return event


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

    def __init__(
        self, lockdown: LockdownServiceProvider, insecure: bool = False, timeout: Optional[Union[float, int]] = None
    ):
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
        self.logger.debug(f"Observing {name}")
        await self.service.send_plist({"Command": "ObserveNotification", "Name": name})

    async def receive_notification(self) -> AsyncGenerator[NotificationEvent, None]:
        """
        Yield notifications relayed from the device for previously observed names.

        Continuously reads from the service and yields each received message until the connection
        is closed.

        :returns: an async generator of the received notifications.
        :raises NotificationTimeoutError: if no notification arrives within the configured socket timeout.
        """
        while True:
            try:
                yield NotificationEvent.from_message(await self.service.recv_plist())
            except socket.timeout as e:
                raise NotificationTimeoutError from e


class RemoteNotificationProxyService(RemoteService):
    """
    Post and observe Darwin notifications over the native RemoteXPC notification proxy.

    This is the RSD-native counterpart of `NotificationProxyService`: instead of tunnelling the
    classic lockdown service through its ``.shim.remote`` alias, it talks to the notification proxy
    daemon directly over RemoteXPC. The message vocabulary is identical (``PostNotification`` /
    ``ObserveNotification`` / ``RelayNotification``), only the transport differs.

    Requires an iOS 17+ RSD tunnel. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.mobile.notification_proxy.remote"
    INSECURE_SERVICE_NAME = "com.apple.mobile.insecure_notification_proxy.remote"

    def __init__(self, rsd: RemoteServiceDiscoveryService, insecure: bool = False):
        """
        :param rsd: RSD provider used to open the RemoteXPC service.
        :param insecure: when True, use the insecure relay meant for untrusted clients.
        """
        super().__init__(rsd, self.INSECURE_SERVICE_NAME if insecure else self.SERVICE_NAME)

    async def notify_post(self, name: str) -> None:
        """
        Post a notification on the device.

        :param name: notification name to post (e.g. a Darwin notification name).
        """
        await self.service.send_request({"Command": "PostNotification", "Name": name})

    async def notify_register_dispatch(self, name: str) -> None:
        """
        Register interest in a notification so the device relays it back.

        Once registered, the device sends a ``RelayNotification`` message whenever the named
        notification fires, which can be read via `receive_notification`.

        :param name: notification name to observe.
        """
        self.logger.debug(f"Observing {name}")
        await self.service.send_request({"Command": "ObserveNotification", "Name": name})

    async def receive_notification(self) -> AsyncGenerator[NotificationEvent, None]:
        """
        Yield notifications relayed from the device for previously observed names.

        Each yielded message is of the form
        ``{"Command": "RelayNotification", "Name": <notification name>}``. Since iOS 27.2 the secure
        service also includes ``"State"``, the notification's 64-bit ``notify_get_state()`` value.

        :returns: an async generator of the relayed notifications.
        """
        while True:
            yield NotificationEvent.from_message(await self.service.receive_response())
