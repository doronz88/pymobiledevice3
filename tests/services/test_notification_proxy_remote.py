import asyncio
import json
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.services.notification_proxy import NotificationEvent, RemoteNotificationProxyService

PROBE_NOTIFICATION = "com.apple.pymobiledevice3.test.notification"


class FakeConnection:
    def __init__(self, inbound: list[dict[str, Any]]) -> None:
        self.sent: list[dict[str, Any]] = []
        self._inbound = list(inbound)

    async def send_request(self, request: dict[str, Any]) -> None:
        self.sent.append(request)

    async def receive_response(self) -> dict[str, Any]:
        if not self._inbound:
            raise asyncio.CancelledError
        return self._inbound.pop(0)


def _service(
    inbound: Optional[list[dict[str, Any]]] = None,
) -> tuple[RemoteNotificationProxyService, FakeConnection]:
    connection = FakeConnection(inbound if inbound is not None else [])
    service = RemoteNotificationProxyService(cast(RemoteServiceDiscoveryService, object()))
    service._service = cast(RemoteXPCConnection, connection)
    return service, connection


def test_service_names() -> None:
    # The native RemoteXPC services, not the ".shim.remote" lockdown aliases.
    assert RemoteNotificationProxyService.SERVICE_NAME == "com.apple.mobile.notification_proxy.remote"
    assert RemoteNotificationProxyService.INSECURE_SERVICE_NAME == "com.apple.mobile.insecure_notification_proxy.remote"


@pytest.mark.parametrize(
    ("insecure", "expected"),
    [
        (False, "com.apple.mobile.notification_proxy.remote"),
        (True, "com.apple.mobile.insecure_notification_proxy.remote"),
    ],
)
def test_insecure_selects_service(insecure: bool, expected: str) -> None:
    service = RemoteNotificationProxyService(cast(RemoteServiceDiscoveryService, object()), insecure=insecure)
    assert service.service_name == expected


@pytest.mark.asyncio
async def test_notify_post_sends_post_command() -> None:
    service, connection = _service()

    await service.notify_post(PROBE_NOTIFICATION)

    assert connection.sent == [{"Command": "PostNotification", "Name": PROBE_NOTIFICATION}]


@pytest.mark.asyncio
async def test_notify_register_dispatch_sends_observe_command() -> None:
    service, connection = _service()

    await service.notify_register_dispatch(PROBE_NOTIFICATION)

    assert connection.sent == [{"Command": "ObserveNotification", "Name": PROBE_NOTIFICATION}]


@pytest.mark.asyncio
async def test_receive_notification_yields_relayed_messages() -> None:
    relayed = {"Command": "RelayNotification", "Name": PROBE_NOTIFICATION}
    service, _ = _service([relayed])

    async for event in service.receive_notification():
        assert event == relayed
        break


@pytest.mark.asyncio
async def test_receive_notification_yields_typed_events() -> None:
    service, _ = _service([{"Command": "RelayNotification", "Name": PROBE_NOTIFICATION, "State": 7}])

    async for event in service.receive_notification():
        assert isinstance(event, NotificationEvent)
        assert (event.command, event.name, event.state) == ("RelayNotification", PROBE_NOTIFICATION, 7)
        break


def test_notification_event_is_still_the_message() -> None:
    message = {"Command": "RelayNotification", "Name": PROBE_NOTIFICATION}

    event = NotificationEvent.from_message(message)

    assert event == message and event["Name"] == PROBE_NOTIFICATION and event.get("State") is None
    assert event.state is None
    assert json.loads(json.dumps(event)) == message
    assert repr(event) == repr(message)


def test_notification_event_without_a_name() -> None:
    event = NotificationEvent.from_message({"Command": "ProxyDeath"})

    assert event.command == "ProxyDeath" and event.name is None


@pytest.mark.asyncio
async def test_observe_post_relay_round_trip_on_device(service_provider) -> None:
    """Observe a notification, post it, and confirm the device relays it back."""
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("the native notification proxy requires an RSD tunnel")

    async with RemoteNotificationProxyService(service_provider) as observer:
        await observer.notify_register_dispatch(PROBE_NOTIFICATION)
        async with RemoteNotificationProxyService(service_provider) as poster:
            await asyncio.sleep(1)
            await poster.notify_post(PROBE_NOTIFICATION)

            async def first_relay() -> NotificationEvent:
                async for event in observer.receive_notification():
                    return event
                raise AssertionError("stream ended without a relay")

            event = await asyncio.wait_for(first_relay(), 15)

    assert (event.command, event.name) == ("RelayNotification", PROBE_NOTIFICATION)
    # iOS 27.2 added the notification's state to the relay.
    assert event.state is None or isinstance(event.state, int)
