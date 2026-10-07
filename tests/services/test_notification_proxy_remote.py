import asyncio
import json
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type
from pymobiledevice3.services.notification_proxy import (
    NotificationEvent,
    NotificationStateError,
    RemoteNotificationProxyService,
)

PROBE_NOTIFICATION = "com.apple.pymobiledevice3.test.notification"


class FakeConnection:
    def __init__(self, inbound: list[dict[str, Any]]) -> None:
        self.sent: list[dict[str, Any]] = []
        self._inbound = list(inbound)

    async def send_request(self, request: dict[str, Any], wanting_reply: bool = False) -> None:
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


@pytest.mark.asyncio
@pytest.mark.parametrize(("state", "wire_type"), [(5, XpcInt64Type), (-2, XpcInt64Type), (2**64 - 1, XpcUInt64Type)])
async def test_notify_set_state_sends_a_64_bit_integer(state: int, wire_type: type) -> None:
    service, connection = _service()

    await service.notify_set_state(PROBE_NOTIFICATION, state)

    (request,) = connection.sent
    assert request == {"Command": "SetNotificationState", "Name": PROBE_NOTIFICATION, "State": state}
    assert type(request["State"]) is wire_type


@pytest.mark.asyncio
async def test_notify_get_state_returns_the_state_of_the_requested_name() -> None:
    service, connection = _service([
        {"Command": "RelayNotification", "Name": "other", "State": 1},
        {"Command": "RelayNotificationState", "Name": PROBE_NOTIFICATION, "State": 42, "Status": 0},
    ])

    assert await service.notify_get_state(PROBE_NOTIFICATION) == 42
    assert connection.sent == [{"Command": "GetNotificationState", "Name": PROBE_NOTIFICATION}]


@pytest.mark.asyncio
async def test_notify_get_state_raises_on_a_failure_status() -> None:
    service, _ = _service([{"Command": "RelayNotificationState", "Name": PROBE_NOTIFICATION, "State": 0, "Status": 7}])

    with pytest.raises(NotificationStateError) as error:
        await service.notify_get_state(PROBE_NOTIFICATION)

    assert error.value.status == 7


@pytest.mark.asyncio
async def test_state_is_held_while_the_setter_is_connected_on_device(service_provider) -> None:
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("the native notification proxy requires an RSD tunnel")
    if tuple(int(part) for part in service_provider.product_version.split(".")[:2]) < (27, 2):
        pytest.skip("notification state requires iOS 27.2")
    name = f"{PROBE_NOTIFICATION}.state"

    async with RemoteNotificationProxyService(service_provider) as reader:
        async with RemoteNotificationProxyService(service_provider) as setter:
            await setter.notify_set_state(name, 1234)
            await asyncio.sleep(0.5)
            assert await reader.notify_get_state(name) == 1234
        await asyncio.sleep(1)
        assert await reader.notify_get_state(name) == 0


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
