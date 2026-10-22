import asyncio
import logging
from typing import Any, cast

import pytest

from pymobiledevice3.dtx.channel import DTXChannel
from pymobiledevice3.dtx.connection import DTXConnection
from pymobiledevice3.dtx.exceptions import DTXProtocolError
from pymobiledevice3.dtx.message import DTXMessage
from pymobiledevice3.exceptions import ConnectionTerminatedError

pytestmark = pytest.mark.asyncio


class FakeChannel:
    def __init__(self) -> None:
        self.shutdown_reason = None

    def _shutdown(self, reason: str) -> None:
        self.shutdown_reason = reason


def _connection(channels: dict[int, FakeChannel]) -> DTXConnection:
    connection = object.__new__(DTXConnection)
    connection.logger = logging.getLogger(__name__)
    connection._channel_lock = asyncio.Lock()
    connection._channels = cast(Any, dict(channels))
    connection._services = cast(Any, dict.fromkeys(channels))
    return connection


@pytest.mark.parametrize(("local_code", "peer_code"), [(2, -2), (-3, 3)])
async def test_peer_cancellation_closes_the_channel_it_names_from_its_side(local_code: int, peer_code: int) -> None:
    channel = FakeChannel()
    connection = _connection({local_code: channel})

    await connection._on_channel_cancelled(peer_code)

    assert channel.shutdown_reason == "channel cancelled by remote"
    assert local_code not in connection._channels
    assert local_code not in connection._services


async def test_peer_cancellation_of_an_unknown_channel_is_a_protocol_error() -> None:
    channel = FakeChannel()
    connection = _connection({2: channel})

    with pytest.raises(DTXProtocolError):
        await connection._on_channel_cancelled(2)
    assert channel.shutdown_reason is None


async def test_peer_cancellation_fails_the_requests_awaiting_a_reply_on_the_channel() -> None:
    """A service the device cannot create cancels its channel instead of replying (iOS 13
    LocationSimulation); the call waiting for that reply must fail, not hang."""
    connection = _connection({})
    connection._pending_replies = {}
    sent: list[DTXMessage] = []

    async def send_message(message: DTXMessage) -> None:
        message.identifier = len(sent) + 1
        connection._pending_replies[message.identifier] = asyncio.get_running_loop().create_future()
        sent.append(message)

    connection._send_message = send_message
    channel = DTXChannel(2, "com.example.service", connection)
    connection._channels[2] = channel
    call = asyncio.create_task(channel.invoke("doSomething"))
    while not sent:
        await asyncio.sleep(0)

    await connection._on_channel_cancelled(-2)

    with pytest.raises(ConnectionTerminatedError, match="closed before replying"):
        await asyncio.wait_for(call, timeout=5)
    assert connection._pending_replies == {}
