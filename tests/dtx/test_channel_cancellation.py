import asyncio
import logging
from typing import Any, cast

import pytest

from pymobiledevice3.dtx.connection import DTXConnection
from pymobiledevice3.dtx.exceptions import DTXProtocolError

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
