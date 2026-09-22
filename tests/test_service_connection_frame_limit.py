import struct
from unittest.mock import AsyncMock, Mock

import pytest

from pymobiledevice3.exceptions import ProtocolError
from pymobiledevice3.service_connection import ServiceConnection


def _connection() -> ServiceConnection:
    connection = object.__new__(ServiceConnection)
    connection.max_frame_size = 16
    return connection


@pytest.mark.asyncio
async def test_recv_prefixed_rejects_oversized_frame():
    connection = _connection()
    connection.recvall = AsyncMock(return_value=struct.pack(">L", 17))
    with pytest.raises(ProtocolError):
        await connection.recv_prefixed()
    # the payload was never requested, so a lying device cannot make the host buffer it
    connection.recvall.assert_awaited_once_with(4)


@pytest.mark.asyncio
async def test_recv_prefixed_accepts_frame_at_limit():
    connection = _connection()
    connection.recvall = AsyncMock(side_effect=[struct.pack(">L", 16), b"x" * 16])
    assert await connection.recv_prefixed() == b"x" * 16


def test_recv_prefixed_sync_rejects_oversized_frame():
    connection = _connection()
    connection.recvall_sync = Mock(return_value=struct.pack(">L", 17))
    with pytest.raises(ProtocolError):
        connection.recv_prefixed_sync()
    connection.recvall_sync.assert_called_once_with(4)
