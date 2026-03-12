import asyncio
import struct

import pytest

from pymobiledevice3.service_connection import ServiceConnection


class _DummySocket:
    def setblocking(self, _: bool) -> None:
        pass


class _ContendedReader:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._busy = False

    async def readexactly(self, size: int) -> bytes:
        if self._busy:
            raise RuntimeError("readexactly() called while another coroutine is already waiting for incoming data")

        self._busy = True
        try:
            await asyncio.sleep(0.01)
            chunk, self._payload = self._payload[:size], self._payload[size:]
            if len(chunk) < size:
                raise asyncio.IncompleteReadError(chunk, size)
            return chunk
        finally:
            self._busy = False

    async def read(self, size: int) -> bytes:
        chunk, self._payload = self._payload[:size], self._payload[size:]
        return chunk


class _DummyWriter:
    pass


@pytest.mark.asyncio
async def test_recv_prefixed_is_serialized() -> None:
    first = b"abc"
    second = b"defgh"
    payload = struct.pack(">L", len(first)) + first + struct.pack(">L", len(second)) + second
    conn = ServiceConnection(_DummySocket())  # type: ignore[arg-type]
    conn.reader = _ContendedReader(payload)  # type: ignore[assignment]
    conn.writer = _DummyWriter()  # type: ignore[assignment]

    messages = await asyncio.gather(conn.recv_prefixed(), conn.recv_prefixed())

    assert messages == [first, second]
