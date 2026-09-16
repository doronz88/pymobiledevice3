import asyncio
from typing import cast

import pytest
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, CloseConnection, Request

from pymobiledevice3.tunneld.ws_bridge import ConnectWebsocket


class _Writer:
    def __init__(self) -> None:
        self.writes: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_a_close_that_arrives_with_the_handshake_accept_keeps_its_code():
    # A tunneld refusing /connect answers the handshake and closes with its own code in one go;
    # on a fast link both frames land in the same read, and `connect()` returns on the accept.
    client = WSConnection(ConnectionType.CLIENT)
    server = WSConnection(ConnectionType.SERVER)
    server.receive_data(client.send(Request(host="tunneld", target="/connect?udid=x")))
    assert isinstance(next(server.events()), Request)
    response = server.send(AcceptConnection()) + server.send(CloseConnection(code=4502, reason="refused"))
    client.receive_data(response)
    for event in client.events():  # what connect() does: stop at the accept
        if isinstance(event, AcceptConnection):
            break
    reader = asyncio.StreamReader()
    reader.feed_eof()  # nothing more will ever arrive from the peer
    writer = _Writer()

    bridge = ConnectWebsocket(reader, cast(asyncio.StreamWriter, writer), client, "tunneld")

    assert await bridge.recv_bytes() is None
    assert (bridge.close_code, bridge.close_reason) == (4502, "refused")
    assert writer.writes, "the close was acknowledged"
