"""Client side of tunneld's ``WS /connect`` endpoint.

Two consumers speak it: :class:`pymobiledevice3.tunneld.api.TunneldConnectDialer`, which bridges a
local process's device-bound connections through a remote tunneld, and tunneld itself, which
forwards a ``/connect`` it cannot serve to the upstream that owns the device. Both need the same
handshake and the same framing rules, so they share this module rather than hand-rolling it.
"""

import asyncio
import logging
import urllib.parse
from collections import deque
from contextlib import suppress
from typing import Optional

from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, BytesMessage, CloseConnection, Ping, RejectConnection, Request
from wsproto.utilities import RemoteProtocolError

logger = logging.getLogger(__name__)

#: Read chunk size on both legs of a bridge
CHUNK_SIZE = 65536


class ConnectWebsocket:
    """An established ``/connect`` websocket, presented as a binary message stream.

    The tunnel traffic carried here is a byte stream re-framed into websocket messages: message
    boundaries are meaningless, so consumers must concatenate payloads exactly as they would TCP
    segments.
    """

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ws: WSConnection, description: str
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._ws = ws
        self._pending: deque[bytes] = deque()
        self._closed = False
        self.description = description
        #: close code/reason the peer sent, once it closed
        self.close_code: Optional[int] = None
        self.close_reason: Optional[str] = None

    async def send_bytes(self, data: bytes) -> None:
        self._writer.write(self._ws.send(BytesMessage(data=data)))
        await self._writer.drain()

    async def recv_bytes(self) -> Optional[bytes]:
        """The next binary payload, or ``None`` once the peer closed (see `close_code`)."""
        while True:
            if self._pending:
                return self._pending.popleft()
            if self._closed:
                return None
            data = await self._reader.read(CHUNK_SIZE)
            if not data:
                self._closed = True
                continue
            try:
                self._ws.receive_data(data)
            except RemoteProtocolError as e:
                logger.debug("%s sent an invalid websocket frame: %s", self.description, e)
                self._closed = True
                continue
            for event in self._ws.events():
                if isinstance(event, BytesMessage):
                    self._pending.append(bytes(event.data))
                elif isinstance(event, Ping):
                    self._writer.write(self._ws.send(event.response()))
                    await self._writer.drain()
                elif isinstance(event, CloseConnection):
                    self.close_code, self.close_reason = event.code, event.reason
                    self._closed = True
                    with suppress(Exception):
                        self._writer.write(self._ws.send(event.response()))
                        await self._writer.drain()

    def close(self, code: int = 1000) -> None:
        """Close the websocket. Deliberately synchronous: an abandoned bridge (e.g. Ctrl+C on a
        live stream) is closed by GC with ``GeneratorExit``, where any await raises "coroutine
        ignored GeneratorExit". The close frame flushes with the transport's own close."""
        with suppress(Exception):
            self._writer.write(self._ws.send(CloseConnection(code=code)))
        with suppress(Exception):
            self._writer.close()


async def connect(
    host: str,
    port: int,
    udid: str,
    device_port: Optional[int] = None,
    address: Optional[str] = None,
    extra_headers: Optional[list[tuple[bytes, bytes]]] = None,
) -> ConnectWebsocket:
    """Open a ``/connect`` websocket on the tunneld at ``host``:``port``.

    :param udid: UDID of the target device.
    :param device_port: port to reach over the device's tunnel; ``None`` lets the serving tunneld
        apply its own default (the tunnel's RSD port).
    :param address: the device's tunnel address, naming which of its tunnels to use when it has
        more than one. Ignored by tunnelds predating the parameter, which key on the UDID alone.
    :param extra_headers: additional handshake headers (tunneld passes its federation hop budget).
    :raises ConnectionError: if the handshake fails, including a tunneld too old to serve
        ``/connect``.
    """
    description = f"tunneld at {host}:{port}"
    reader, writer = await asyncio.open_connection(host, port)
    try:
        ws = WSConnection(ConnectionType.CLIENT)
        target = f"/connect?udid={urllib.parse.quote(udid)}"
        if device_port is not None:
            target += f"&port={device_port}"
        if address is not None:
            target += f"&address={urllib.parse.quote(address)}"
        writer.write(ws.send(Request(host=f"{host}:{port}", target=target, extra_headers=extra_headers or [])))
        await writer.drain()
        while True:
            data = await reader.read(CHUNK_SIZE)
            if not data:
                raise ConnectionError(f"{description} closed the connection during the /connect websocket handshake")
            try:
                ws.receive_data(data)
            except RemoteProtocolError as e:
                raise ConnectionError(f"{description} sent an invalid websocket handshake response: {e}") from e
            for event in ws.events():
                if isinstance(event, AcceptConnection):
                    return ConnectWebsocket(reader, writer, ws, description)
                if isinstance(event, RejectConnection):
                    raise ConnectionError(
                        f"{description} rejected /connect (HTTP {event.status_code}); it likely predates the "
                        f"/connect endpoint — upgrade its pymobiledevice3"
                    )
    except BaseException:
        with suppress(Exception):
            writer.close()
        raise
