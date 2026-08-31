import asyncio
import ipaddress
import logging
import socket
import urllib.parse
from contextlib import suppress
from typing import Any, Optional

import requests
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, BytesMessage, CloseConnection, Ping, Pong, RejectConnection, Request
from wsproto.utilities import RemoteProtocolError

from pymobiledevice3.exceptions import TunneldConnectionError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.service_connection import close_stream_writer

logger = logging.getLogger(__name__)

TUNNELD_DEFAULT_ADDRESS = ("127.0.0.1", 49151)

# ``(host, port)`` TCP address of a running ``tunneld`` HTTP server
TunneldAddress = tuple[str, int]

# Read chunk size on both legs of a /connect bridge
_BRIDGE_CHUNK_SIZE = 65536


class TunneldConnectDialer:
    """``asyncio.open_connection``-compatible dialer bridging device-bound connections through a
    tunneld's ``WS /connect`` endpoint.

    When tunneld runs where its tunnel interface is unreachable from this process — another host,
    a different docker network stack, or behind an SSH port-forward — the RSD addresses reported
    over ``GET /`` cannot be dialed directly. :meth:`dial` bridges instead: it opens a websocket to
    ``/connect?udid=...&port=...`` and hands the caller one end of a local ``socket.socketpair``
    whose other end is pumped against the websocket. The caller side is a real socket, so consumers
    that reach for ``writer.get_extra_info('socket')`` (``ServiceConnection``) keep working. Dials
    to any address other than the device's tunnel address fall through to the stdlib dialer.

    Pass :meth:`dial` to ``RemoteServiceDiscoveryService(open_connection=...)``. There is nothing
    to tear down explicitly: each bridge's pump ends when either of its legs closes, so closing the
    RSD (which closes every service connection opened through it) ends every bridge.
    """

    def __init__(self, tunneld_address: TunneldAddress, udid: str, tunnel_address: str) -> None:
        """
        :param tunneld_address: ``(host, port)`` of the ``tunneld`` HTTP server.
        :param udid: UDID of the target device (the ``?udid=`` of ``/connect``).
        :param tunnel_address: the device's tunnel address; only dials to it are bridged.
        """
        self._tunneld_address = tunneld_address
        self._udid = udid
        self._tunnel_address = str(tunnel_address)
        # strong refs so in-flight pump tasks aren't garbage collected mid-bridge
        self._pumps: set[asyncio.Task[None]] = set()

    async def dial(
        self, host: Optional[str] = None, port: Optional[int] = None, **kwargs: Any
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """``asyncio.open_connection``-compatible dialer passed to the RSD via ``open_connection=``.

        Connections to the device's tunnel address are bridged through ``/connect``; everything
        else falls through to the stdlib ``asyncio.open_connection`` unchanged."""
        if host is None or str(host) != self._tunnel_address:
            return await asyncio.open_connection(host, port, **kwargs)
        assert port is not None
        ws_reader, ws_writer, ws = await self._websocket_handshake(port)
        caller_sock, bridge_sock = socket.socketpair()
        try:
            bridge_reader, bridge_writer = await asyncio.open_connection(sock=bridge_sock)
        except BaseException:
            bridge_sock.close()
            caller_sock.close()
            await close_stream_writer(ws_writer)
            raise
        try:
            reader, writer = await asyncio.open_connection(sock=caller_sock)
        except BaseException:
            caller_sock.close()
            await close_stream_writer(bridge_writer)
            await close_stream_writer(ws_writer)
            raise
        pump = asyncio.create_task(
            self._pump(ws, ws_reader, ws_writer, bridge_reader, bridge_writer),
            name=f"tunneld-connect-bridge-{self._udid}-{port}",
        )
        self._pumps.add(pump)
        pump.add_done_callback(self._pumps.discard)
        return reader, writer

    async def _websocket_handshake(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, WSConnection]:
        """Connect to tunneld and upgrade to a ``/connect`` websocket, returning the connected
        stream pair and the wsproto state machine (in the ``OPEN`` state)."""
        host_header = f"{self._tunneld_address[0]}:{self._tunneld_address[1]}"
        reader, writer = await asyncio.open_connection(self._tunneld_address[0], self._tunneld_address[1])
        try:
            ws = WSConnection(ConnectionType.CLIENT)
            target = f"/connect?udid={urllib.parse.quote(self._udid)}&port={port}"
            writer.write(ws.send(Request(host=host_header, target=target)))
            await writer.drain()
            while True:
                data = await reader.read(_BRIDGE_CHUNK_SIZE)
                if not data:
                    raise ConnectionError(
                        f"tunneld at {host_header} closed the connection during the /connect websocket handshake"
                    )
                try:
                    ws.receive_data(data)
                except RemoteProtocolError as e:
                    raise ConnectionError(
                        f"tunneld at {host_header} sent an invalid websocket handshake response: {e}"
                    ) from e
                for event in ws.events():
                    if isinstance(event, AcceptConnection):
                        return reader, writer, ws
                    if isinstance(event, RejectConnection):
                        raise ConnectionError(
                            f"tunneld at {host_header} rejected /connect (HTTP {event.status_code}); "
                            f"it likely predates the /connect endpoint — upgrade its pymobiledevice3"
                        )
        except BaseException:
            await close_stream_writer(writer)
            raise

    async def _pump(
        self,
        ws: WSConnection,
        ws_reader: asyncio.StreamReader,
        ws_writer: asyncio.StreamWriter,
        bridge_reader: asyncio.StreamReader,
        bridge_writer: asyncio.StreamWriter,
    ) -> None:
        """Bridge the caller's socketpair leg and the websocket leg until either side ends."""

        async def caller_to_ws() -> None:
            try:
                while True:
                    data = await bridge_reader.read(_BRIDGE_CHUNK_SIZE)
                    if not data:
                        break
                    ws_writer.write(ws.send(BytesMessage(data=data)))
                    await ws_writer.drain()
            except Exception:
                pass
            finally:
                # The caller is gone — nothing can be delivered to it anymore, so end the
                # websocket leg entirely; tunneld then closes its device-side TCP connection.
                # Teardown must stay synchronous: an abandoned bridge (e.g. Ctrl+C on a live
                # stream) is closed by GC with GeneratorExit, where any await raises
                # "coroutine ignored GeneratorExit". The close frame flushes with the
                # transport's own close.
                with suppress(Exception):
                    ws_writer.write(ws.send(CloseConnection(code=1000)))
                with suppress(Exception):
                    ws_writer.close()

        async def ws_to_caller() -> None:
            try:
                while True:
                    data = await ws_reader.read(_BRIDGE_CHUNK_SIZE)
                    if not data:
                        break
                    ws.receive_data(data)
                    for event in ws.events():
                        if isinstance(event, BytesMessage):
                            bridge_writer.write(event.data)
                            await bridge_writer.drain()
                        elif isinstance(event, Ping):
                            ws_writer.write(ws.send(Pong(payload=event.payload)))
                            await ws_writer.drain()
                        elif isinstance(event, CloseConnection):
                            # surface tunneld's application close codes (e.g. 4404 no tunnel,
                            # 4502 connect failed) — a plain EOF is all the caller will see
                            if event.code != 1000:
                                logger.warning("tunneld /connect bridge closed: %s (%s)", event.code, event.reason)
                            with suppress(Exception):
                                ws_writer.write(ws.send(event.response()))
                                await ws_writer.drain()
                            return
            except Exception:
                pass
            finally:
                # deliver EOF to the caller so its pending reads finish; the caller's close
                # then ends caller_to_ws
                with suppress(Exception):
                    if bridge_writer.can_write_eof():
                        bridge_writer.write_eof()

        try:
            await asyncio.gather(caller_to_ws(), ws_to_caller())
        finally:
            # synchronous closes only (see caller_to_ws); the transports finish closing on
            # the loop
            for writer in (bridge_writer, ws_writer):
                with suppress(Exception):
                    writer.close()


def _bridge_by_default(tunneld_address: TunneldAddress) -> bool:
    """Whether connections should be bridged through ``/connect`` when the caller didn't say:
    yes iff the tunneld host is non-loopback (its tunnel interface cannot be reachable locally).
    A loopback tunneld is local, where dialing the tunnel interface directly is faster; pass
    ``bridge=True`` explicitly for a local address that actually forwards to a remote tunneld
    (e.g. an SSH port-forward)."""
    host = tunneld_address[0]
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() != "localhost"


async def get_tunneld_devices(
    tunneld_address: TunneldAddress = TUNNELD_DEFAULT_ADDRESS, bridge: Optional[bool] = None
) -> list[RemoteServiceDiscoveryService]:
    """
    Query a running ``tunneld`` instance over HTTP for all active tunnels and connect to each.

    :param tunneld_address: ``(host, port)`` of the ``tunneld`` HTTP server.
    :param bridge: bridge connections through tunneld's ``WS /connect`` endpoint instead of dialing
        the tunnel interface directly — required when that interface is unreachable from this
        process (tunneld on another host, a different docker network stack, or behind an SSH
        port-forward). ``None`` bridges automatically when ``tunneld_address`` is a non-loopback
        TCP host.
    :returns: a connected `RemoteServiceDiscoveryService`
        for every tunnel that could be reached; tunnels that fail to connect are skipped.
    :raises TunneldConnectionError: if the ``tunneld`` instance cannot be reached.
    """
    tunnels = _list_tunnels(tunneld_address)
    return await _create_rsds_from_tunnels(tunnels, tunneld_address, bridge)


async def get_tunneld_device_by_udid(
    udid: str, tunneld_address: TunneldAddress = TUNNELD_DEFAULT_ADDRESS, bridge: Optional[bool] = None
) -> Optional[RemoteServiceDiscoveryService]:
    """
    Query a running ``tunneld`` instance over HTTP for the tunnel matching a given UDID and connect.

    :param udid: UDID of the target device.
    :param tunneld_address: ``(host, port)`` of the ``tunneld`` HTTP server.
    :param bridge: bridge connections through tunneld's ``WS /connect`` endpoint instead of dialing
        the tunnel interface directly (see `get_tunneld_devices`).
    :returns: a connected
        `RemoteServiceDiscoveryService` for
        the device, or ``None`` if ``tunneld`` reports no tunnel for the UDID.
    :raises TunneldConnectionError: if the ``tunneld`` instance cannot be reached.
    """
    tunnels = _list_tunnels(tunneld_address)
    if udid not in tunnels:
        return None
    rsds = await _create_rsds_from_tunnels({udid: tunnels[udid]}, tunneld_address, bridge)
    return rsds[0]


def _list_tunnels(tunneld_address: TunneldAddress = TUNNELD_DEFAULT_ADDRESS) -> dict[str, list[dict[str, Any]]]:
    try:
        resp = requests.get(f"http://{tunneld_address[0]}:{tunneld_address[1]}")
        tunnels = resp.json()
    except (requests.exceptions.ConnectionError, OSError) as e:
        raise TunneldConnectionError() from e
    return tunnels


async def _create_rsds_from_tunnels(
    tunnels: dict[str, list[dict[str, Any]]], tunneld_address: TunneldAddress, bridge: Optional[bool] = None
) -> list[RemoteServiceDiscoveryService]:
    if bridge is None:
        bridge = _bridge_by_default(tunneld_address)
    rsds: list[RemoteServiceDiscoveryService] = []
    for udid, details in tunnels.items():
        for tunnel_details in details:
            open_connection = None
            if bridge:
                dialer = TunneldConnectDialer(tunneld_address, udid, tunnel_details["tunnel-address"])
                open_connection = dialer.dial
            rsd = RemoteServiceDiscoveryService(
                (tunnel_details["tunnel-address"], tunnel_details["tunnel-port"]),
                name=tunnel_details["interface"],
                open_connection=open_connection,
                auxiliary_metadata=tunnel_details.get("auxiliary-metadata"),
            )
            try:
                await rsd.connect()
                rsds.append(rsd)
            except (TimeoutError, ConnectionError):
                continue
    return rsds
