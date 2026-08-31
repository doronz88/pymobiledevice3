import asyncio
import ipaddress
import logging
import socket
from contextlib import suppress
from typing import Any, Optional

import requests

from pymobiledevice3.exceptions import TunneldConnectionError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.tunneld import ws_bridge

logger = logging.getLogger(__name__)

TUNNELD_DEFAULT_ADDRESS = ("127.0.0.1", 49151)

# ``(host, port)`` TCP address of a running ``tunneld`` HTTP server
TunneldAddress = tuple[str, int]


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
        upstream = await ws_bridge.connect(
            self._tunneld_address[0], self._tunneld_address[1], self._udid, port, address=self._tunnel_address
        )
        caller_sock, bridge_sock = socket.socketpair()
        try:
            bridge_reader, bridge_writer = await asyncio.open_connection(sock=bridge_sock)
        except BaseException:
            bridge_sock.close()
            caller_sock.close()
            upstream.close()
            raise
        try:
            reader, writer = await asyncio.open_connection(sock=caller_sock)
        except BaseException:
            caller_sock.close()
            with suppress(Exception):
                bridge_writer.close()
            upstream.close()
            raise
        pump = asyncio.create_task(
            self._pump(upstream, bridge_reader, bridge_writer),
            name=f"tunneld-connect-bridge-{self._udid}-{port}",
        )
        self._pumps.add(pump)
        pump.add_done_callback(self._pumps.discard)
        return reader, writer

    async def _pump(
        self,
        upstream: ws_bridge.ConnectWebsocket,
        bridge_reader: asyncio.StreamReader,
        bridge_writer: asyncio.StreamWriter,
    ) -> None:
        """Bridge the caller's socketpair leg and the websocket leg until either side ends."""

        async def caller_to_ws() -> None:
            try:
                while True:
                    data = await bridge_reader.read(ws_bridge.CHUNK_SIZE)
                    if not data:
                        break
                    await upstream.send_bytes(data)
            except Exception:
                pass
            finally:
                # The caller is gone — nothing can be delivered to it anymore, so end the
                # websocket leg entirely; tunneld then closes its device-side TCP connection.
                # Teardown stays synchronous (see ConnectWebsocket.close).
                upstream.close()

        async def ws_to_caller() -> None:
            try:
                while True:
                    data = await upstream.recv_bytes()
                    if data is None:
                        break
                    bridge_writer.write(data)
                    await bridge_writer.drain()
            except Exception:
                pass
            finally:
                # surface tunneld's application close codes (e.g. 4404 no tunnel, 4502 connect
                # failed) — a plain EOF is all the caller will ever see
                if upstream.close_code is not None and upstream.close_code != 1000:
                    logger.warning(
                        "tunneld /connect bridge closed: %s (%s)", upstream.close_code, upstream.close_reason
                    )
                # deliver EOF to the caller so its pending reads finish; the caller's close
                # then ends caller_to_ws
                with suppress(Exception):
                    if bridge_writer.can_write_eof():
                        bridge_writer.write_eof()

        try:
            await asyncio.gather(caller_to_ws(), ws_to_caller())
        finally:
            # synchronous closes only (see caller_to_ws)
            with suppress(Exception):
                bridge_writer.close()
            upstream.close()


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
