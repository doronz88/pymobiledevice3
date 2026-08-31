import asyncio
import dataclasses
import json
import logging
import os
import signal
import time
import traceback
import urllib.parse
import warnings
from contextlib import asynccontextmanager, suppress
from ssl import SSLEOFError
from typing import Any, Optional, Union

import pydantic
import requests

from pymobiledevice3.bonjour import browse_remoted
from pymobiledevice3.tunneld import ws_bridge

with warnings.catch_warnings():
    # Ignore: "Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater."
    warnings.simplefilter("ignore", category=UserWarning)
    import fastapi

import uvicorn
from construct import StreamError
from fastapi import FastAPI
from packaging.version import Version

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import (
    ConnectionFailedError,
    ConnectionFailedToUsbmuxdError,
    ConnectionTerminatedError,
    DeviceNotFoundError,
    GetProhibitedError,
    IncorrectModeError,
    InvalidServiceError,
    LockdownError,
    MuxException,
    PairingError,
    QuicProtocolNotSupportedError,
    StreamClosedError,
)
from pymobiledevice3.lockdown import create_using_usbmux, get_mobdev2_lockdowns
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.module_imports import start_tunnel
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService
from pymobiledevice3.remote.tunnel_service import (
    CoreDeviceTunnelProxy,
    RemotePairingProtocol,
    RemotePairingTunnelService,
    TunnelResult,
    create_core_device_tunnel_service_using_rsd,
    get_remote_pairing_tunnel_services,
)
from pymobiledevice3.remote.utils import get_rsds, stop_remoted
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS
from pymobiledevice3.utils import asyncio_print_traceback
from pymobiledevice3.utils import current_task_name as _current_task_name

logger = logging.getLogger(__name__)

# bugfix: after the device reboots, it might take some time for remoted to start answering the bonjour queries
REATTEMPT_INTERVAL = 5
REATTEMPT_COUNT = 5

REMOTEPAIRING_INTERVAL = 5
MOBDEV2_INTERVAL = 5

# USB monitor will periodically forget what interfaces it has seen
# and force a full rescan.  The value is number of iterations of the
# inner loop (which sleeps one second each) before blowing away the
# `previous_ips` cache.
USB_MONITOR_RESCAN_INTERVAL = 30

USBMUX_INTERVAL = 2
OSUTILS = get_os_utils()

# Timeout for opening the TCP connection over the tunnel from the /connect websocket endpoint
CONNECT_TCP_TIMEOUT = 10

# Maximum concurrent /connect bridges
CONNECT_MAX_BRIDGES = 200

# Read chunk size used when proxying tunnel traffic over the /connect websocket endpoint
CONNECT_CHUNK_SIZE = 65536

# Application-specific websocket close codes (4000-4999) used by the /connect endpoint
WS_CLOSE_NO_TUNNEL = 4404
WS_CLOSE_CONNECT_FAILED = 4502

# Standard websocket close codes used by the /connect endpoint
WS_CLOSE_UNSUPPORTED_DATA = 1003
WS_CLOSE_TRY_AGAIN_LATER = 1013

_UPSTREAM_FETCH_TIMEOUT = 2.0

# Every federated listing request carries the number of upstream hops it may still traverse.
# Without it, tunnelds that register each other (A -> B -> A) recurse until the fetch timeouts
# unwind: the nesting spawns a growing tree of in-flight requests against the bounded
# to_thread executor, and the innermost fetches lose the race against their parents' timeouts,
# so a cycle drops the very listings it was meant to merge.
UPSTREAM_HOPS_HEADER = "x-tunneld-hops-remaining"
UPSTREAM_MAX_HOPS = 4

# How long a resolved "which upstream serves this UDID" answer is reused. A device session opens
# many service connections; re-listing every upstream for each one would add a round trip apiece.
_UPSTREAM_OWNER_TTL = 5.0


def normalize_upstream_url(url: str) -> str:
    """Canonicalize an upstream tunneld address to ``http://HOST:PORT``.

    Accepts ``HOST``, ``HOST:PORT`` and ``http://HOST[:PORT]`` (IPv6 in brackets), filling in
    tunneld's default port. Federation reads the address twice — ``requests`` fetches the listing
    from the URL, while the ``/connect`` relay dials the parsed host and port — so both are given
    one canonical form to agree on, and anything neither could act on is rejected here instead of
    failing silently later.

    :raises ValueError: if the address cannot be used as an upstream.
    """
    candidate = url.strip()
    if "//" not in candidate:
        # a bare 'lab-1:49151' parses as scheme 'lab-1', so spell the scheme out
        candidate = f"http://{candidate}"
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme != "http":
        raise ValueError(
            f"unsupported upstream scheme {parsed.scheme!r} in {url!r}: the /connect relay speaks "
            f"plaintext HTTP, so only http:// upstreams are supported"
        )
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError(f"upstream {url!r} must be a bare host[:port], carrying no path or query")
    try:
        port = parsed.port or TUNNELD_DEFAULT_ADDRESS[1]
    except ValueError as e:
        raise ValueError(f"upstream {url!r} has an invalid port") from e
    if not parsed.hostname:
        raise ValueError(f"upstream {url!r} names no host")
    # urlparse strips the brackets IPv6 literals need in a URL
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{host}:{port}"


def _tunnel_entry_key(entry: dict[str, Any]) -> tuple[Any, Any, Any]:
    """Identity of a listing entry, for de-duplicating tunnels reported through several paths."""
    return entry.get("tunnel-address"), entry.get("tunnel-port"), entry.get("interface")


def _fetch_upstream(url: str, hops_remaining: int) -> dict[str, Any]:
    """Fetch a tunneld listing from an upstream URL. Called in a worker thread
    via asyncio.to_thread; raises on any error so the caller can skip the
    upstream silently."""
    resp = requests.get(url, timeout=_UPSTREAM_FETCH_TIMEOUT, headers={UPSTREAM_HOPS_HEADER: str(hops_remaining)})
    resp.raise_for_status()
    return resp.json()


async def _close_quietly(websocket: fastapi.WebSocket, code: int = 1000, reason: Optional[str] = None) -> None:
    """Close the websocket, tolerating a client that already disconnected.

    Closing after the client dropped raises WebSocketDisconnect (starlette re-raises it
    from OSError); RuntimeError covers a close that was already sent.
    """
    with suppress(RuntimeError, fastapi.WebSocketDisconnect):
        await websocket.close(code=code, reason=reason)


@dataclasses.dataclass
class TunnelTask:
    task: asyncio.Task[None]
    udid: Optional[str] = None
    tunnel: Optional[TunnelResult] = None


class TunneldCore:
    def __init__(
        self,
        protocol: TunnelProtocol = TunnelProtocol.DEFAULT,
        wifi_monitor: bool = True,
        usb_monitor: bool = True,
        usbmux_monitor: bool = True,
        usbmux_address: Optional[str] = None,
        mobdev2_monitor: bool = True,
        upstreams: Optional[list[str]] = None,
    ) -> None:
        self.protocol = protocol
        self.tasks: list[asyncio.Task[None]] = []
        self.tunnel_tasks: dict[str, TunnelTask] = {}
        self.usb_monitor = usb_monitor
        self.wifi_monitor = wifi_monitor
        self.usbmux_monitor = usbmux_monitor
        self.usbmux_address = usbmux_address
        self.mobdev2_monitor = mobdev2_monitor
        # Upstream tunneld URLs, seeded from --upstream and registered at runtime via
        # POST /upstream. Each `GET /` request merges these tunnelds' listings into the local
        # one, and a `/connect` for a device none of our own tunnels serve is relayed to the
        # upstream that owns it - so one reachable tunneld fronts devices attached to hosts the
        # client has no route to.
        self.upstream_urls: set[str] = {normalize_upstream_url(url) for url in (upstreams or [])}

    def start(self) -> None:
        """Register all tasks"""
        self.tasks = []
        if self.usb_monitor:
            self.tasks.append(asyncio.create_task(self.monitor_usb_task(), name="monitor-usb-task"))
        if self.wifi_monitor:
            self.tasks.append(asyncio.create_task(self.monitor_wifi_task(), name="monitor-wifi-task"))
        if self.usbmux_monitor:
            self.tasks.append(asyncio.create_task(self.monitor_usbmux_task(), name="monitor-usbmux-task"))
        if self.mobdev2_monitor:
            self.tasks.append(asyncio.create_task(self.monitor_mobdev2_task(), name="monitor-mobdev2-task"))

    def get_tunnel(self, udid: str, address: Optional[str] = None) -> Optional[TunnelResult]:
        """The tunnel this instance holds for ``udid``, or ``None``.

        ``address`` selects a specific tunnel: a device can have more than one (another tunneld
        federated through this one may hold its own tunnel to the same device), and pairing one
        tunnel's address with another's port yields an endpoint that does not exist.
        """
        for task in self.tunnel_tasks.values():
            # Linux implementations of `usbmuxd` may report an incorrect value of UDID, dismissing the `-` character.
            # For such cases, we also check for a UDID without it.
            # See: <https://github.com/doronz88/pymobiledevice3/issues/1388#issuecomment-2782249770>
            task_udid = task.udid or ""
            if ((task_udid == udid) or (task_udid.replace("-", "") == udid)) and (task.tunnel is not None):
                if address is not None and task.tunnel.address != address:
                    continue
                return task.tunnel

        return None

    def tunnel_exists_for_udid(self, udid: str) -> bool:
        return self.get_tunnel(udid) is not None

    @asyncio_print_traceback
    async def monitor_usb_task(self) -> None:
        try:
            previous_ips = []
            iteration = 0
            while True:
                iteration += 1
                current_ips = OSUTILS.get_ipv6_ips()
                added = [ip for ip in current_ips if ip not in previous_ips]
                removed = [ip for ip in previous_ips if ip not in current_ips]

                # periodically forget what we have seen so that we reattempt
                # tunnels even if the interface didn't disappear / reappear
                if iteration >= USB_MONITOR_RESCAN_INTERVAL:
                    previous_ips = []
                    iteration = 0
                else:
                    previous_ips = current_ips

                # logger.debug(f'added interfaces: {added}')
                # logger.debug(f'removed interfaces: {removed}')

                for ip in removed:
                    if ip in self.tunnel_tasks:
                        self.tunnel_tasks[ip].task.cancel()
                        with suppress(asyncio.CancelledError):
                            await self.tunnel_tasks[ip].task

                if added:
                    # A new interface was attached
                    for answer in await browse_remoted():
                        for address in answer.addresses:
                            if address.iface.startswith("utun"):
                                # Skip already established tunnels
                                continue
                            if address.full_ip in self.tunnel_tasks:
                                # Skip already established tunnels
                                continue
                            self.tunnel_tasks[address.full_ip] = TunnelTask(
                                task=asyncio.create_task(
                                    self.handle_new_potential_usb_cdc_ncm_interface_task(address.full_ip),
                                    name=f"handle-new-potential-usb-cdc-ncm-interface-task-{address.full_ip}",
                                )
                            )

                # wait before re-iterating
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    @asyncio_print_traceback
    async def monitor_wifi_task(self) -> None:
        try:
            while True:
                remote_pairing_tunnel_services = []
                claimed_services: set[RemotePairingTunnelService] = set()
                try:
                    remote_pairing_tunnel_services = await get_remote_pairing_tunnel_services()
                    for service in remote_pairing_tunnel_services:
                        hostname = service.hostname
                        if hostname is None:
                            # a discovered RemotePairing service always carries the hostname it was
                            # browsed at; skip defensively rather than crash the monitor loop.
                            continue
                        if hostname in self.tunnel_tasks:
                            # skip tunnel if already exists for this ip
                            continue
                        if self.tunnel_exists_for_udid(service.remote_identifier):
                            # skip tunnel if already exists for this udid
                            continue
                        self.tunnel_tasks[hostname] = TunnelTask(
                            task=asyncio.create_task(
                                self.start_tunnel_task(hostname, service),
                                name=f"start-tunnel-task-wifi-{hostname}",
                            ),
                            udid=service.remote_identifier,
                        )
                        claimed_services.add(service)
                except asyncio.exceptions.IncompleteReadError:
                    logger.debug("Got IncompleteReadError from monitor-wifi-task")
                except asyncio.CancelledError:
                    # Raise and cancel gracefully
                    raise
                except Exception:
                    logger.error(f"Got exception from {_current_task_name()}")
                finally:
                    for service in remote_pairing_tunnel_services:
                        if service in claimed_services:
                            continue
                        with suppress(Exception):
                            await service.close()
                await asyncio.sleep(REMOTEPAIRING_INTERVAL)
        except asyncio.CancelledError:
            # Cancel gracefully
            pass

    @asyncio_print_traceback
    async def monitor_usbmux_task(self) -> None:
        while True:
            mux = None
            try:
                mux = await usbmux.create_mux(usbmux_address=self.usbmux_address)
                await mux.listen()

                while True:
                    await mux.receive_device_state_update()

                    mux_devices: list[usbmux.MuxDevice] = mux.devices
                    for mux_device in mux_devices:
                        task_identifier = f"usbmux-{mux_device.serial}-{mux_device.connection_type}"
                        if self.tunnel_exists_for_udid(mux_device.serial):
                            # Skip if already established a tunnel for this udid
                            continue
                        if task_identifier in self.tunnel_tasks:
                            # Skip if already trying to establish a tunnel for this device
                            continue
                        service = None
                        try:
                            async with await create_using_usbmux(
                                mux_device.serial, usbmux_address=self.usbmux_address
                            ) as lockdown:
                                service = await CoreDeviceTunnelProxy.create(lockdown)
                        except (
                            MuxException,
                            InvalidServiceError,
                            GetProhibitedError,
                            StreamError,
                            ConnectionTerminatedError,
                            DeviceNotFoundError,
                            LockdownError,
                            IncorrectModeError,
                            SSLEOFError,
                        ):
                            if service is not None:
                                await service.close()
                            continue
                        self.tunnel_tasks[task_identifier] = TunnelTask(
                            udid=mux_device.serial,
                            task=asyncio.create_task(
                                self.start_tunnel_task(task_identifier, service, protocol=TunnelProtocol.TCP),
                                name=f"start-tunnel-task-{task_identifier}",
                            ),
                        )
            except (ConnectionFailedToUsbmuxdError, OSError):
                # This is exception is expected to occur repeatedly on linux running usbmuxd
                # as long as there isn't any physical iDevice connected.
                # NOTE: ConnectionFailedToUsbmuxdError subclasses MuxException, so this more
                # specific handler must stay above the MuxException handler below.
                logger.debug("failed to connect to usbmux. waiting for it to restart")
                await asyncio.sleep(USBMUX_INTERVAL)
            except (BlockingIOError, StreamError, MuxException) as e:
                # Connection lost - will reconnect on next iteration.
                # MuxException("socket connection broken") is raised when usbmuxd drops the
                # listen socket on device replug/reboot (notably on Linux); reconnect instead
                # of letting the monitor task die (see issue #1742).
                logger.debug(f"usbmux connection error: {e}, reconnecting...")
                await asyncio.sleep(USBMUX_INTERVAL)
            except asyncio.CancelledError:
                break
            finally:
                if mux is not None:
                    await mux.close()

    @asyncio_print_traceback
    async def monitor_mobdev2_task(self) -> None:
        try:
            while True:
                async for ip, lockdown in get_mobdev2_lockdowns(only_paired=True):
                    async with lockdown:
                        udid = lockdown.udid
                        # a paired lockdown always exposes UniqueDeviceID
                        assert udid is not None
                        task_identifier = f"mobdev2-{udid}-{ip}"
                        if self.tunnel_exists_for_udid(udid):
                            # Skip tunnel if already exists for this udid
                            continue
                        if task_identifier in self.tunnel_tasks:
                            # Skip if already trying to establish a tunnel for this device
                            continue
                        try:
                            tunnel_service = await CoreDeviceTunnelProxy.create(lockdown)
                        except InvalidServiceError:
                            logger.warning(f"[{task_identifier}] failed to start CoreDeviceTunnelProxy - skipping")
                            continue
                    self.tunnel_tasks[task_identifier] = TunnelTask(
                        task=asyncio.create_task(
                            self.start_tunnel_task(task_identifier, tunnel_service),
                            name=f"start-tunnel-task-{task_identifier}",
                        ),
                        udid=udid,
                    )
                await asyncio.sleep(MOBDEV2_INTERVAL)
        except asyncio.CancelledError:
            pass

    @asyncio_print_traceback
    async def start_tunnel_task(
        self,
        task_identifier: str,
        protocol_handler: Union[RemotePairingProtocol, CoreDeviceTunnelProxy],
        queue: Optional[asyncio.Queue[Optional[TunnelResult]]] = None,
        protocol: Optional[TunnelProtocol] = None,
    ) -> None:
        if protocol is None:
            protocol = self.protocol
        if isinstance(protocol_handler, CoreDeviceTunnelProxy):
            protocol = TunnelProtocol.TCP
        tun = None
        bailed_out = False
        try:
            if self.tunnel_exists_for_udid(protocol_handler.remote_identifier):
                # cancel current tunnel creation
                raise asyncio.CancelledError()

            async with start_tunnel(protocol_handler, protocol=protocol) as tun:
                if not self.tunnel_exists_for_udid(protocol_handler.remote_identifier):
                    self.tunnel_tasks[task_identifier].tunnel = tun
                    self.tunnel_tasks[task_identifier].udid = protocol_handler.remote_identifier
                    if queue is not None:
                        queue.put_nowait(tun)
                        # avoid sending another message if succeeded
                        queue = None
                    logger.info(f"[{_current_task_name()}] Created tunnel --rsd {tun.address} {tun.port}")
                    await tun.client.wait_closed()
                else:
                    bailed_out = True
                    logger.debug(
                        f"[{_current_task_name()}] Not establishing tunnel since there is already an "
                        f"active one for same udid"
                    )
        except asyncio.CancelledError:
            pass
        except QuicProtocolNotSupportedError as e:
            logger.warning(f"[{_current_task_name()}] {e.__class__.__name__}: {e}")
        except (
            asyncio.exceptions.IncompleteReadError,
            TimeoutError,
            OSError,
            ConnectionResetError,
            StreamError,
            InvalidServiceError,
        ) as e:
            if tun is None:
                logger.debug(f"Got {e.__class__.__name__} from {_current_task_name()}")
            else:
                logger.debug(f"Got {e.__class__.__name__} from tunnel --rsd {tun.address} {tun.port}")
        except Exception:
            logger.exception(f"Got exception from {_current_task_name()}")
        finally:
            if queue is not None:
                # notify something went wrong
                queue.put_nowait(None)

            if tun is not None and not bailed_out:
                logger.info(f"Disconnected from tunnel --rsd {tun.address} {tun.port}")
                await tun.client.stop_tunnel()

            with suppress(OSError):
                await protocol_handler.close()

            if task_identifier in self.tunnel_tasks:
                # in case the tunnel was removed just now
                self.tunnel_tasks.pop(task_identifier)

    @asyncio_print_traceback
    async def handle_new_potential_usb_cdc_ncm_interface_task(self, ip: str) -> None:
        rsd = None
        try:
            # establish an untrusted RSD handshake
            rsd = RemoteServiceDiscoveryService((ip, RSD_PORT))

            with stop_remoted():
                first_time = True
                retry = False
                while retry or first_time:
                    retry = False
                    try:
                        await rsd.connect()
                    except StreamClosedError:
                        # Could be on first try because of remoted race
                        if first_time:
                            retry = True
                    except (ConnectionRefusedError, TimeoutError, OSError) as e:
                        raise asyncio.CancelledError() from e
                    finally:
                        first_time = False

            if (self.protocol == TunnelProtocol.QUIC) and (Version(rsd.product_version) < Version("17.0.0")):
                await rsd.close()
                rsd = None
                raise asyncio.CancelledError()

            try:
                core_device_tunnel = await create_core_device_tunnel_service_using_rsd(rsd)
            except InvalidServiceError as e:
                logger.warning(
                    f"[{_current_task_name()}] Skipping {rsd.product_type} ({rsd.product_version}): "
                    f"{e.__class__.__name__}: {e}"
                )
                raise asyncio.CancelledError() from e

            await asyncio.create_task(
                self.start_tunnel_task(ip, core_device_tunnel),
                name=f"start-tunnel-task-usb-{ip}",
            )
        except asyncio.CancelledError:
            pass
        except PairingError:
            logger.exception(f"Failed to pair with {ip}")
        except RuntimeError:
            logger.debug(f"Got RuntimeError from: {_current_task_name()}")
        except Exception:
            logger.exception(f"Error raised from: {_current_task_name()}: {traceback.format_exc()}")
        finally:
            if rsd is not None:
                with suppress(OSError):
                    await rsd.close()

            if ip in self.tunnel_tasks:
                # In case the tunnel was removed just now
                self.tunnel_tasks.pop(ip)

    async def close(self) -> None:
        """close all tasks"""
        for task in self.tasks + [tunnel_task.task for tunnel_task in self.tunnel_tasks.values()]:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    def get_tunnels_ips(self) -> dict[str, list[str]]:
        """Retrieve the available tunnel tasks and format them as {UDID: [IP]}"""
        tunnels_ips: dict[str, list[str]] = {}
        for ip, active_tunnel in self.tunnel_tasks.items():
            if (active_tunnel.udid is None) or (active_tunnel.tunnel is None):
                continue
            if active_tunnel.udid not in tunnels_ips:
                tunnels_ips[active_tunnel.udid] = [ip]
            else:
                tunnels_ips[active_tunnel.udid].append(ip)
        return tunnels_ips

    def cancel(self, udid: str) -> None:
        """Cancel active tunnels"""
        for tunnel_ip in self.get_tunnels_ips().get(udid, []):
            self.tunnel_tasks.pop(tunnel_ip).task.cancel()
            logger.info(f"Canceling tunnel {tunnel_ip}")

    def clear(self) -> None:
        """Clear active tunnels"""
        for _udid, tunnel in self.tunnel_tasks.items():
            logger.info(f"Removing tunnel {tunnel}")
            tunnel.task.cancel()
        self.tunnel_tasks = {}


class TunneldRunner:
    """TunneldRunner orchestrate between the webserver and TunneldCore"""

    @classmethod
    def create(
        cls,
        host: str,
        port: int,
        protocol: TunnelProtocol = TunnelProtocol.QUIC,
        usb_monitor: bool = True,
        wifi_monitor: bool = True,
        usbmux_monitor: bool = True,
        usbmux_address: Optional[str] = None,
        mobdev2_monitor: bool = True,
        upstreams: Optional[list[str]] = None,
    ) -> None:
        cls(
            host,
            port,
            protocol=protocol,
            usb_monitor=usb_monitor,
            wifi_monitor=wifi_monitor,
            usbmux_monitor=usbmux_monitor,
            usbmux_address=usbmux_address,
            mobdev2_monitor=mobdev2_monitor,
            upstreams=upstreams,
        )._run_app()

    def __init__(
        self,
        host: str,
        port: int,
        protocol: TunnelProtocol = TunnelProtocol.QUIC,
        usb_monitor: bool = True,
        wifi_monitor: bool = True,
        usbmux_monitor: bool = True,
        usbmux_address: Optional[str] = None,
        mobdev2_monitor: bool = True,
        upstreams: Optional[list[str]] = None,
    ):
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            self._tunneld_core.start()
            yield
            logger.info("Closing tunneld tasks...")
            await self._tunneld_core.close()

        self.host = host
        self.port = port
        self.protocol = protocol
        self._connect_bridge_count = 0
        # udid -> (expiry, upstream url), see _find_upstream_owner
        self._upstream_owners: dict[str, tuple[float, str]] = {}
        self._app = FastAPI(lifespan=lifespan)
        self._tunneld_core = TunneldCore(
            protocol=protocol,
            wifi_monitor=wifi_monitor,
            usb_monitor=usb_monitor,
            usbmux_monitor=usbmux_monitor,
            usbmux_address=usbmux_address,
            mobdev2_monitor=mobdev2_monitor,
            upstreams=upstreams,
        )

        @self._app.get("/")
        async def list_tunnels(
            hops_remaining: int = fastapi.Header(default=UPSTREAM_MAX_HOPS, alias=UPSTREAM_HOPS_HEADER),
        ) -> dict[str, list[dict[str, Any]]]:
            """Retrieve the available tunnels and format them as {UUID: TUNNEL_ADDRESS}.
            Listings from any registered upstream tunnelds (see POST /upstream) are
            fetched in parallel and merged into the response, up to ``hops_remaining``
            levels of federation (see UPSTREAM_HOPS_HEADER)."""
            tunnels: dict[str, list[dict[str, Any]]] = {}
            for ip, active_tunnel in self._tunneld_core.tunnel_tasks.items():
                if (active_tunnel.udid is None) or (active_tunnel.tunnel is None):
                    continue
                if active_tunnel.udid not in tunnels:
                    tunnels[active_tunnel.udid] = []
                tunnels[active_tunnel.udid].append({
                    "tunnel-address": active_tunnel.tunnel.address,
                    "tunnel-port": active_tunnel.tunnel.port,
                    "interface": ip,
                    "auxiliary-metadata": active_tunnel.tunnel.auxiliary_metadata,
                    # served by this instance: its /connect reaches the device directly
                    "origin": None,
                })

            upstream_urls = list(self._tunneld_core.upstream_urls)
            if upstream_urls and hops_remaining > 0:
                results = await asyncio.gather(
                    *(asyncio.to_thread(_fetch_upstream, url, hops_remaining - 1) for url in upstream_urls),
                    return_exceptions=True,
                )
                for url, result in zip(upstream_urls, results):
                    if isinstance(result, BaseException):
                        logger.debug(f"upstream tunneld {url} unreachable: {result!r}")
                        continue
                    for udid, entries in (result or {}).items():
                        merged = tunnels.setdefault(udid, [])
                        # a cycle (or two upstreams federating a third) reports the same tunnel
                        # through more than one path; list every tunnel once
                        known = {_tunnel_entry_key(entry) for entry in merged}
                        for entry in entries:
                            key = _tunnel_entry_key(entry)
                            if key in known:
                                continue
                            known.add(key)
                            # tag with the hop that reported it, overwriting what that upstream
                            # said about its own origin: this URL is the one a client can act on,
                            # and it is the next hop this instance's /connect would relay to
                            merged.append({**entry, "origin": url})
            return tunnels

        class _UpstreamBody(pydantic.BaseModel):
            url: str

        @self._app.get("/upstream")
        async def list_upstreams() -> list[str]:
            return sorted(self._tunneld_core.upstream_urls)

        @self._app.post("/upstream")
        async def add_upstream(body: _UpstreamBody) -> fastapi.Response:
            try:
                url = normalize_upstream_url(body.url)
            except ValueError as e:
                return fastapi.Response(status_code=400, content=json.dumps({"error": str(e)}))
            self._tunneld_core.upstream_urls.add(url)
            data: dict[str, Any] = {
                "operation": "add_upstream",
                "url": url,
                "data": True,
                "message": f"upstream {url} added",
            }
            return generate_http_response(data)

        @self._app.delete("/upstream")
        async def remove_upstream(body: _UpstreamBody) -> fastapi.Response:
            # normalized on the way in, so the caller may spell it either way
            with suppress(ValueError):
                self._tunneld_core.upstream_urls.discard(normalize_upstream_url(body.url))
            self._tunneld_core.upstream_urls.discard(body.url)
            data: dict[str, Any] = {
                "operation": "remove_upstream",
                "url": body.url,
                "data": True,
                "message": f"upstream {body.url} removed",
            }
            return generate_http_response(data)

        @self._app.get("/shutdown")
        async def shutdown() -> fastapi.Response:
            """Shutdown Tunneld"""
            os.kill(os.getpid(), signal.SIGINT)
            data: dict[str, Any] = {"operation": "shutdown", "data": True, "message": "Server shutting down..."}
            return generate_http_response(data)

        @self._app.get("/clear_tunnels")
        async def clear_tunnels() -> fastapi.Response:
            self._tunneld_core.clear()
            data: dict[str, Any] = {"operation": "clear_tunnels", "data": True, "message": "Cleared tunnels..."}
            return generate_http_response(data)

        @self._app.get("/cancel")
        async def cancel_tunnel(udid: str) -> fastapi.Response:
            self._tunneld_core.cancel(udid=udid)
            data: dict[str, Any] = {
                "operation": "cancel",
                "udid": udid,
                "data": True,
                "message": f"tunnel {udid} Canceled ...",
            }
            return generate_http_response(data)

        @self._app.get("/hello")
        async def hello() -> fastapi.Response:
            data = {"message": "Hello, I'm alive"}
            return generate_http_response(data)

        def generate_http_response(
            data: dict[str, Any], status_code: int = 200, media_type: str = "application/json"
        ) -> fastapi.Response:
            return fastapi.Response(status_code=status_code, media_type=media_type, content=json.dumps(data))

        @self._app.get("/start-tunnel")
        async def start_tunnel(
            udid: str, ip: Optional[str] = None, connection_type: Optional[str] = None
        ) -> fastapi.Response:
            udid_tunnels = [
                t.tunnel for t in self._tunneld_core.tunnel_tasks.values() if t.udid == udid and t.tunnel is not None
            ]
            if len(udid_tunnels) > 0:
                data: dict[str, Any] = {
                    "interface": udid_tunnels[0].interface,
                    "port": udid_tunnels[0].port,
                    "address": udid_tunnels[0].address,
                    "auxiliary-metadata": udid_tunnels[0].auxiliary_metadata,
                }
                return generate_http_response(data)

            queue: asyncio.Queue[Optional[TunnelResult]] = asyncio.Queue()
            created_task = False

            try:
                if not created_task and connection_type in ("usbmux", None):
                    task_identifier = f"usbmux-{udid}"
                    try:
                        async with await create_using_usbmux(
                            udid, usbmux_address=self._tunneld_core.usbmux_address
                        ) as lockdown:
                            service = await CoreDeviceTunnelProxy.create(lockdown)
                        task = asyncio.create_task(
                            self._tunneld_core.start_tunnel_task(
                                task_identifier, service, protocol=TunnelProtocol.TCP, queue=queue
                            ),
                            name=f"start-tunnel-task-{task_identifier}",
                        )
                        self._tunneld_core.tunnel_tasks[task_identifier] = TunnelTask(task=task, udid=udid)
                        created_task = True
                    except (ConnectionFailedError, InvalidServiceError, MuxException):
                        pass
                if connection_type in ("usb", None):
                    for rsd in await get_rsds(udid=udid):
                        rsd_ip = rsd.service.address[0]
                        if ip is not None and rsd_ip != ip:
                            await rsd.close()
                            continue
                        task = asyncio.create_task(
                            self._tunneld_core.start_tunnel_task(
                                rsd_ip, await create_core_device_tunnel_service_using_rsd(rsd), queue=queue
                            ),
                            name=f"start-tunnel-usb-{rsd_ip}",
                        )
                        self._tunneld_core.tunnel_tasks[rsd_ip] = TunnelTask(task=task, udid=rsd.udid)
                        created_task = True
                if not created_task and connection_type in ("wifi", None):
                    for remotepairing in await get_remote_pairing_tunnel_services(udid=udid):
                        remotepairing_ip = remotepairing.hostname
                        # a discovered service always carries the hostname it was browsed at
                        assert remotepairing_ip is not None
                        if ip is not None and remotepairing_ip != ip:
                            await remotepairing.close()
                            continue
                        task = asyncio.create_task(
                            self._tunneld_core.start_tunnel_task(remotepairing_ip, remotepairing, queue=queue),
                            name=f"start-tunnel-wifi-{remotepairing_ip}",
                        )
                        self._tunneld_core.tunnel_tasks[remotepairing_ip] = TunnelTask(
                            task=task, udid=remotepairing.remote_identifier
                        )
                        created_task = True
            except Exception as e:
                return fastapi.Response(
                    status_code=501,
                    content=json.dumps({
                        "error": {
                            "exception": e.__class__.__name__,
                            "traceback": traceback.format_exc(),
                        }
                    }),
                )

            if not created_task:
                return fastapi.Response(status_code=501, content=json.dumps({"error": "task not created"}))

            tunnel: Optional[TunnelResult] = await queue.get()
            if tunnel is not None:
                data: dict[str, Any] = {
                    "interface": tunnel.interface,
                    "port": tunnel.port,
                    "address": tunnel.address,
                    "auxiliary-metadata": tunnel.auxiliary_metadata,
                }
                return generate_http_response(data)
            else:
                return fastapi.Response(
                    status_code=404, content=json.dumps({"error": "something went wrong during tunnel creation"})
                )

        @self._app.websocket("/connect")
        async def connect(
            websocket: fastapi.WebSocket,
            udid: str,
            port: Optional[int] = fastapi.Query(default=None, ge=1, le=65535),
            address: Optional[str] = fastapi.Query(default=None),
            hops_remaining: int = fastapi.Header(default=UPSTREAM_MAX_HOPS, alias=UPSTREAM_HOPS_HEADER),
        ) -> None:
            """Bridge a websocket client into the tunnel interface of a given device.

            Binary websocket messages are forwarded as-is into a TCP connection opened over the
            device's tunnel — to the requested ``port``, defaulting to the RSD port — and vice
            versa, allowing clients without direct access to the tunnel interface (e.g. a
            different docker network stack, or a different host altogether) to reach the tunnel
            services through the tunneld HTTP API.
            """
            await websocket.accept()
            if self._connect_bridge_count >= CONNECT_MAX_BRIDGES:
                await _close_quietly(
                    websocket, code=WS_CLOSE_TRY_AGAIN_LATER, reason="too many concurrent /connect bridges"
                )
                return
            self._connect_bridge_count += 1
            try:
                await self._bridge_websocket(websocket, udid, port, hops_remaining, address)
            finally:
                self._connect_bridge_count -= 1

    async def _bridge_websocket(
        self,
        websocket: fastapi.WebSocket,
        udid: str,
        port: Optional[int],
        hops_remaining: int = UPSTREAM_MAX_HOPS,
        address: Optional[str] = None,
    ) -> None:
        tunnel = self._tunneld_core.get_tunnel(udid, address)
        if tunnel is None:
            # Not a tunnel of ours — the device may belong to a registered upstream, whose tunnel
            # interface is no more reachable from the client than it is from here, so relay rather
            # than redirect. This is also the path when we DO hold a tunnel for this device but the
            # caller asked for a different one of its tunnels.
            if await self._bridge_to_upstream(websocket, udid, port, hops_remaining, address):
                return
            await _close_quietly(websocket, code=WS_CLOSE_NO_TUNNEL, reason=f"no tunnel exists for udid: {udid}")
            return
        if port is None:
            port = tunnel.port
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(tunnel.address, port), timeout=CONNECT_TCP_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError) as e:
            await _close_quietly(
                websocket,
                code=WS_CLOSE_CONNECT_FAILED,
                reason=f"failed to connect to [{tunnel.address}]:{port}: {str(e) or 'timed out'}",
            )
            return

        async def forward_websocket_to_tcp() -> None:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    raise fastapi.WebSocketDisconnect(int(message.get("code") or 1000), message.get("reason"))
                data = message.get("bytes")
                if data is None:
                    # a text frame on what is strictly a binary bridge
                    await _close_quietly(
                        websocket, code=WS_CLOSE_UNSUPPORTED_DATA, reason="only binary websocket messages are supported"
                    )
                    return
                writer.write(data)
                await writer.drain()

        async def forward_tcp_to_websocket() -> None:
            while True:
                data = await reader.read(CONNECT_CHUNK_SIZE)
                if not data:
                    break
                await websocket.send_bytes(data)

        forwarders = [
            asyncio.create_task(forward_websocket_to_tcp(), name=f"connect-websocket-to-tcp-{udid}-{port}"),
            asyncio.create_task(forward_tcp_to_websocket(), name=f"connect-tcp-to-websocket-{udid}-{port}"),
        ]
        try:
            await asyncio.wait(forwarders, return_when=asyncio.FIRST_COMPLETED)
        finally:
            # the cleanup lives in the finally so a cancellation aimed at this task
            # (e.g. server shutdown) can't orphan the forwarders
            for forwarder in forwarders:
                forwarder.cancel()
            results = await asyncio.gather(*forwarders, return_exceptions=True)
            for forwarder, result in zip(forwarders, results):
                # disconnections from either side are expected; log anything else at debug
                if isinstance(result, Exception) and not isinstance(result, (fastapi.WebSocketDisconnect, OSError)):
                    logger.debug(f"unexpected error in {forwarder.get_name()}", exc_info=result)
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
            await _close_quietly(websocket)

    async def _find_upstream_owner(
        self, udid: str, hops_remaining: int, address: Optional[str] = None
    ) -> Optional[str]:
        """URL of the registered upstream serving ``udid`` (and, when given, that exact tunnel
        ``address``), or ``None``.

        Resolved from the upstreams' own listings — the same fetch `GET /` performs — and cached
        briefly, because a single device session opens many service connections."""
        if hops_remaining <= 0:
            return None
        urls = sorted(self._tunneld_core.upstream_urls)
        if not urls:
            return None
        now = time.monotonic()
        cache_key = f"{udid}@{address}" if address is not None else udid
        cached = self._upstream_owners.get(cache_key)
        if cached is not None and cached[0] > now:
            return cached[1]
        results = await asyncio.gather(
            *(asyncio.to_thread(_fetch_upstream, url, hops_remaining - 1) for url in urls),
            return_exceptions=True,
        )
        # Linux usbmuxd may report a UDID without its dashes (see TunneldCore.get_tunnel)
        wanted = udid.replace("-", "")
        for url, result in zip(urls, results):
            if isinstance(result, BaseException):
                logger.debug(f"upstream tunneld {url} unreachable: {result!r}")
                continue
            for served, entries in (result or {}).items():
                if served.replace("-", "") != wanted:
                    continue
                if address is not None and not any(entry.get("tunnel-address") == address for entry in entries):
                    continue
                self._upstream_owners[cache_key] = (now + _UPSTREAM_OWNER_TTL, url)
                return url
        return None

    async def _bridge_to_upstream(
        self,
        websocket: fastapi.WebSocket,
        udid: str,
        port: Optional[int],
        hops_remaining: int,
        address: Optional[str] = None,
    ) -> bool:
        """Relay this ``/connect`` to the upstream tunneld that owns ``udid``.

        Returns ``False`` when no upstream serves the device, leaving the websocket untouched for
        the caller to close."""
        url = await self._find_upstream_owner(udid, hops_remaining, address)
        if url is None:
            return False
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname is None:
            logger.debug(f"upstream tunneld {url} has no host to connect to")
            return False
        try:
            upstream = await asyncio.wait_for(
                ws_bridge.connect(
                    parsed.hostname,
                    parsed.port or 80,
                    udid,
                    port,
                    address=address,
                    extra_headers=[(UPSTREAM_HOPS_HEADER.encode(), str(hops_remaining - 1).encode())],
                ),
                timeout=CONNECT_TCP_TIMEOUT,
            )
        except (ConnectionError, OSError, asyncio.TimeoutError) as e:
            await _close_quietly(
                websocket,
                code=WS_CLOSE_CONNECT_FAILED,
                reason=f"failed to reach upstream {url}: {str(e) or 'timed out'}",
            )
            return True

        async def forward_websocket_to_upstream() -> None:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    raise fastapi.WebSocketDisconnect(int(message.get("code") or 1000), message.get("reason"))
                data = message.get("bytes")
                if data is None:
                    # a text frame on what is strictly a binary bridge
                    await _close_quietly(
                        websocket, code=WS_CLOSE_UNSUPPORTED_DATA, reason="only binary websocket messages are supported"
                    )
                    return
                await upstream.send_bytes(data)

        async def forward_upstream_to_websocket() -> None:
            while True:
                data = await upstream.recv_bytes()
                if data is None:
                    break
                await websocket.send_bytes(data)

        forwarders = [
            asyncio.create_task(forward_websocket_to_upstream(), name=f"upstream-websocket-to-upstream-{udid}-{port}"),
            asyncio.create_task(forward_upstream_to_websocket(), name=f"upstream-to-websocket-{udid}-{port}"),
        ]
        try:
            await asyncio.wait(forwarders, return_when=asyncio.FIRST_COMPLETED)
        finally:
            # mirrors _bridge_websocket: cleanup in the finally so a cancellation aimed at this
            # task can't orphan the forwarders
            for forwarder in forwarders:
                forwarder.cancel()
            results = await asyncio.gather(*forwarders, return_exceptions=True)
            for forwarder, result in zip(forwarders, results):
                if isinstance(result, Exception) and not isinstance(result, (fastapi.WebSocketDisconnect, OSError)):
                    logger.debug(f"unexpected error in {forwarder.get_name()}", exc_info=result)
            upstream.close()
            # pass the upstream's own close code through, so a client debugging a federated
            # topology sees 4404/4502 from the tunneld that actually refused
            await _close_quietly(websocket, code=upstream.close_code or 1000, reason=upstream.close_reason)
        return True

    def _run_app(self) -> None:
        # per-message deflate would burn CPU compressing the mostly-encrypted tunnel
        # traffic bridged over /connect
        uvicorn.run(
            self._app, host=self.host, port=self.port, loop="asyncio", ws="wsproto", ws_per_message_deflate=False
        )
