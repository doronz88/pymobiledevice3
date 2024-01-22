import asyncio
import dataclasses
import logging
import os
import signal
import sys
import traceback
from contextlib import asynccontextmanager, suppress
from typing import Dict, List, Optional, Tuple

import fastapi
import uvicorn
from fastapi import FastAPI
from ifaddr import get_adapters
from packaging.version import Version

from pymobiledevice3.remote.bonjour import query_bonjour
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.core_device_tunnel_service import TunnelResult
from pymobiledevice3.remote.module_imports import start_tunnel
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService
from pymobiledevice3.remote.utils import stop_remoted

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TunnelTask:
    task: asyncio.Task
    udid: Optional[str] = None
    tunnel: Optional[TunnelResult] = None


class TunneldCore:
    def __init__(self, protocol: TunnelProtocol = TunnelProtocol.QUIC):
        self.protocol = protocol
        self.tasks: List[asyncio.Task] = []
        self.tunnel_tasks: Dict[str, TunnelTask] = {}

    def start(self) -> None:
        """ Register all tasks """
        self.tasks = [
            asyncio.create_task(self.monitor_adapters(), name='monitor_adapters'),
        ]

    async def monitor_adapters(self):
        previous_ips = []
        while True:
            if sys.platform == 'win32':
                current_ips = [f'{adapter.ips[0].ip[0]}%{adapter.ips[0].ip[2]}' for adapter in get_adapters() if
                               adapter.ips[0].is_IPv6]
            else:
                current_ips = [f'{adapter.ips[0].ip[0]}%{adapter.nice_name}' for adapter in get_adapters() if
                               adapter.ips[0].is_IPv6]

            added = [ip for ip in current_ips if ip not in previous_ips]
            removed = [ip for ip in previous_ips if ip not in current_ips]

            previous_ips = current_ips

            logger.debug(f'added interfaces: {added}')
            logger.debug(f'removed interfaces: {removed}')

            for ip in removed:
                if ip in self.tunnel_tasks:
                    self.tunnel_tasks[ip].task.cancel()
                    await self.tunnel_tasks[ip].task

            for ip in added:
                self.tunnel_tasks[ip] = TunnelTask(
                    task=asyncio.create_task(self.handle_new_ip(ip), name='handle_new_address'))

            # wait before re-iterating
            await asyncio.sleep(1)

    async def handle_new_ip(self, ip: str):
        tun = None
        try:
            # browse the adapter for CoreDevices
            query = query_bonjour(ip)

            # wait the response to arrive
            await asyncio.sleep(1)

            # validate a CoreDevice was indeed found
            addresses = query.listener.addresses
            if not addresses:
                raise asyncio.CancelledError()
            peer_address = addresses[0]

            # establish an untrusted RSD handshake
            rsd = RemoteServiceDiscoveryService((peer_address, RSD_PORT))
            with stop_remoted():
                try:
                    rsd.connect()
                except ConnectionRefusedError:
                    raise asyncio.CancelledError()

            if (self.protocol == TunnelProtocol.QUIC) and (Version(rsd.product_version) < Version('17.0.0')):
                raise asyncio.CancelledError()

            # populate the udid from the untrusted RSD information
            self.tunnel_tasks[ip].udid = rsd.udid

            # establish a trusted tunnel
            async with start_tunnel(rsd, protocol=self.protocol) as tun:
                self.tunnel_tasks[ip].tunnel = tun
                logger.info(f'Created tunnel --rsd {tun.address} {tun.port}')
                await tun.client.wait_closed()

        except asyncio.CancelledError:
            pass
        except Exception:
            logger.error(traceback.format_exc())
        finally:
            if tun is not None:
                logger.info(f'disconnected from tunnel --rsd {tun.address} {tun.port}')

            if ip in self.tunnel_tasks:
                # in case the tunnel was removed just now
                self.tunnel_tasks.pop(ip)

    async def close(self):
        """ close all tasks """
        for task in self.tasks + [tunnel_task.task for tunnel_task in self.tunnel_tasks.values()]:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    def clear(self) -> None:
        """ Clear active tunnels """
        for udid, tunnel in self.tunnel_tasks.items():
            logger.info(f'Removing tunnel {tunnel}')
            tunnel.task.cancel()
        self.tunnel_tasks = {}


class TunneldRunner:
    """ TunneldRunner orchestrate between the webserver and TunneldCore """

    @classmethod
    def create(cls, host: str, port: int, protocol: TunnelProtocol = TunnelProtocol.QUIC) -> None:
        cls(host, port, protocol=protocol)._run_app()

    def __init__(self, host: str, port: int, protocol: TunnelProtocol = TunnelProtocol.QUIC):
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            logging.getLogger('zeroconf').disabled = True
            self._tunneld_core.start()
            yield
            logger.info('Closing tunneld tasks...')
            await self._tunneld_core.close()

        self.host = host
        self.port = port
        self.protocol = protocol
        self._app = FastAPI(lifespan=lifespan)
        self._tunneld_core = TunneldCore(protocol)

        @self._app.get('/')
        async def list_tunnels() -> Dict[str, Tuple]:
            """ Retrieve the available tunnels and format them as {UUID: TUNNEL_ADDRESS} """
            tunnels = {}
            for ip, active_tunnel in self._tunneld_core.tunnel_tasks.items():
                if (active_tunnel.udid is not None) and (active_tunnel.tunnel is not None):
                    tunnels[active_tunnel.udid] = (active_tunnel.tunnel.address, active_tunnel.tunnel.port)
            return tunnels

        @self._app.get('/shutdown')
        async def shutdown() -> fastapi.Response:
            """ Shutdown Tunneld """
            os.kill(os.getpid(), signal.SIGINT)
            return fastapi.Response(status_code=200, content='Server shutting down...')

        @self._app.get('/clear_tunnels')
        async def clear_tunnels() -> fastapi.Response:
            self._tunneld_core.clear()
            return fastapi.Response(status_code=200, content='Cleared tunnels...')

    def _run_app(self) -> None:
        uvicorn.run(self._app, host=self.host, port=self.port, loop='asyncio')
