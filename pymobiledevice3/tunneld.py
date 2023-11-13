import asyncio
import dataclasses
import logging
import os
import signal
from contextlib import suppress
from typing import Dict, Tuple

import fastapi
import ifaddr.netifaces
import uvicorn
import zeroconf
from fastapi import FastAPI
from packaging import version
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncZeroconf

from pymobiledevice3.exceptions import InterfaceIndexNotFoundError
from pymobiledevice3.remote.module_imports import start_quic_tunnel
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.utils import stop_remoted

logger = logging.getLogger(__name__)

ZEROCONF_TIMEOUT = 3000
MIN_VERSION = '17.0.0'
UNINIT_ADDRESS = ('', 0)


@dataclasses.dataclass
class Tunnel:
    rsd: RemoteServiceDiscoveryService
    task: asyncio.Task = None
    address: Tuple[str, int] = UNINIT_ADDRESS


class TunneldCore:
    def __init__(self):
        self.adapters: Dict[int, str] = {}
        self.active_tunnels: Dict[int, Tunnel] = {}
        self._type = '_remoted._tcp.local.'
        self._name = 'ncm._remoted._tcp.local.'
        self._interval = .5
        self.tasks = []

    def start(self) -> None:
        """ Register all tasks """
        self.tasks = [
            asyncio.create_task(self.update_adapters(), name='update_adapters'),
            asyncio.create_task(self.remove_detached_devices(), name='remove_detached_devices'),
            asyncio.create_task(self.discover_new_devices(), name='discover_new_devices'),
        ]

    async def close(self):
        """ close all tasks """
        for task in self.tasks:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    def clear(self) -> None:
        """ Clear active tunnels """
        for udid, tunnel in self.active_tunnels.items():
            logger.info(f'Removing tunnel {tunnel.address}')
            tunnel.rsd.close()
            tunnel.task.cancel()
        self.active_tunnels = {}

    @staticmethod
    async def handle_new_tunnel(tun: Tunnel) -> None:
        """ Create new tunnel """
        async with start_quic_tunnel(tun.rsd) as tunnel_result:
            tun.address = tunnel_result.address, tunnel_result.port
            logger.info(f'Created tunnel --rsd {tun.address[0]} {tun.address[1]}')
            await tunnel_result.client.wait_closed()

    @staticmethod
    async def connect_rsd(address: str, port: int) -> RemoteServiceDiscoveryService:
        """ Connect to RSD """
        with stop_remoted():
            rsd = RemoteServiceDiscoveryService((address, port))
            rsd.connect()
            return rsd

    async def update_adapters(self) -> None:
        """ Constantly updates the 'adapters' dictionary with IPv6 addresses linked to network interfaces """
        while True:
            self.adapters = {iface.index: addr.ip[0] for iface in ifaddr.get_adapters() for addr in iface.ips if
                             addr.is_IPv6}
            await asyncio.sleep(self._interval)

    async def remove_detached_devices(self) -> None:
        """ Continuously checks if adapters were removed and removes associated tunnels """
        while True:
            # Find active tunnels that are no longer associated with adapters
            diff = list(set(self.active_tunnels.keys()) - set(self.adapters.keys()))
            # For each detached tunnel, cancel its task, log the removal, and remove it from the active tunnels
            for k in diff:
                self.active_tunnels[k].task.cancel()
                self.active_tunnels[k].rsd.close()
                logger.info(f'Removing tunnel {self.active_tunnels[k].address}')
                self.active_tunnels.pop(k)

            await asyncio.sleep(self._interval)

    def get_interface_index(self, address: str) -> int:
        """
        To address the issue of an unknown IPv6 scope id for a device, we employ a workaround.
        We maintain a mapping that associates the scope id with the adapter address.
        To resolve this, we remove the last segment (quartet) from both the adapter address and the target address.
        If there is a match, we retrieve the scope id associated with that adapter and use it.

        Disclaimer: Matching addresses based on their segments may result in interface collision in specific network
        configurations.
        """
        address_segments = address.split(':')[:-1]
        for k, v in self.adapters.items():
            if address_segments != v.split(':')[:-1]:
                continue
            return k
        raise InterfaceIndexNotFoundError(address=address)

    async def discover_new_devices(self) -> None:
        """ Continuously scans for devices advertising 'RSD' through IPv6 adapters """
        while True:
            # Search for devices advertising the specified service type and name
            async with AsyncZeroconf(ip_version=IPVersion.V6Only) as aiozc:
                try:
                    info = await aiozc.async_get_service_info(self._type, self._name, timeout=ZEROCONF_TIMEOUT)
                except zeroconf.Error as e:
                    logger.warning(e)
                    continue
                if info is None:
                    continue
                # Extract device details
                addr = info.parsed_addresses(IPVersion.V6Only)[0]
                try:
                    interface_index = self.get_interface_index(addr)
                except InterfaceIndexNotFoundError as e:
                    logger.warning(f'Failed to find interface index for {e.address}')
                    continue
                if interface_index in self.active_tunnels:
                    continue
                # Connect to the discovered device
                addr = f'{addr}%{interface_index}'
                try:
                    rsd = await self.connect_rsd(addr, info.port)
                except (TimeoutError, ConnectionError, OSError):
                    logger.warning(f'Failed to connect rsd to {addr}')
                    continue
                # Check unsupported devices with a product version below a minimum threshold
                if version.parse(rsd.product_version) < version.parse(MIN_VERSION):
                    logger.warning(f'{rsd.udid} Unsupported device {rsd.product_version} < {MIN_VERSION}')
                    continue
                logger.info(f'Creating tunnel for {addr}')
                tunnel = Tunnel(rsd)
                # Add the tunnel to the active tunnels and start a handling task
                tunnel.task = asyncio.create_task(self.handle_new_tunnel(tunnel))
                self.active_tunnels[interface_index] = tunnel
            await asyncio.sleep(self._interval)


class TunneldRunner:
    """ TunneldRunner orchestrate between the webserver and TunneldCore """
    @classmethod
    def create(cls, host: str, port: int) -> None:
        cls(host, port)._run_app()

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._app = FastAPI()
        self._tunneld_core = TunneldCore()

        @self._app.get('/')
        async def list_tunnels() -> Dict[str, Tuple[str, int]]:
            """ Retrieve the available tunnels and format them as {UUID: TUNNEL_ADDRESS} """
            tunnels = {}
            for k, v in self._tunneld_core.active_tunnels.items():
                if v.address == UNINIT_ADDRESS:
                    continue
                tunnels[v.rsd.udid] = v.address
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

        @self._app.on_event('startup')
        async def on_startup() -> None:
            """ start TunneldCore """
            logging.getLogger('zeroconf').disabled = True
            self._tunneld_core.start()

        @self._app.on_event('shutdown')
        async def on_close() -> None:
            logger.info('Closing tunneld tasks...')
            await self._tunneld_core.close()

    def _run_app(self) -> None:
        uvicorn.run(self._app, host=self.host, port=self.port, loop='asyncio')
