import asyncio
import dataclasses
import json
import logging
import os
import signal
import traceback
from contextlib import asynccontextmanager, suppress
from typing import Dict, List, Mapping, Optional, Tuple, Union

import construct
import fastapi
import requests
import uvicorn
from construct import StreamError
from fastapi import FastAPI
from packaging.version import Version

from pymobiledevice3 import usbmux
from pymobiledevice3.bonjour import REMOTED_SERVICE_NAMES, browse
from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionFailedToUsbmuxdError, GetProhibitedError, \
    InvalidServiceError, MuxException, PairingError, TunneldConnectionError
from pymobiledevice3.lockdown import create_using_usbmux, get_mobdev2_lockdowns
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.module_imports import start_tunnel
from pymobiledevice3.remote.remote_service_discovery import RSD_PORT, RemoteServiceDiscoveryService
from pymobiledevice3.remote.tunnel_service import CoreDeviceTunnelProxy, RemotePairingProtocol, TunnelResult, \
    create_core_device_tunnel_service_using_rsd, get_remote_pairing_tunnel_services
from pymobiledevice3.remote.utils import get_rsds, stop_remoted
from pymobiledevice3.utils import asyncio_print_traceback, get_asyncio_loop

logger = logging.getLogger(__name__)

TUNNELD_DEFAULT_ADDRESS = ('127.0.0.1', 49151)

# bugfix: after the device reboots, it might take some time for remoted to start answering the bonjour queries
REATTEMPT_INTERVAL = 5
REATTEMPT_COUNT = 5

REMOTEPAIRING_INTERVAL = 5
MOVDEV2_INTERVAL = 5

USBMUX_INTERVAL = 2
OSUTILS = get_os_utils()


@dataclasses.dataclass
class TunnelTask:
    task: asyncio.Task
    udid: Optional[str] = None
    tunnel: Optional[TunnelResult] = None


class TunneldCore:
    def __init__(self, protocol: TunnelProtocol = TunnelProtocol.QUIC, wifi_monitor: bool = True,
                 usb_monitor: bool = True, usbmux_monitor: bool = True, mobdev2_monitor: bool = True) -> None:
        self.protocol = protocol
        self.tasks: List[asyncio.Task] = []
        self.tunnel_tasks: Dict[str, TunnelTask] = {}
        self.usb_monitor = usb_monitor
        self.wifi_monitor = wifi_monitor
        self.usbmux_monitor = usbmux_monitor
        self.mobdev2_monitor = mobdev2_monitor

    def start(self) -> None:
        """ Register all tasks """
        self.tasks = []
        if self.usb_monitor:
            self.tasks.append(asyncio.create_task(self.monitor_usb_task(), name='monitor-usb-task'))
        if self.wifi_monitor:
            self.tasks.append(asyncio.create_task(self.monitor_wifi_task(), name='monitor-wifi-task'))
        if self.usbmux_monitor:
            self.tasks.append(asyncio.create_task(self.monitor_usbmux_task(), name='monitor-usbmux-task'))
        if self.mobdev2_monitor:
            self.tasks.append(asyncio.create_task(self.monitor_mobdev2_task(), name='monitor-mobdev2-task'))

    def tunnel_exists_for_udid(self, udid: str) -> bool:
        for task in self.tunnel_tasks.values():
            if (task.udid == udid) and (task.tunnel is not None):
                return True
        return False

    @asyncio_print_traceback
    async def monitor_usb_task(self) -> None:
        previous_ips = []
        while True:
            current_ips = OSUTILS.get_ipv6_ips()
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
                    task=asyncio.create_task(self.handle_new_potential_usb_cdc_ncm_interface_task(ip),
                                             name=f'handle-new-potential-usb-cdc-ncm-interface-task-{ip}'))

            # wait before re-iterating
            await asyncio.sleep(1)

    @asyncio_print_traceback
    async def monitor_wifi_task(self) -> None:
        try:
            while True:
                for service in await get_remote_pairing_tunnel_services():
                    if service.hostname in self.tunnel_tasks:
                        # skip tunnel if already exists for this ip
                        await service.close()
                        continue
                    if self.tunnel_exists_for_udid(service.remote_identifier):
                        # skip tunnel if already exists for this udid
                        await service.close()
                        continue
                    self.tunnel_tasks[service.hostname] = TunnelTask(
                        task=asyncio.create_task(self.start_tunnel_task(service.hostname, service),
                                                 name=f'start-tunnel-task-wifi-{service.hostname}'),
                        udid=service.remote_identifier
                    )
                await asyncio.sleep(REMOTEPAIRING_INTERVAL)
        except asyncio.CancelledError:
            pass

    @asyncio_print_traceback
    async def monitor_usbmux_task(self) -> None:
        try:
            while True:
                try:
                    for mux_device in usbmux.list_devices():
                        task_identifier = f'usbmux-{mux_device.serial}-{mux_device.connection_type}'
                        if self.tunnel_exists_for_udid(mux_device.serial):
                            continue
                        try:
                            service = CoreDeviceTunnelProxy(create_using_usbmux(mux_device.serial))
                        except (MuxException, InvalidServiceError, GetProhibitedError, construct.core.StreamError):
                            continue
                        self.tunnel_tasks[task_identifier] = TunnelTask(
                            udid=mux_device.serial,
                            task=asyncio.create_task(
                                self.start_tunnel_task(task_identifier,
                                                       service,
                                                       protocol=TunnelProtocol.TCP),
                                name=f'start-tunnel-task-{task_identifier}'))
                except ConnectionFailedToUsbmuxdError:
                    # This is exception is expected to occur repeatedly on linux running usbmuxd
                    # as long as there isn't any physical iDevice connected
                    logger.debug('failed to connect to usbmux. waiting for it to restart')
                finally:
                    await asyncio.sleep(USBMUX_INTERVAL)
        except asyncio.CancelledError:
            pass

    @asyncio_print_traceback
    async def monitor_mobdev2_task(self) -> None:
        try:
            while True:
                async for ip, lockdown in get_mobdev2_lockdowns(only_paired=True):
                    if self.tunnel_exists_for_udid(lockdown.udid):
                        # skip tunnel if already exists for this udid
                        continue
                    task_identifier = f'mobdev2-{lockdown.udid}-{ip}'
                    try:
                        tunnel_service = CoreDeviceTunnelProxy(lockdown)
                    except InvalidServiceError:
                        logger.warning(f'[{task_identifier}] failed to start CoreDeviceTunnelProxy - skipping')
                        continue
                    self.tunnel_tasks[task_identifier] = TunnelTask(
                        task=asyncio.create_task(self.start_tunnel_task(task_identifier, tunnel_service),
                                                 name=f'start-tunnel-task-{task_identifier}'),
                        udid=lockdown.udid
                    )
                await asyncio.sleep(MOVDEV2_INTERVAL)
        except asyncio.CancelledError:
            pass

    @asyncio_print_traceback
    async def start_tunnel_task(
            self, task_identifier: str, protocol_handler: Union[RemotePairingProtocol, CoreDeviceTunnelProxy],
            queue: Optional[asyncio.Queue] = None, protocol: Optional[TunnelProtocol] = None) -> None:
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
                    logger.info(f'[{asyncio.current_task().get_name()}] Created tunnel --rsd {tun.address} {tun.port}')
                    await tun.client.wait_closed()
                else:
                    bailed_out = True
                    logger.debug(
                        f'not establishing tunnel from {asyncio.current_task().get_name()} '
                        f'since there is already an active one for same udid')
        except asyncio.CancelledError:
            pass
        except (ConnectionResetError, StreamError) as e:
            logger.debug(f'got {e.__class__.__name__} from {asyncio.current_task().get_name()}')
        except (asyncio.exceptions.IncompleteReadError, TimeoutError, OSError) as e:
            logger.debug(f'got {e.__class__.__name__} from tunnel --rsd {tun.address} {tun.port}')
        except Exception:
            logger.error(f'got exception from {asyncio.current_task().get_name()}: {traceback.format_exc()}')
        finally:
            if queue is not None:
                # notify something went wrong
                queue.put_nowait(None)

            if tun is not None and not bailed_out:
                logger.info(f'disconnected from tunnel --rsd {tun.address} {tun.port}')

            if protocol_handler is not None:
                try:
                    await protocol_handler.close()
                except OSError:
                    pass

            if task_identifier in self.tunnel_tasks:
                # in case the tunnel was removed just now
                self.tunnel_tasks.pop(task_identifier)

    @asyncio_print_traceback
    async def handle_new_potential_usb_cdc_ncm_interface_task(self, ip: str) -> None:
        rsd = None
        try:
            answers = None
            for i in range(REATTEMPT_COUNT):
                answers = await browse(REMOTED_SERVICE_NAMES, [ip])
                if answers:
                    break
                logger.debug(f'No addresses found for: {ip}')
                await asyncio.sleep(REATTEMPT_INTERVAL)

            if not answers:
                raise asyncio.CancelledError()

            peer_address = answers[0].ips[0]

            # establish an untrusted RSD handshake
            rsd = RemoteServiceDiscoveryService((peer_address, RSD_PORT))

            with stop_remoted():
                try:
                    await rsd.connect()
                except (ConnectionRefusedError, TimeoutError):
                    raise asyncio.CancelledError()

            if (self.protocol == TunnelProtocol.QUIC) and (Version(rsd.product_version) < Version('17.0.0')):
                await rsd.close()
                raise asyncio.CancelledError()

            await asyncio.create_task(
                self.start_tunnel_task(ip, await create_core_device_tunnel_service_using_rsd(rsd)),
                name=f'start-tunnel-task-usb-{ip}')
        except asyncio.CancelledError:
            pass
        except PairingError as e:
            logger.error(f'Failed to pair with {ip} with error: {e}')
        except RuntimeError:
            logger.debug(f'Got RuntimeError from: {asyncio.current_task().get_name()}')
        except Exception:
            logger.error(f'Error raised from: {asyncio.current_task().get_name()}: {traceback.format_exc()}')
        finally:
            if rsd is not None:
                try:
                    await rsd.close()
                except OSError:
                    pass

            if ip in self.tunnel_tasks:
                # in case the tunnel was removed just now
                self.tunnel_tasks.pop(ip)

    async def close(self) -> None:
        """ close all tasks """
        for task in self.tasks + [tunnel_task.task for tunnel_task in self.tunnel_tasks.values()]:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    def get_tunnels_ips(self) -> Dict:
        """ Retrieve the available tunnel tasks and format them as {UDID: [IP]} """
        tunnels_ips = {}
        for ip, active_tunnel in self.tunnel_tasks.items():
            if (active_tunnel.udid is None) or (active_tunnel.tunnel is None):
                continue
            if active_tunnel.udid not in tunnels_ips:
                tunnels_ips[active_tunnel.udid] = [ip]
            else:
                tunnels_ips[active_tunnel.udid].append(ip)
        return tunnels_ips

    def cancel(self, udid: str) -> None:
        """ Cancel active tunnels """
        for tunnel_ip in self.get_tunnels_ips().get(udid, []):
            self.tunnel_tasks.pop(tunnel_ip).task.cancel()
            logger.info(f'canceling tunnel {tunnel_ip}')

    def clear(self) -> None:
        """ Clear active tunnels """
        for udid, tunnel in self.tunnel_tasks.items():
            logger.info(f'Removing tunnel {tunnel}')
            tunnel.task.cancel()
        self.tunnel_tasks = {}


class TunneldRunner:
    """ TunneldRunner orchestrate between the webserver and TunneldCore """

    @classmethod
    def create(cls, host: str, port: int, protocol: TunnelProtocol = TunnelProtocol.QUIC, usb_monitor: bool = True,
               wifi_monitor: bool = True, usbmux_monitor: bool = True, mobdev2_monitor: bool = True) -> None:
        cls(host, port, protocol=protocol, usb_monitor=usb_monitor, wifi_monitor=wifi_monitor,
            usbmux_monitor=usbmux_monitor, mobdev2_monitor=mobdev2_monitor)._run_app()

    def __init__(self, host: str, port: int, protocol: TunnelProtocol = TunnelProtocol.QUIC, usb_monitor: bool = True,
                 wifi_monitor: bool = True, usbmux_monitor: bool = True, mobdev2_monitor: bool = True):
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
        self._tunneld_core = TunneldCore(protocol=protocol, wifi_monitor=wifi_monitor, usb_monitor=usb_monitor,
                                         usbmux_monitor=usbmux_monitor, mobdev2_monitor=mobdev2_monitor)

        @self._app.get('/')
        async def list_tunnels() -> Mapping[str, List[Mapping]]:
            """ Retrieve the available tunnels and format them as {UUID: TUNNEL_ADDRESS} """
            tunnels = {}
            for ip, active_tunnel in self._tunneld_core.tunnel_tasks.items():
                if (active_tunnel.udid is None) or (active_tunnel.tunnel is None):
                    continue
                if active_tunnel.udid not in tunnels:
                    tunnels[active_tunnel.udid] = []
                tunnels[active_tunnel.udid].append(({
                    'tunnel-address': active_tunnel.tunnel.address,
                    'tunnel-port': active_tunnel.tunnel.port,
                    'interface': ip}))
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

        @self._app.get('/cancel')
        async def cancel_tunnel(udid: str) -> fastapi.Response:
            self._tunneld_core.cancel(udid=udid)
            return fastapi.Response(status_code=200, content=f'tunnel {udid} Canceled ...')

        @self._app.get('/hello')
        async def hello() -> fastapi.Response:
            response = {'message': 'Hello, I\'m alive'}
            return fastapi.Response(status_code=200, media_type="application/json", content=json.dumps(response))

        def generate_tunnel_response(tunnel: TunnelResult) -> fastapi.Response:
            return fastapi.Response(
                status_code=200,
                content=json.dumps({'interface': tunnel.interface, 'port': tunnel.port, 'address': tunnel.address}))

        @self._app.get('/start-tunnel')
        async def start_tunnel(
                udid: str, ip: Optional[str] = None, connection_type: Optional[str] = None) -> fastapi.Response:
            udid_tunnels = [t.tunnel for t in self._tunneld_core.tunnel_tasks.values() if t.udid == udid]
            if len(udid_tunnels) > 0:
                return generate_tunnel_response(udid_tunnels[0])

            queue = asyncio.Queue()
            created_task = False

            try:
                if not created_task and connection_type in ('usbmux', None):
                    task_identifier = f'usbmux-{udid}'
                    try:
                        service = CoreDeviceTunnelProxy(create_using_usbmux(udid))
                        task = asyncio.create_task(
                            self._tunneld_core.start_tunnel_task(task_identifier, service, protocol=TunnelProtocol.TCP,
                                                                 queue=queue),
                            name=f'start-tunnel-task-{task_identifier}')
                        self._tunneld_core.tunnel_tasks[task_identifier] = TunnelTask(task=task, udid=udid)
                        created_task = True
                    except (ConnectionFailedError, InvalidServiceError, MuxException):
                        pass
                if connection_type in ('usb', None):
                    for rsd in await get_rsds(udid=udid):
                        rsd_ip = rsd.service.address[0]
                        if ip is not None and rsd_ip != ip:
                            await rsd.close()
                            continue
                        task = asyncio.create_task(
                            self._tunneld_core.start_tunnel_task(rsd_ip,
                                                                 await create_core_device_tunnel_service_using_rsd(rsd),
                                                                 queue=queue),
                            name=f'start-tunnel-usb-{rsd_ip}')
                        self._tunneld_core.tunnel_tasks[rsd_ip] = TunnelTask(task=task, udid=rsd.udid)
                        created_task = True
                if not created_task and connection_type in ('wifi', None):
                    for remotepairing in await get_remote_pairing_tunnel_services(udid=udid):
                        remotepairing_ip = remotepairing.hostname
                        if ip is not None and remotepairing_ip != ip:
                            await remotepairing.close()
                            continue
                        task = asyncio.create_task(
                            self._tunneld_core.start_tunnel_task(remotepairing_ip, remotepairing, queue=queue),
                            name=f'start-tunnel-wifi-{remotepairing_ip}')
                        self._tunneld_core.tunnel_tasks[remotepairing_ip] = TunnelTask(
                            task=task, udid=remotepairing.remote_identifier)
                        created_task = True
            except Exception as e:
                return fastapi.Response(status_code=501,
                                        content=json.dumps({'error': {
                                            'exception': e.__class__.__name__,
                                            'traceback': traceback.format_exc(),
                                        }}))

            if not created_task:
                return fastapi.Response(status_code=501, content=json.dumps({'error': 'task not not created'}))

            tunnel: Optional[TunnelResult] = await queue.get()
            if tunnel is not None:
                return generate_tunnel_response(tunnel)
            else:
                return fastapi.Response(status_code=404,
                                        content=json.dumps({'error': 'something went wrong during tunnel creation'}))

    def _run_app(self) -> None:
        uvicorn.run(self._app, host=self.host, port=self.port, loop='asyncio')


async def async_get_tunneld_devices(tunneld_address: Tuple[str, int] = TUNNELD_DEFAULT_ADDRESS) \
        -> List[RemoteServiceDiscoveryService]:
    tunnels = _list_tunnels(tunneld_address)
    return await _create_rsds_from_tunnels(tunnels)


def get_tunneld_devices(tunneld_address: Tuple[str, int] = TUNNELD_DEFAULT_ADDRESS) \
        -> List[RemoteServiceDiscoveryService]:
    return get_asyncio_loop().run_until_complete(async_get_tunneld_devices(tunneld_address))


async def async_get_tunneld_device_by_udid(udid: str, tunneld_address: Tuple[str, int] = TUNNELD_DEFAULT_ADDRESS) \
        -> Optional[RemoteServiceDiscoveryService]:
    tunnels = _list_tunnels(tunneld_address)
    if udid not in tunnels:
        return None
    rsds = await _create_rsds_from_tunnels({udid: tunnels[udid]})
    return rsds[0]


def get_tunneld_device_by_udid(udid: str, tunneld_address: Tuple[str, int] = TUNNELD_DEFAULT_ADDRESS) \
        -> Optional[RemoteServiceDiscoveryService]:
    return get_asyncio_loop().run_until_complete(async_get_tunneld_device_by_udid(udid, tunneld_address))


def _list_tunnels(tunneld_address: Tuple[str, int] = TUNNELD_DEFAULT_ADDRESS) -> Mapping[str, List[Mapping]]:
    try:
        # Get the list of tunnels from the specified address
        resp = requests.get(f'http://{tunneld_address[0]}:{tunneld_address[1]}')
        tunnels = resp.json()
    except requests.exceptions.ConnectionError:
        raise TunneldConnectionError()
    return tunnels


async def _create_rsds_from_tunnels(tunnels: Mapping[str, List[Mapping]]) -> List[RemoteServiceDiscoveryService]:
    rsds = []
    for udid, details in tunnels.items():
        for tunnel_details in details:
            rsd = RemoteServiceDiscoveryService((tunnel_details['tunnel-address'], tunnel_details['tunnel-port']),
                                                name=tunnel_details['interface'])
            try:
                await rsd.connect()
                rsds.append(rsd)
            except (TimeoutError, ConnectionError):
                continue
    return rsds
