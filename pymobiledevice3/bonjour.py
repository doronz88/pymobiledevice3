import asyncio
import dataclasses
from socket import AF_INET, AF_INET6, inet_ntop
from typing import List, Mapping, Optional

from ifaddr import get_adapters
from zeroconf import IPVersion, ServiceListener, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from pymobiledevice3.osu.os_utils import get_os_utils

REMOTEPAIRING_SERVICE_NAMES = ['_remotepairing._tcp.local.']
REMOTEPAIRING_MANUAL_PAIRING_SERVICE_NAMES = ['_remotepairing-manual-pairing._tcp.local.']
MOBDEV2_SERVICE_NAMES = ['_apple-mobdev2._tcp.local.']
REMOTED_SERVICE_NAMES = ['_remoted._tcp.local.']
OSUTILS = get_os_utils()
DEFAULT_BONJOUR_TIMEOUT = OSUTILS.bonjour_timeout


@dataclasses.dataclass
class BonjourAnswer:
    name: str
    properties: Mapping[bytes, bytes]
    ips: List[str]
    port: int


class BonjourListener(ServiceListener):
    def __init__(self, ip: str):
        super().__init__()
        self.name: Optional[str] = None
        self.properties: Mapping[bytes, bytes] = {}
        self.ip = ip
        self.port: Optional[int] = None
        self.addresses: List[str] = []
        self.queue: asyncio.Queue = asyncio.Queue()
        self.querying_task: Optional[asyncio.Task] = asyncio.create_task(self.query_addresses())

    def async_on_service_state_change(
            self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
        self.queue.put_nowait((zeroconf, service_type, name, state_change))

    async def query_addresses(self) -> None:
        zeroconf, service_type, name, state_change = await self.queue.get()
        self.name = name
        service_info = AsyncServiceInfo(service_type, name)
        await service_info.async_request(zeroconf, 3000)
        ipv4 = [inet_ntop(AF_INET, address.packed) for address in
                service_info.ip_addresses_by_version(IPVersion.V4Only)]
        ipv6 = []
        if '%' in self.ip:
            ipv6 = [inet_ntop(AF_INET6, address.packed) + '%' + self.ip.split('%')[1] for address in
                    service_info.ip_addresses_by_version(IPVersion.V6Only)]
        self.addresses = ipv4 + ipv6
        self.properties = service_info.properties
        self.port = service_info.port

    async def close(self) -> None:
        self.querying_task.cancel()
        try:
            await self.querying_task
        except asyncio.CancelledError:
            pass


@dataclasses.dataclass
class BonjourQuery:
    zc: AsyncZeroconf
    service_browser: AsyncServiceBrowser
    listener: BonjourListener


def query_bonjour(service_names: List[str], ip: str) -> BonjourQuery:
    aiozc = AsyncZeroconf(interfaces=[ip])
    listener = BonjourListener(ip)
    service_browser = AsyncServiceBrowser(aiozc.zeroconf, service_names,
                                          handlers=[listener.async_on_service_state_change])
    return BonjourQuery(aiozc, service_browser, listener)


async def browse(service_names: List[str], ips: List[str], timeout: float = DEFAULT_BONJOUR_TIMEOUT) \
        -> List[BonjourAnswer]:
    bonjour_queries = [query_bonjour(service_names, adapter) for adapter in ips]
    answers = []
    await asyncio.sleep(timeout)
    for bonjour_query in bonjour_queries:
        if bonjour_query.listener.addresses:
            answer = BonjourAnswer(
                bonjour_query.listener.name, bonjour_query.listener.properties, bonjour_query.listener.addresses,
                bonjour_query.listener.port)
            if answer not in answers:
                answers.append(answer)
        await bonjour_query.listener.close()
        await bonjour_query.service_browser.async_cancel()
        await bonjour_query.zc.async_close()
    return answers


async def browse_ipv6(service_names: List[str], timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[BonjourAnswer]:
    return await browse(service_names, OSUTILS.get_ipv6_ips(), timeout=timeout)


def get_ipv4_addresses() -> List[str]:
    ips = []
    for adapter in get_adapters():
        if adapter.nice_name.startswith('tun'):
            # skip browsing on already established tunnels
            continue
        for ip in adapter.ips:
            if ip.ip == '127.0.0.1':
                continue
            if not ip.is_IPv4:
                continue
            ips.append(ip.ip)
    return ips


async def browse_ipv4(service_names: List[str], timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[BonjourAnswer]:
    return await browse(service_names, get_ipv4_addresses(), timeout=timeout)


async def browse_remoted(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[BonjourAnswer]:
    return await browse_ipv6(REMOTED_SERVICE_NAMES, timeout=timeout)


async def browse_mobdev2(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[BonjourAnswer]:
    return await browse(MOBDEV2_SERVICE_NAMES, get_ipv4_addresses() + OSUTILS.get_ipv6_ips(), timeout=timeout)


async def browse_remotepairing(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[BonjourAnswer]:
    return await browse_ipv4(REMOTEPAIRING_SERVICE_NAMES, timeout=timeout)


async def browse_remotepairing_manual_pairing(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[BonjourAnswer]:
    return await browse_ipv4(REMOTEPAIRING_MANUAL_PAIRING_SERVICE_NAMES, timeout=timeout)
