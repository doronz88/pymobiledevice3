import dataclasses
import sys
import time
from socket import AF_INET6, inet_ntop
from typing import List

from ifaddr import get_adapters
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
from zeroconf.const import _TYPE_AAAA

DEFAULT_BONJOUR_TIMEOUT = 1 if sys.platform != 'win32' else 2  # On Windows, it takes longer to get the addresses


class RemotedListener(ServiceListener):
    def __init__(self, ip: str):
        super().__init__()
        self.ip = ip
        self.addresses: List[str] = []

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name == 'ncm._remoted._tcp.local.':
            service_info = zc.get_service_info(type_, name)
            entries_with_name = zc.cache.async_entries_with_name(service_info.server)
            for entry in entries_with_name:
                if entry.type == _TYPE_AAAA:
                    self.addresses.append(inet_ntop(AF_INET6, entry.address) + '%' + self.ip.split('%')[1])

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


@dataclasses.dataclass
class BonjourQuery:
    zc: Zeroconf
    service_browser: ServiceBrowser
    listener: RemotedListener


def query_bonjour(ip: str) -> BonjourQuery:
    zc = Zeroconf(interfaces=[ip.split('%')[0]])
    listener = RemotedListener(ip)
    service_browser = ServiceBrowser(zc, '_remoted._tcp.local.', listener)
    return BonjourQuery(zc, service_browser, listener)


def get_remoted_addresses(timeout: int = DEFAULT_BONJOUR_TIMEOUT) -> List[str]:
    if sys.platform == 'win32':
        ips = [f'{adapter.ips[0].ip[0]}%{adapter.ips[0].ip[2]}' for adapter in get_adapters() if adapter.ips[0].is_IPv6]
    else:
        ips = [f'{adapter.ips[0].ip[0]}%{adapter.nice_name}' for adapter in get_adapters() if adapter.ips[0].is_IPv6]
    bonjour_queries = [query_bonjour(adapter) for adapter in ips]
    time.sleep(timeout)
    addresses = []
    for bonjour_query in bonjour_queries:
        addresses += bonjour_query.listener.addresses
        bonjour_query.service_browser.cancel()
        bonjour_query.zc.close()
    return addresses
