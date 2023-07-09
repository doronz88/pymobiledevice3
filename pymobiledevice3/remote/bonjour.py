import itertools
import time
from socket import AF_INET6, inet_ntop
from typing import List

from ifaddr import Adapter, get_adapters
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
from zeroconf.const import _TYPE_AAAA

DEFAULT_BONJOUR_TIMEOUT = 1


class RemotedListener(ServiceListener):
    def __init__(self, adapter: Adapter):
        super().__init__()
        self.adapter = adapter
        self.addresses: List[str] = []

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name == 'ncm._remoted._tcp.local.':
            service_info = zc.get_service_info(type_, name)
            entries_with_name = zc.cache.async_entries_with_name(service_info.server)
            for entry in entries_with_name:
                if entry.type == _TYPE_AAAA:
                    self.addresses.append(inet_ntop(AF_INET6, entry.address) + '%' + self.adapter.nice_name)


def query_bonjour(adapter: Adapter) -> RemotedListener:
    zeroconf = Zeroconf(interfaces=[adapter.ips[0].ip[0]])
    listener = RemotedListener(adapter)
    ServiceBrowser(zeroconf, '_remoted._tcp.local.', listener)
    return listener


def get_remoted_addresses(timeout: int = DEFAULT_BONJOUR_TIMEOUT) -> List[str]:
    adapters = [adapter for adapter in get_adapters() if adapter.ips[0].is_IPv6]
    listeners = [query_bonjour(adapter) for adapter in adapters]
    time.sleep(timeout)
    return list(itertools.chain.from_iterable([listener.addresses for listener in listeners]))
