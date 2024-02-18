import asyncio
import sys
import time
from typing import List, Optional

from ifaddr import get_adapters
from zeroconf import ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

DEFAULT_BONJOUR_TIMEOUT = 1 if sys.platform != 'win32' else 2  # On Windows, it takes longer to get the addresses


class Notifier:
    def __init__(self):
        self.addresses: List[str] = []

    def async_on_service_state_change(self, zeroconf: Zeroconf, service_type: str, name: str,
                                      state_change: ServiceStateChange) -> None:
        if state_change is not ServiceStateChange.Added:
            return
        asyncio.ensure_future(self.async_display_service_info(zeroconf, service_type, name))

    async def async_display_service_info(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        info = AsyncServiceInfo(service_type, name)
        await info.async_request(zeroconf, 3000)
        if info:
            self.addresses = info.parsed_scoped_addresses()


class AsyncRunner:
    def __init__(self) -> None:
        self.aiobrowser: Optional[AsyncServiceBrowser] = None
        self.aiozc: Optional[AsyncZeroconf] = None

    async def async_run(self, timeout: int, interfaces):
        self.aiozc = AsyncZeroconf(interfaces)

        notifier = Notifier()
        services = ['_remoted._tcp.local.']
        self.aiobrowser = AsyncServiceBrowser(
            self.aiozc.zeroconf, services, handlers=[notifier.async_on_service_state_change]
        )
        start = time.time()
        while time.time() - start < timeout:
            if notifier.addresses:
                return notifier.addresses
            await asyncio.sleep(.1)

    async def async_close(self) -> None:
        assert self.aiozc is not None
        assert self.aiobrowser is not None
        await self.aiobrowser.async_cancel()
        await self.aiozc.async_close()


def get_ncm_potential_addresses() -> List[str]:
    if sys.platform == 'win32':
        return [f'{adapter.ips[0].ip[0]}%{adapter.ips[0].ip[2]}' for adapter in get_adapters() if
                adapter.ips[0].is_IPv6]
    else:
        return [f'{adapter.ips[0].ip[0]}%{adapter.nice_name}' for adapter in get_adapters() if adapter.ips[0].is_IPv6]


async def async_get_remoted_addresses(timeout: int = DEFAULT_BONJOUR_TIMEOUT, ips: Optional[List[str]] = None) \
        -> List[str]:
    runner = AsyncRunner()
    addresses = await runner.async_run(timeout, get_ncm_potential_addresses() if ips is None else ips)
    await runner.async_close()
    return addresses


def get_remoted_addresses(timeout: int = DEFAULT_BONJOUR_TIMEOUT, ips: Optional[List[str]] = None) -> List[str]:
    return asyncio.get_event_loop().run_until_complete(async_get_remoted_addresses(timeout=timeout, ips=ips))
