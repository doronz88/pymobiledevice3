import dataclasses
import logging
import socket
import time
from typing import List, Mapping

from zeroconf import InterfaceChoice, InterfacesType, IPVersion, ServiceBrowser, ServiceListener, Zeroconf

from pymobiledevice3.lockdown import LockdownClient, create_using_tcp

SERVICE_NAME = '_apple-mobdev2._tcp.local.'

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class BonjourDevice:
    name: str
    mac_address: str
    ipv4: List[str]
    ipv6: List[str]
    lockdown: LockdownClient

    def asdict(self) -> Mapping:
        return {
            'name': self.name,
            'mac_address': self.mac_address,
            'ipv4': self.ipv4,
            'ipv6': self.ipv6,
            'lockdown_info': self.lockdown.all_values
        }


class BonjourListener(ServiceListener):
    def __init__(self, pair_records: List[Mapping] = None):
        super().__init__()
        self.pair_records = [] if pair_records is None else pair_records
        self.discovered_devices = {}

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        logger.debug(f'Service {name} updated')

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        logger.debug(f'Service {name} removed')
        self.discovered_devices.pop(name)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        logger.debug(f'Service {name} added, service info: {info}')

        ipv4 = [socket.inet_ntop(socket.AF_INET, address) for address in info.addresses_by_version(IPVersion.V4Only)]
        ipv6 = [socket.inet_ntop(socket.AF_INET6, address) for address in info.addresses_by_version(IPVersion.V6Only)]

        try:
            lockdown = create_using_tcp(hostname=ipv4[0], autopair=False)

            for pair_record in self.pair_records:
                lockdown = create_using_tcp(hostname=ipv4[0], autopair=False, pair_record=pair_record)
                if lockdown.paired:
                    break
        except ConnectionRefusedError:
            logger.debug('Service failed to establish a lockdown connection')
            return

        self.discovered_devices[name] = BonjourDevice(name=name, mac_address=name.split('@')[0], ipv4=ipv4, ipv6=ipv6,
                                                      lockdown=lockdown)


def browse(timeout: int, interfaces: InterfacesType = InterfaceChoice.All, pair_records: List[Mapping] = None) -> \
        Mapping[str, BonjourDevice]:
    with Zeroconf(interfaces=interfaces) as zc:
        listener = BonjourListener(pair_records=pair_records)
        ServiceBrowser(zc, SERVICE_NAME, listener)
        time.sleep(timeout)
        return listener.discovered_devices
