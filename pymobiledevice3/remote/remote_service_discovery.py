from dataclasses import dataclass
from typing import List, Tuple

from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.remote.bonjour import DEFAULT_BONJOUR_TIMEOUT, get_remoted_addresses
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection


@dataclass
class RSDDevice:
    hostname: str
    udid: str
    product_type: str
    os_version: str


# from remoted ([RSDRemoteNCMDeviceDevice createPortListener])
RSD_PORT = 58783


class RemoteServiceDiscoveryService:
    def __init__(self, address: Tuple[str, int]):
        self.service = RemoteXPCConnection(address)
        self.peer_info = None

    def connect(self) -> None:
        self.service.connect()
        self.peer_info = self.service.receive_response()

    def connect_to_service(self, name: str) -> RemoteXPCConnection:
        service_port = int(self.peer_info['Services'][name]['Port'])
        service = RemoteXPCConnection((self.service.address[0], service_port))
        service.connect()
        return service

    def __enter__(self) -> 'RemoteServiceDiscoveryService':
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.service.close()


def get_remoted_devices(timeout: int = DEFAULT_BONJOUR_TIMEOUT) -> List[RSDDevice]:
    result = []
    for hostname in get_remoted_addresses(timeout):
        with RemoteServiceDiscoveryService((hostname, RSD_PORT)) as rsd:
            properties = rsd.peer_info['Properties']
            result.append(RSDDevice(hostname=hostname, udid=properties['UniqueDeviceID'],
                                    product_type=properties['ProductType'], os_version=properties['OSVersion']))
    return result


def get_remoted_device(udid: str, timeout: int = DEFAULT_BONJOUR_TIMEOUT) -> RSDDevice:
    devices = get_remoted_devices(timeout=timeout)
    for device in devices:
        if device.udid == udid:
            return device
    raise NoDeviceConnectedError()
