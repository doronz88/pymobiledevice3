import base64
import logging
from dataclasses import dataclass
from typing import List, Mapping, Optional, Tuple, Union

from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import InvalidServiceError, NoDeviceConnectedError, PyMobileDevice3Exception, \
    StartServiceError
from pymobiledevice3.lockdown import LockdownClient, create_using_remote
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.pair_records import get_local_pairing_record, get_remote_pairing_record_filename
from pymobiledevice3.remote.bonjour import DEFAULT_BONJOUR_TIMEOUT, get_remoted_addresses
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.service_connection import LockdownServiceConnection


@dataclass
class RSDDevice:
    hostname: str
    udid: str
    product_type: str
    os_version: str


# from remoted ([RSDRemoteNCMDeviceDevice createPortListener])
RSD_PORT = 58783


class RemoteServiceDiscoveryService(LockdownServiceProvider):
    def __init__(self, address: Tuple[str, int]):
        super().__init__()
        self.service = RemoteXPCConnection(address)
        self.peer_info: Optional[Mapping] = None
        self.lockdown: Optional[LockdownClient] = None
        self.all_values: Optional[Mapping] = None

    @property
    def product_version(self) -> str:
        return self.peer_info['Properties']['OSVersion']

    @property
    def ecid(self) -> int:
        return self.peer_info['Properties']['UniqueChipID']

    @property
    def developer_mode_status(self) -> bool:
        return self.lockdown.developer_mode_status

    def connect(self) -> None:
        self.service.connect()
        self.peer_info = self.service.receive_response()
        self.udid = self.peer_info['Properties']['UniqueDeviceID']
        self.product_type = self.peer_info['Properties']['ProductType']
        try:
            self.lockdown = create_using_remote(self.start_lockdown_service('com.apple.mobile.lockdown.remote.trusted'))
        except InvalidServiceError:
            self.lockdown = create_using_remote(
                self.start_lockdown_service('com.apple.mobile.lockdown.remote.untrusted'))
        self.all_values = self.lockdown.all_values

    def get_value(self, domain: str = None, key: str = None):
        return self.lockdown.get_value(domain, key)

    def start_lockdown_service_without_checkin(self, name: str) -> LockdownServiceConnection:
        return LockdownServiceConnection.create_using_tcp(self.service.address[0], self.get_service_port(name))

    def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> LockdownServiceConnection:
        service = self.start_lockdown_service_without_checkin(name)
        checkin = {'Label': 'pymobiledevice3', 'ProtocolVersion': '2', 'Request': 'RSDCheckin'}
        if include_escrow_bag:
            pairing_record = get_local_pairing_record(get_remote_pairing_record_filename(self.udid), get_home_folder())
            checkin['EscrowBag'] = base64.b64decode(pairing_record['remote_unlock_host_key'])
        response = service.send_recv_plist(checkin)
        if response['Request'] != 'RSDCheckin':
            raise PyMobileDevice3Exception(f'Invalid response for RSDCheckIn: {response}. Expected "RSDCheckIn"')
        response = service.recv_plist()
        if response['Request'] != 'StartService':
            raise PyMobileDevice3Exception(f'Invalid response for RSDCheckIn: {response}. Expected "ServiceService"')
        return service

    async def aio_start_lockdown_service(
            self, name: str, include_escrow_bag: bool = False) -> LockdownServiceConnection:
        service = self.start_lockdown_service(name, include_escrow_bag=include_escrow_bag)
        await service.aio_start()
        return service

    def start_lockdown_developer_service(self, name, include_escrow_bag: bool = False) -> LockdownServiceConnection:
        try:
            return self.start_lockdown_service_without_checkin(name)
        except StartServiceError:
            logging.getLogger(self.__module__).error(
                'Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. '
                'You can do so using: pymobiledevice3 mounter mount'
            )
            raise

    def start_remote_service(self, name: str) -> RemoteXPCConnection:
        service = RemoteXPCConnection((self.service.address[0], self.get_service_port(name)))
        return service

    def start_service(self, name: str) -> Union[RemoteXPCConnection, LockdownServiceConnection]:
        service = self.peer_info['Services'][name]
        service_properties = service.get('Properties', {})
        use_remote_xpc = service_properties.get('UsesRemoteXPC', False)
        return self.start_remote_service(name) if use_remote_xpc else self.start_lockdown_service(name)

    def get_service_port(self, name: str) -> int:
        """takes a service name and returns the port that service is running on if the service exists"""
        service = self.peer_info['Services'].get(name)
        if service is None:
            raise InvalidServiceError(f'No such service: {name}')
        return int(service['Port'])

    def close(self) -> None:
        self.service.close()
        if self.lockdown is not None:
            self.lockdown.close()

    def __enter__(self) -> 'RemoteServiceDiscoveryService':
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return (f'<{self.__class__.__name__} PRODUCT:{self.product_type} VERSION:{self.product_version} '
                f'UDID:{self.udid}>')


def get_remoted_devices(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> List[RSDDevice]:
    result = []
    for hostname in get_remoted_addresses(timeout):
        with RemoteServiceDiscoveryService((hostname, RSD_PORT)) as rsd:
            properties = rsd.peer_info['Properties']
            result.append(RSDDevice(hostname=hostname, udid=properties['UniqueDeviceID'],
                                    product_type=properties['ProductType'], os_version=properties['OSVersion']))
    return result


def get_remoted_device(udid: str, timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> RSDDevice:
    devices = get_remoted_devices(timeout=timeout)
    for device in devices:
        if device.udid == udid:
            return device
    raise NoDeviceConnectedError()
