import base64
import logging
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, Union

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remoted
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import (
    InvalidServiceError,
    NoDeviceConnectedError,
    PyMobileDevice3Exception,
    StartServiceError,
)
from pymobiledevice3.lockdown import LockdownClient, create_using_remote
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.pair_records import get_local_pairing_record, get_remote_pairing_record_filename
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.service_connection import ServiceConnection


@dataclass
class RSDDevice:
    hostname: str
    udid: str
    product_type: str
    os_version: str


# from remoted ([RSDRemoteNCMDeviceDevice createPortListener])
RSD_PORT = 58783


class RemoteServiceDiscoveryService(LockdownServiceProvider):
    def __init__(self, address: tuple[str, int], name: Optional[str] = None) -> None:
        super().__init__()
        self.name = name
        self.service = RemoteXPCConnection(address)
        self.peer_info: Optional[dict] = None
        self.lockdown: Optional[LockdownClient] = None
        self.all_values: Optional[dict] = None

    @property
    def product_version(self) -> str:
        return self.peer_info["Properties"]["OSVersion"]

    @property
    def product_build_version(self) -> str:
        return self.peer_info["Properties"]["BuildVersion"]

    @property
    def ecid(self) -> int:
        return self.peer_info["Properties"]["UniqueChipID"]

    async def get_developer_mode_status(self) -> bool:
        return await self.lockdown.get_developer_mode_status()

    async def get_date(self) -> datetime:
        return await self.lockdown.get_date()

    async def set_language(self, language: str) -> None:
        await self.lockdown.set_language(language)

    async def get_language(self) -> str:
        return await self.lockdown.get_language()

    async def set_locale(self, locale: str) -> None:
        await self.lockdown.set_locale(locale)

    async def get_locale(self) -> str:
        return await self.lockdown.get_locale()

    async def set_assistive_touch(self, value: bool) -> None:
        await self.lockdown.set_assistive_touch(value)

    async def get_assistive_touch(self) -> bool:
        return await self.lockdown.get_assistive_touch()

    async def set_voice_over(self, value: bool) -> None:
        await self.lockdown.set_voice_over(value)

    async def get_voice_over(self) -> bool:
        return await self.lockdown.get_voice_over()

    async def set_invert_display(self, value: bool) -> None:
        await self.lockdown.set_invert_display(value)

    async def get_invert_display(self) -> bool:
        return await self.lockdown.get_invert_display()

    async def set_enable_wifi_connections(self, value: bool) -> None:
        await self.lockdown.set_enable_wifi_connections(value)

    async def get_enable_wifi_connections(self) -> bool:
        return await self.lockdown.get_enable_wifi_connections()

    async def set_timezone(self, timezone: str) -> None:
        await self.lockdown.set_timezone(timezone)

    async def set_uses24h_clock(self, value: bool) -> None:
        await self.lockdown.set_uses24h_clock(value)

    async def connect(self) -> None:
        await self.service.connect()
        try:
            self.peer_info = await self.service.receive_response()
            self.udid = self.peer_info["Properties"]["UniqueDeviceID"]
            self.product_type = self.peer_info["Properties"]["ProductType"]

            # Attempt to initialize a lockdown connection (May fail if RemoteXPC device does not offer this service,
            # such as VirtualMac (virtual macOS instance)
            self.lockdown: Optional[LockdownServiceProvider] = None

            with suppress(InvalidServiceError):
                self.lockdown = await create_using_remote(
                    await self.start_lockdown_service("com.apple.mobile.lockdown.remote.trusted")
                )

            if self.lockdown is None:
                # Reattempt with the untrusted service variant
                with suppress(InvalidServiceError):
                    self.lockdown = await create_using_remote(
                        await self.start_lockdown_service("com.apple.mobile.lockdown.remote.untrusted")
                    )

            self.all_values = self.lockdown.all_values if self.lockdown is not None else {}
        except Exception:
            await self.close()
            raise

    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        return await self.lockdown.get_value(domain, key)

    async def set_value(self, value, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        return await self.lockdown.set_value(value, domain=domain, key=key)

    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        return await self.lockdown.remove_value(domain=domain, key=key)

    async def start_lockdown_service_without_checkin(self, name: str) -> ServiceConnection:
        return await self.create_service_connection(self.get_service_port(name))

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict:
        # RSD services are discovered from peer_info and do not require a separate StartService RPC.
        _ = include_escrow_bag
        return {"Port": self.get_service_port(name), "EnableServiceSSL": False}

    async def create_service_connection(self, port: int) -> ServiceConnection:
        return await ServiceConnection.create_using_tcp(self.service.address[0], port)

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        service = await self.start_lockdown_service_without_checkin(name)
        await service.start()
        try:
            checkin = {"Label": "pymobiledevice3", "ProtocolVersion": "2", "Request": "RSDCheckin"}
            if include_escrow_bag:
                pairing_record = get_local_pairing_record(
                    get_remote_pairing_record_filename(self.udid), get_home_folder()
                )
                checkin["EscrowBag"] = base64.b64decode(pairing_record["remote_unlock_host_key"])
            response = await service.send_recv_plist(checkin)
            if response["Request"] != "RSDCheckin":
                raise PyMobileDevice3Exception(f'Invalid response for RSDCheckIn: {response}. Expected "RSDCheckIn"')
            response = await service.recv_plist()
            if response["Request"] != "StartService":
                raise PyMobileDevice3Exception(
                    f'Invalid response for RSDCheckIn: {response}. Expected "ServiceService"'
                )
            error = response.get("Error")
            if error is not None:
                raise StartServiceError(name, error)
        except Exception:
            await service.close()
            raise
        return service

    async def start_lockdown_developer_service(self, name, include_escrow_bag: bool = False) -> ServiceConnection:
        try:
            return await self.start_lockdown_service_without_checkin(name)
        except StartServiceError:
            logging.getLogger(self.__module__).exception(
                "Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. "
                "You can do so using: pymobiledevice3 mounter mount"
            )
            raise

    def start_remote_service(self, name: str) -> RemoteXPCConnection:
        service = RemoteXPCConnection((self.service.address[0], self.get_service_port(name)))
        return service

    async def start_service(self, name: str) -> Union[RemoteXPCConnection, ServiceConnection]:
        service = self.peer_info["Services"][name]
        service_properties = service.get("Properties", {})
        use_remote_xpc = service_properties.get("UsesRemoteXPC", False)
        return self.start_remote_service(name) if use_remote_xpc else await self.start_lockdown_service(name)

    def get_service_port(self, name: str) -> int:
        """takes a service name and returns the port that service is running on if the service exists"""
        service = self.peer_info["Services"].get(name)
        if service is None:
            raise InvalidServiceError(f"No such service: {name}")
        return int(service["Port"])

    async def close(self) -> None:
        if self.lockdown is not None:
            await self.lockdown.close()
        await self.service.close()

    async def __aenter__(self) -> "RemoteServiceDiscoveryService":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    def __repr__(self) -> str:
        name_str = ""
        if self.name:
            name_str = f" NAME:{self.name}"
        return (
            f"<{self.__class__.__name__} PRODUCT:{self.product_type} VERSION:{self.product_version} "
            f"UDID:{self.udid}{name_str}>"
        )


async def get_remoted_devices(timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> list[RSDDevice]:
    result = []
    for instance in await browse_remoted(timeout):
        for address in instance.addresses:
            with RemoteServiceDiscoveryService((address.full_ip, RSD_PORT)) as rsd:
                properties = rsd.peer_info["Properties"]
                result.append(
                    RSDDevice(
                        hostname=address.full_ip,
                        udid=properties["UniqueDeviceID"],
                        product_type=properties["ProductType"],
                        os_version=properties["OSVersion"],
                    )
                )
    return result


async def get_remoted_device(udid: str, timeout: float = DEFAULT_BONJOUR_TIMEOUT) -> RSDDevice:
    devices = await get_remoted_devices(timeout=timeout)
    for device in devices:
        if device.udid == udid:
            return device
    raise NoDeviceConnectedError()
