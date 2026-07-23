# pyright: reportMissingTypeArgument=error
import base64
import logging
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional, Union, cast

from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_remoted
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import (
    InvalidServiceError,
    NoDeviceConnectedError,
    NotConnectedError,
    NotPairedError,
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
    """
    Service provider for the iOS 17+ RemoteServiceDiscovery (RSD) endpoint exposed over a tunnel.

    On modern devices, services are no longer started through lockdownd's StartService RPC.
    Instead a RemoteXPC handshake against the RSD port yields ``peer_info`` describing every
    available service and the TCP port it listens on. This class connects to that endpoint,
    discovers those services, and acts as a
    `LockdownServiceProvider`, letting callers
    open both RemoteXPC and lockdown-style service connections.

    The RSD address is only reachable over an active tunnel (a kernel-routable interface or an
    in-process userspace tunnel; see `is_in_process_tunnel`). Instances may be used as async
    context managers, which connect on entry and close on exit.

    :ivar service: the underlying RemoteXPC connection to the RSD endpoint.
    :ivar peer_info: handshake response describing device properties and available services;
        populated by `connect`.
    :ivar lockdown: lockdown client created over the remote endpoint, or ``None`` if the device
        does not offer the remote lockdown service (e.g. a virtual macOS instance).
    """

    def __init__(
        self, address: tuple[str, int], name: Optional[str] = None, open_connection: Optional[Callable[..., Any]] = None
    ) -> None:
        """
        :param address: ``(host, port)`` of the RSD endpoint to connect to.
        :param name: optional human-readable name for this RSD (e.g. the tunnel interface name).
        :param open_connection: optional ``asyncio.open_connection``-compatible dialer used for the
            RemoteXPC handshake and every service connection opened through this RSD. ``None`` uses
            the stdlib dialer; the userspace tunnel injects a relay dialer so device-bound
            connections route through its in-process stack.
        """
        super().__init__()
        self.name = name
        # ``asyncio.open_connection``-compatible dialer used for the RemoteXPC handshake and every
        # service connection opened through this RSD (read by callers such as FileServiceService).
        # ``None`` => stdlib ``asyncio.open_connection``; the userspace tunnel injects a relay dialer
        # so device-bound connections route through its in-process stack without a global monkeypatch.
        self.open_connection = open_connection
        self.service = RemoteXPCConnection(address, open_connection=open_connection)
        self.peer_info: Optional[dict[str, Any]] = None
        self.lockdown: Optional[LockdownClient] = None
        self.all_values: dict[str, Any] = {}

    @property
    def is_in_process_tunnel(self) -> bool:
        """True when this RSD reaches the device through an in-process dialer (the userspace
        tunnel) rather than a kernel-routable interface. The device address (``self.service.address``)
        is then only reachable from THIS process, so it must not be handed to external tools such as
        lldb as a connect endpoint."""
        return self.open_connection is not None

    def _require_peer_info(self) -> dict[str, Any]:
        """Return the handshake ``peer_info``, raising if the RSD has not been connected yet."""
        if self.peer_info is None:
            raise NotConnectedError("RSD is not connected; call connect() first")
        return self.peer_info

    @property
    def product_version(self) -> str:
        """Device OS version, taken from the RSD handshake ``peer_info`` (``"1.0"`` if absent).

        Tolerates a missing ``OSVersion`` (mirrors ``LockdownClient.product_version``) so building an
        ``InvalidServiceError`` never raises ``KeyError`` on the ``suppress(InvalidServiceError)``
        checkin path (e.g. a device that offers no lockdown service, such as a VirtualMac)."""
        return self._require_peer_info()["Properties"].get("OSVersion") or "1.0"

    @property
    def product_build_version(self) -> str:
        """Device OS build string, taken from the RSD handshake ``peer_info``."""
        return self._require_peer_info()["Properties"]["BuildVersion"]

    @property
    def ecid(self) -> int:
        """Device ECID (unique chip identifier), taken from the RSD handshake ``peer_info``."""
        return self._require_peer_info()["Properties"]["UniqueChipID"]

    @property
    def _lockdown(self) -> LockdownClient:
        """Return the remote lockdown client, raising if the device offers no lockdown service."""
        if self.lockdown is None:
            raise InvalidServiceError("device does not offer a lockdown service", self.udid, self.product_version)
        return self.lockdown

    async def get_developer_mode_status(self) -> bool:
        return await self._lockdown.get_developer_mode_status()

    async def get_date(self) -> datetime:
        return await self._lockdown.get_date()

    async def set_language(self, language: str) -> None:
        await self._lockdown.set_language(language)

    async def get_language(self) -> str:
        return await self._lockdown.get_language()

    async def set_locale(self, locale: str) -> None:
        await self._lockdown.set_locale(locale)

    async def get_locale(self) -> str:
        return await self._lockdown.get_locale()

    async def set_assistive_touch(self, value: bool) -> None:
        await self._lockdown.set_assistive_touch(value)

    async def get_assistive_touch(self) -> bool:
        return await self._lockdown.get_assistive_touch()

    async def set_voice_over(self, value: bool) -> None:
        await self._lockdown.set_voice_over(value)

    async def get_voice_over(self) -> bool:
        return await self._lockdown.get_voice_over()

    async def set_invert_display(self, value: bool) -> None:
        await self._lockdown.set_invert_display(value)

    async def get_invert_display(self) -> bool:
        return await self._lockdown.get_invert_display()

    async def set_enable_wifi_connections(self, value: bool) -> None:
        await self._lockdown.set_enable_wifi_connections(value)

    async def get_enable_wifi_connections(self) -> bool:
        return await self._lockdown.get_enable_wifi_connections()

    async def set_timezone(self, timezone: str) -> None:
        await self._lockdown.set_timezone(timezone)

    async def set_uses24h_clock(self, value: bool) -> None:
        await self._lockdown.set_uses24h_clock(value)

    async def connect(self) -> None:
        """
        Connect to the RSD endpoint and perform the RemoteXPC handshake.

        Populates ``peer_info``, `udid`, and `product_type` from the handshake, then
        attempts to open a remote lockdown connection (preferring the trusted variant, falling back
        to the untrusted one). If neither is available the device is treated as offering no lockdown
        service and `lockdown` is left ``None``. On any failure the connection is closed.

        :raises Exception: re-raises after closing if the handshake or connection fails.
        """
        await self.service.connect()
        try:
            await self.service.send_device_handshake()
            self.peer_info = await self.service.receive_response()
            self.udid = self.peer_info["Properties"]["UniqueDeviceID"]
            self.product_type = self.peer_info["Properties"]["ProductType"]

            # Attempt to initialize a lockdown connection (May fail if RemoteXPC device does not offer this service,
            # such as VirtualMac (virtual macOS instance)
            self.lockdown = None

            with suppress(InvalidServiceError):
                self.lockdown = await create_using_remote(
                    await self.start_lockdown_service("com.apple.mobile.lockdown.remote.trusted"),
                    identifier=self.udid,
                )

            if self.lockdown is None:
                # Reattempt with the untrusted service variant
                with suppress(InvalidServiceError):
                    self.lockdown = await create_using_remote(
                        await self.start_lockdown_service("com.apple.mobile.lockdown.remote.untrusted"),
                        identifier=self.udid,
                    )

            self.all_values = self.lockdown.all_values if self.lockdown is not None else {}
        except Exception:
            await self.close()
            raise

    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        return await self._lockdown.get_value(domain, key)

    async def set_value(self, value, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        return await self._lockdown.set_value(value, domain=domain, key=key)

    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        return await self._lockdown.remove_value(domain=domain, key=key)

    async def start_lockdown_service_without_checkin(self, name: str) -> ServiceConnection:
        """
        Open a raw connection to a service's port without performing the RSD check-in handshake.

        :param name: name of the service to connect to.
        :returns: an unstarted connection to the service's port.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        return await self.create_service_connection(self.get_service_port(name))

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
        """
        Return the connection attributes for a service.

        Unlike lockdownd, RSD services are discovered from ``peer_info`` and need no StartService
        RPC, so this resolves the port locally and reports SSL as disabled.

        :param name: name of the service.
        :param include_escrow_bag: accepted for interface compatibility; ignored.
        :returns: a dict with the service ``Port`` and ``EnableServiceSSL`` set to ``False``.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        # RSD services are discovered from peer_info and do not require a separate StartService RPC.
        _ = include_escrow_bag
        return {"Port": self.get_service_port(name), "EnableServiceSSL": False}

    async def create_service_connection(self, port: int) -> ServiceConnection:
        """
        Create a TCP service connection to a port on the device through this RSD.

        :param port: device-side TCP port to connect to.
        :returns: a connection routed through this RSD's dialer.
        """
        return await ServiceConnection.create_using_tcp(
            self.service.address[0], port, open_connection=self.open_connection
        )

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """
        Open a service connection and complete the RSD check-in handshake.

        Connects to the service port, performs the ``RSDCheckin`` exchange (optionally attaching the
        host escrow bag for unlock), and returns the started connection.

        :param name: name of the service to start.
        :param include_escrow_bag: when True, attach the local pairing record's escrow bag to the
            check-in, allowing the connection to unlock the device.
        :returns: a started, checked-in service connection.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        :raises StartServiceError: if the device reports an error starting the service.
        :raises PyMobileDevice3Exception: if the check-in handshake returns an unexpected response.
        """
        service = await self.start_lockdown_service_without_checkin(name)
        await service.start()
        try:
            checkin: dict[str, Any] = {"Label": "pymobiledevice3", "ProtocolVersion": "2", "Request": "RSDCheckin"}
            if include_escrow_bag:
                if self.udid is None:
                    raise NotConnectedError("RSD is not connected; call connect() first")
                pairing_record = get_local_pairing_record(
                    get_remote_pairing_record_filename(self.udid), get_home_folder()
                )
                if pairing_record is None:
                    raise NotPairedError(f"no local pairing record found for {self.udid}")
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
                raise StartServiceError(name, cast(str, error))
        except Exception:
            await service.close()
            raise
        return service

    async def start_lockdown_developer_service(self, name, include_escrow_bag: bool = False) -> ServiceConnection:
        """
        Open a connection to a developer service (without RSD check-in).

        :param name: name of the developer service.
        :param include_escrow_bag: accepted for interface compatibility; ignored.
        :returns: an unstarted connection to the service's port.
        :raises StartServiceError: if the service cannot be reached; logs a hint that the
            DeveloperDiskImage may need to be mounted.
        """
        try:
            return await self.start_lockdown_service_without_checkin(name)
        except StartServiceError:
            logging.getLogger(self.__module__).exception(
                "Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. "
                "You can do so using: pymobiledevice3 mounter mount"
            )
            raise

    def start_remote_service(self, name: str) -> RemoteXPCConnection:
        """
        Create (but do not connect) a RemoteXPC connection to a service.

        :param name: name of the service.
        :returns: an unconnected RemoteXPC connection to the service's port.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        service = RemoteXPCConnection(
            (self.service.address[0], self.get_service_port(name)), open_connection=self.open_connection
        )
        return service

    async def start_service(self, name: str) -> Union[RemoteXPCConnection, ServiceConnection]:
        """
        Start a service using the transport it advertises in ``peer_info``.

        Services flagged with ``UsesRemoteXPC`` are opened as RemoteXPC connections via
        `start_remote_service`; all others are opened as lockdown-style connections via
        `start_lockdown_service`.

        :param name: name of the service to start.
        :returns: a RemoteXPC connection or a started lockdown service connection, per the
            service's advertised transport.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        service = self._require_peer_info()["Services"][name]
        service_properties = service.get("Properties", {})
        use_remote_xpc = service_properties.get("UsesRemoteXPC", False)
        return self.start_remote_service(name) if use_remote_xpc else await self.start_lockdown_service(name)

    def get_service_port(self, name: str) -> int:
        """
        Resolve the TCP port a service listens on from the RSD handshake ``peer_info``.

        :param name: name of the service.
        :returns: the device-side TCP port for the service.
        :raises InvalidServiceError: if the device does not offer a service with this name.
        """
        service = self._require_peer_info()["Services"].get(name)
        if service is None:
            raise InvalidServiceError(f"No such service: {name}", self.udid, self.product_version)
        return int(service["Port"])

    async def close(self) -> None:
        """Close the lockdown client (if any) and the underlying RemoteXPC connection."""
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
    """
    Discover RSD-capable devices advertised by ``remoted`` over Bonjour.

    :param timeout: Bonjour browse timeout, in seconds.
    :returns: a list of `RSDDevice` records, one per discovered device address.
    """
    result = []
    for instance in await browse_remoted(timeout):
        for address in instance.addresses:
            async with RemoteServiceDiscoveryService((address.full_ip, RSD_PORT)) as rsd:
                properties = rsd._require_peer_info()["Properties"]
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
    """
    Discover a single RSD-capable device by UDID.

    :param udid: UDID of the device to find.
    :param timeout: Bonjour browse timeout, in seconds.
    :returns: the matching `RSDDevice`.
    :raises NoDeviceConnectedError: if no advertised device matches the UDID.
    """
    devices = await get_remoted_devices(timeout=timeout)
    for device in devices:
        if device.udid == udid:
            return device
    raise NoDeviceConnectedError()
