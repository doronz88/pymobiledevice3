import asyncio
import datetime
import logging
import os
import plistlib
import socket
import tempfile
import time
from abc import ABC, abstractmethod
from asyncio import IncompleteReadError
from collections.abc import AsyncIterable, Generator
from contextlib import contextmanager, suppress
from enum import Enum
from pathlib import Path
from ssl import SSLZeroReturnError, TLSVersion
from typing import Any, Optional, overload

from construct import StreamError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7Options, PKCS7SignatureBuilder
from packaging.version import Version
from typing_extensions import Self

from pymobiledevice3 import usbmux
from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_mobdev2
from pymobiledevice3.ca import generate_pairing_cert_chain
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import (
    BadDevError,
    CannotStopSessionError,
    ConnectionFailedError,
    ConnectionTerminatedError,
    DeviceNotFoundError,
    FatalPairingError,
    GetProhibitedError,
    IncorrectModeError,
    InvalidConnectionError,
    InvalidHostIDError,
    InvalidServiceError,
    LockdownError,
    MissingValueError,
    MuxException,
    NoDeviceConnectedError,
    NotPairedError,
    PairingDialogResponsePendingError,
    PairingError,
    PasswordRequiredError,
    SetProhibitedError,
    StartServiceError,
    UserDeniedPairingError,
)
from pymobiledevice3.irecv_devices import IRECV_DEVICES
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.pair_records import (
    create_pairing_records_cache_folder,
    generate_host_id,
    get_preferred_pair_record,
)
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.usbmux import PlistMuxConnection

OSUTIL = get_os_utils()
SYSTEM_BUID = "30142955-444094379208051516"
RESTORED_SERVICE_TYPE = "com.apple.mobile.restored"

DEFAULT_LABEL = "pymobiledevice3"
SERVICE_PORT = 62078

RECONNECT_RETRY_INTERVAL_SECONDS = 1


class DeviceClass(Enum):
    IPHONE = "iPhone"
    IPAD = "iPad"
    IPOD = "iPod"
    WATCH = "Watch"
    APPLE_TV = "AppleTV"
    VISION_PRO = "RealityDevice"
    UNKNOWN = "Unknown"


class LockdownClient(ABC, LockdownServiceProvider):
    """Client for the device's lockdownd daemon.

    lockdownd is the entry-point daemon on an iOS device: it reports device values, manages host pairing,
    and starts the other on-device services. This abstract base implements the lockdown protocol (querying
    and setting values, pairing, session establishment with optional SSL, and starting named services);
    concrete subclasses supply the transport-specific way to open a connection by overriding
    `create_service_connection`.

    Do not instantiate directly. Obtain an instance from a ``create_using_*`` factory
    (`create_using_usbmux`, `create_using_tcp`, `create_using_remote`) or from the
    `create` classmethod. Instances are async context managers; on exit the underlying connection
    is closed.
    """

    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict[str, Any]] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
    ):
        """Initialize a new LockdownClient instance.

        This is an abstract base class. Instances are normally not constructed directly; use one of the
        ``create_using_*`` factory functions (e.g. `create_using_usbmux`) or the `create`
        classmethod, which build the underlying service connection, initialize device values and optionally
        pair before returning a ready-to-use client.

        :param service: An already-established lockdownd connection used to send/receive plist requests.
        :param host_id: The HostID identifying this host to the device during pairing/session establishment.
        :param identifier: Device identifier (typically its UDID) used to locate the matching pair record on
            the host. ``None`` if unknown.
        :param label: User-agent label included in every request sent to lockdownd.
        :param system_buid: The host's SystemBUID, included when starting a session.
        :param pair_record: A pre-loaded pair record to use instead of looking one up on the host.
        :param pairing_records_cache_folder: Directory used to search for and persist pair records.
        :param port: TCP port of the lockdownd service on the device.
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.service = service
        self.identifier = identifier
        self.label = label
        self.host_id = host_id
        self.system_buid = system_buid
        self.pair_record = pair_record
        self.paired = False
        self.session_id = None
        self.pairing_records_cache_folder = pairing_records_cache_folder
        self.port = port

        self.all_values = {}
        self.udid = None
        self.unique_chip_id: Optional[int] = None
        self.device_public_key: Optional[bytes] = None
        self.product_type = None

    @classmethod
    async def create(
        cls,
        service: ServiceConnection,
        identifier: Optional[str] = None,
        system_buid: str = SYSTEM_BUID,
        label: str = DEFAULT_LABEL,
        autopair: bool = True,
        pair_timeout: Optional[float] = None,
        local_hostname: Optional[str] = None,
        pair_record: Optional[dict[str, Any]] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
        private_key: Optional[RSAPrivateKey] = None,
        **cls_specific_args,
    ):
        """Build a client around an existing service connection, initialize it and optionally pair.

        Generates a HostID, resolves the pairing-records cache folder, constructs the client, queries the
        device's values, and (when ``autopair`` is set) validates an existing pairing or performs a new one.

        :param service: An already-established lockdownd connection.
        :param identifier: Device identifier (typically its UDID) used to locate the matching pair record.
        :param system_buid: The host's SystemBUID, included when starting a session.
        :param label: User-agent label included in every request sent to lockdownd.
        :param autopair: When True, pair with the device (blocking) if it is not already paired.
        :param pair_timeout: Maximum time in seconds to wait for the user to accept the pairing dialog. A
            value of 0 fails immediately if the dialog is pending; ``None`` waits indefinitely.
        :param local_hostname: Seed used to generate the HostID.
        :param pair_record: A pre-loaded pair record to use instead of looking one up on the host.
        :param pairing_records_cache_folder: Directory used to search for and persist pair records.
        :param port: TCP port of the lockdownd service on the device.
        :param private_key: RSA private key to use when generating the pairing certificate chain; a new key
            is generated if omitted.
        :param cls_specific_args: Extra keyword arguments forwarded to the concrete client's constructor.
        :returns: A connected, initialized client instance.
        :raises IncorrectModeError: The connected daemon is not lockdownd.
        :raises FatalPairingError: Pairing succeeded but the subsequent validation failed.
        """
        host_id = generate_host_id(local_hostname)
        pairing_records_cache_folder = create_pairing_records_cache_folder(pairing_records_cache_folder)

        lockdown_client = cls(
            service,
            host_id=host_id,
            identifier=identifier,
            label=label,
            system_buid=system_buid,
            pair_record=pair_record,
            pairing_records_cache_folder=pairing_records_cache_folder,
            port=port,
            **cls_specific_args,
        )
        await lockdown_client._initialize()
        await lockdown_client._handle_autopair(autopair, pair_timeout, private_key=private_key)
        return lockdown_client

    async def _initialize(self) -> None:
        """
        Asynchronously initializes the object by performing a series of queries and assignments
        to set key device-related attributes. This function ensures that the operation mode is
        correct before retrieving and assigning values such as the unique device identifier,
        chip ID, public key, and product type.

        :param self: The instance of the class in which this method is executed.
        :raises IncorrectModeError: If the queried type does not match "com.apple.mobile.lockdown".

        :return: None
        """
        if (await self.query_type()) != "com.apple.mobile.lockdown":
            raise IncorrectModeError()
        self.all_values = await self.get_value()
        self.udid = self.all_values.get("UniqueDeviceID")
        self.unique_chip_id = self.all_values.get("UniqueChipID")
        self.device_public_key = self.all_values.get("DevicePublicKey")
        self.product_type = self.all_values.get("ProductType")

    def __repr__(self) -> str:
        """
        Provides a string representation of the object instance for debugging and logging
        purposes. This method returns relevant details about the instance to assist in
        understanding its current state.

        :return: A formatted string containing the class name and specific attribute values
        """
        return (
            f"<{self.__class__.__name__} ID:{self.identifier} VERSION:{self.product_version} "
            f"TYPE:{self.product_type} PAIRED:{self.paired}>"
        )

    async def __aenter__(self) -> Self:
        """Enter the async context manager and return this client.

        :return: Result of the operation.
        """
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the async context manager and close open resources.

        :param exc_type: Exc type.
        :param exc_val: Exc val.
        :param exc_tb: Exc tb.

        :return: None.
        """
        await self.close()

    @property
    def product_version(self) -> str:
        """The device's iOS/OS version (``ProductVersion``), e.g. ``"17.0"``.

        :returns: The product version, or ``"1.0"`` when the device did not report one.
        """
        return self.all_values.get("ProductVersion") or "1.0"

    @property
    def product_build_version(self) -> Optional[str]:
        """The device's OS build version (``BuildVersion``), e.g. ``"21A329"``.

        :returns: The build version, or ``None`` when the device did not report one.
        """
        return self.all_values.get("BuildVersion")

    @property
    def device_class(self) -> DeviceClass:
        """The device family (iPhone, iPad, Watch, ...) derived from the reported ``DeviceClass`` value.

        :returns: The matching `DeviceClass`, or `UNKNOWN` when the reported value
            is unrecognized.
        """
        try:
            return DeviceClass(self.all_values.get("DeviceClass"))
        except ValueError:
            return DeviceClass("Unknown")

    @property
    def wifi_mac_address(self) -> Optional[str]:
        """The device's Wi-Fi MAC address (``WiFiAddress``).

        :returns: The Wi-Fi MAC address, or ``None`` when the device did not report one.
        """
        return self.all_values.get("WiFiAddress")

    @property
    def short_info(self) -> dict[str, Any]:
        """A compact subset of the device's values, suitable for listing devices.

        :returns: A dict containing ``Identifier`` plus ``DeviceClass``, ``DeviceName``, ``BuildVersion``,
            ``ProductVersion``, ``ProductType`` and ``UniqueDeviceID`` (each ``None`` if not reported).
        """
        keys_to_copy = ["DeviceClass", "DeviceName", "BuildVersion", "ProductVersion", "ProductType", "UniqueDeviceID"]
        result = {
            "Identifier": self.identifier,
        }
        for key in keys_to_copy:
            result[key] = self.all_values.get(key)
        return result

    @property
    def ecid(self) -> int:
        """The device's ECID (unique chip identifier), taken from the reported ``UniqueChipID`` value.

        :returns: The ECID as an integer.
        :raises KeyError: The device did not report a ``UniqueChipID``.
        """
        return self.all_values["UniqueChipID"]

    @property
    def preflight_info(self) -> Optional[dict[str, Any]]:
        """The device's ``PreflightInfo`` value.

        :returns: The preflight info dict, or ``None`` when the device did not report one.
        """
        return self.all_values.get("PreflightInfo")

    @property
    def firmware_preflight_info(self) -> Optional[dict[str, Any]]:
        """The device's ``FirmwarePreflightInfo`` value.

        :returns: The firmware preflight info dict, or ``None`` when the device did not report one.
        """
        return self.all_values.get("FirmwarePreflightInfo")

    @property
    def display_name(self) -> Optional[str]:
        """The human-readable marketing name for the device, resolved from its product type.

        Looks the device's ``ProductType`` up in the built-in device table.

        :returns: The display name, or ``None`` when the product type is not in the table.
        """
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.display_name
        return None

    @property
    def hardware_model(self) -> Optional[str]:
        """The hardware model (e.g. board identifier) for the device, resolved from its product type.

        Looks the device's ``ProductType`` up in the built-in device table.

        :returns: The hardware model, or ``None`` when the product type is not in the table.
        """
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.hardware_model
        return None

    @property
    def board_id(self) -> Optional[int]:
        """The board ID for the device, resolved from its product type.

        Looks the device's ``ProductType`` up in the built-in device table.

        :returns: The board ID, or ``None`` when the product type is not in the table.
        """
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.board_id
        return None

    @property
    def chip_id(self) -> Optional[int]:
        """The chip ID for the device, resolved from its product type.

        Looks the device's ``ProductType`` up in the built-in device table.

        :returns: The chip ID, or ``None`` when the product type is not in the table.
        """
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.chip_id
        return None

    async def query_type(self) -> str:
        """Query the type of the daemon at the other end of the connection.

        Sends a ``QueryType`` request; for a real lockdownd connection this returns
        ``"com.apple.mobile.lockdown"``.

        :returns: The reported daemon type string.
        """
        return (await self._request("QueryType")).get("Type", "")

    async def set_language(self, language: str) -> None:
        """Set the device's language (``Language`` key in the ``com.apple.international`` domain).

        :param language: The language code to set (e.g. ``"en"``).
        """
        await self.set_value(language, key="Language", domain="com.apple.international")

    async def get_language(self) -> str:
        """Get the device's language (``Language`` key in the ``com.apple.international`` domain).

        :returns: The language code, or an empty string when the value is missing or not a string.
        """
        value = await self.get_value(domain="com.apple.international", key="Language")
        return value if isinstance(value, str) else ""

    async def set_locale(self, locale: str) -> None:
        """Set the device's locale (``Locale`` key in the ``com.apple.international`` domain).

        :param locale: The locale string to set (e.g. ``"en_US"``).
        """
        await self.set_value(locale, key="Locale", domain="com.apple.international")

    async def get_locale(self) -> str:
        """Get the device's locale (``Locale`` key in the ``com.apple.international`` domain).

        :returns: The locale string, or an empty string when the value is missing or not a string.
        """
        value = await self.get_value(domain="com.apple.international", key="Locale")
        return value if isinstance(value, str) else ""

    async def set_timezone(self, timezone: str) -> None:
        """Set the device's time zone (``TimeZone`` key, default domain).

        :param timezone: The time zone identifier to set (e.g. ``"America/New_York"``).
        """
        await self.set_value(timezone, key="TimeZone")

    async def set_uses24h_clock(self, value: bool) -> None:
        """Set whether the device uses the 24-hour clock format (``Uses24HourClock`` key, default domain).

        :param value: True for 24-hour format, False for 12-hour format.
        """
        await self.set_value(value, key="Uses24HourClock")

    async def set_uses24hClock(self, value: bool) -> None:
        """Alias of `set_uses24h_clock`.

        :param value: True for 24-hour format, False for 12-hour format.
        """
        await self.set_uses24h_clock(value)

    async def set_assistive_touch(self, value: bool) -> None:
        """Enable or disable AssistiveTouch (``AssistiveTouchEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :param value: True to enable AssistiveTouch, False to disable it.
        """
        await self.set_value(int(value), "com.apple.Accessibility", "AssistiveTouchEnabledByiTunes")

    async def get_assistive_touch(self) -> bool:
        """Get whether AssistiveTouch is enabled (``AssistiveTouchEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :returns: True if AssistiveTouch is enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="AssistiveTouchEnabledByiTunes")
        return bool(value)

    async def set_voice_over(self, value: bool) -> None:
        """Enable or disable VoiceOver (``VoiceOverTouchEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :param value: True to enable VoiceOver, False to disable it.
        """
        await self.set_value(int(value), "com.apple.Accessibility", "VoiceOverTouchEnabledByiTunes")

    async def get_voice_over(self) -> bool:
        """Get whether VoiceOver is enabled (``VoiceOverTouchEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :returns: True if VoiceOver is enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="VoiceOverTouchEnabledByiTunes")
        return bool(value)

    async def set_invert_display(self, value: bool) -> None:
        """Enable or disable display color inversion (``InvertDisplayEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :param value: True to enable display inversion, False to disable it.
        """
        await self.set_value(int(value), "com.apple.Accessibility", "InvertDisplayEnabledByiTunes")

    async def get_invert_display(self) -> bool:
        """Get whether display color inversion is enabled (``InvertDisplayEnabledByiTunes`` key in the
        ``com.apple.Accessibility`` domain).

        :returns: True if display inversion is enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="InvertDisplayEnabledByiTunes")
        return bool(value)

    async def set_enable_wifi_connections(self, value: bool) -> None:
        """Enable or disable Wi-Fi (wireless) lockdown connections to the device
        (``EnableWifiConnections`` key in the ``com.apple.mobile.wireless_lockdown`` domain).

        :param value: True to allow connecting to the device over Wi-Fi, False to disallow it.
        """
        await self.set_value(value, "com.apple.mobile.wireless_lockdown", "EnableWifiConnections")

    async def get_enable_wifi_connections(self) -> bool:
        """Get whether Wi-Fi (wireless) lockdown connections are enabled (``EnableWifiConnections`` key in the
        ``com.apple.mobile.wireless_lockdown`` domain).

        :returns: True if Wi-Fi connections are enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.mobile.wireless_lockdown", key="EnableWifiConnections")
        return bool(value)

    async def get_developer_mode_status(self) -> bool:
        """Get whether Developer Mode is enabled on the device (``DeveloperModeStatus`` key in the
        ``com.apple.security.mac.amfi`` domain).

        :returns: True if Developer Mode is enabled, False otherwise.
        """
        value = await self.get_value(domain="com.apple.security.mac.amfi", key="DeveloperModeStatus")
        return bool(value)

    async def get_date(self) -> datetime.datetime:
        """Get the device's current date and time.

        Reads the device's ``TimeIntervalSince1970`` value and converts it to a local
        `datetime`. Falls back to the Unix epoch when the value is missing.

        :returns: The device's current date and time.
        """
        timestamp = await self.get_value(key="TimeIntervalSince1970")
        return datetime.datetime.fromtimestamp(timestamp or 0)

    async def enter_recovery(self):
        """Request that the device reboot into recovery mode.

        Sends an ``EnterRecovery`` request to lockdownd.

        :returns: The lockdownd response to the request.
        """
        return await self._request("EnterRecovery")

    async def stop_session(self) -> dict[str, Any]:
        """Stop the current lockdownd session.

        Sends a ``StopSession`` request for the active session and clears the local session id.

        :returns: The lockdownd response to the request.
        :raises CannotStopSessionError: There is no active session, or lockdownd did not report success.
        """
        if self.session_id and self.service:
            response = await self._request("StopSession", {"SessionID": self.session_id})
            self.session_id = None
            if not response or response.get("Result") != "Success":
                raise CannotStopSessionError()
            return response
        raise CannotStopSessionError("No active session")

    async def validate_pairing(self) -> bool:
        """Validate the existing pairing and establish a session with the device.

        Loads a pair record if one is not already set, validates it (using the legacy ``ValidatePair``
        request for devices older than iOS 7), starts a session and, when the device requests it, upgrades
        the connection to SSL. On success, marks the client paired and reloads the device's values. If the
        pair record turns out to be missing or rejected on-device, the connection is re-established and the
        method returns False.

        :returns: True if pairing was validated and a session established; False otherwise (e.g. no pair
            record, an invalid host id, or an on-device pairing that was removed).
        """
        if self.pair_record is None:
            await self.fetch_pair_record()

        if self.pair_record is None:
            return False

        if (Version(self.product_version) < Version("7.0")) and (self.device_class != DeviceClass.WATCH):
            try:
                await self._request("ValidatePair", {"PairRecord": self.pair_record})
            except PairingError:
                return False

        self.host_id = self.pair_record.get("HostID", self.host_id)
        self.system_buid = self.pair_record.get("SystemBUID", self.system_buid)

        try:
            start_session = await self._request(
                "StartSession", {"HostID": self.host_id, "SystemBUID": self.system_buid}
            )
        except (InvalidHostIDError, InvalidConnectionError):
            # no host id means there is no such pairing record
            return False

        self.session_id = start_session.get("SessionID")
        if start_session.get("EnableSessionSSL"):
            if (Version(self.product_version) < Version("5.0")) and (self.device_class != DeviceClass.WATCH):
                # TLS v1 is the protocol required for versions prior to iOS 5
                self.service.min_ssl_proto = TLSVersion.SSLv3
                self.service.max_ssl_proto = TLSVersion.TLSv1

            with self.ssl_file() as f:
                try:
                    await self.service.ssl_start(f)
                except (SSLZeroReturnError, ConnectionTerminatedError):
                    # possible when we have a pair record, but it was removed on-device
                    self.pair_record = None
                    await self.areestablish_connection()
                    return False

        self.paired = True

        # reload data after pairing
        self.all_values = await self.get_value()
        self.udid = self.all_values.get("UniqueDeviceID")

        return True

    async def pair(self, timeout: Optional[float] = None, private_key: Optional[RSAPrivateKey] = None) -> None:
        """Pair this host with the device.

        Retrieves the device's public key, generates a host key and certificate chain, builds a pair record
        and sends a ``Pair`` request. On success the pair record (including any returned escrow bag) is saved
        to the cache folder and the client is marked paired. Pairing requires the user to accept the on-device
        trust dialog.

        :param timeout: Maximum time in seconds to wait for the user to accept the pairing dialog. A value of
            0 fails immediately if the dialog is pending; ``None`` waits indefinitely.
        :param private_key: RSA private key to use when generating the pairing certificate chain; a new key
            is generated if omitted.
        :raises PairingError: The device public key could not be retrieved.
        :raises PairingDialogResponsePendingError: The user did not accept the pairing dialog in time.
        :raises UserDeniedPairingError: The user declined the pairing request.
        """
        self.device_public_key = await self.get_value("", "DevicePublicKey")
        if not self.device_public_key:
            self.logger.error("Unable to retrieve DevicePublicKey")
            await self.service.close()
            raise PairingError()

        self.logger.info("Creating host key & certificate")
        host_cert_pem, host_key_pem, device_cert_pem, root_cert_pem, root_key_pem = generate_pairing_cert_chain(
            self.device_public_key,
            private_key=private_key,
            # TODO: consider parsing product_version to support iOS < 4
        )

        pair_record = {
            "DeviceCertificate": device_cert_pem,
            "HostCertificate": host_cert_pem,
            "HostID": self.host_id,
            "RootCertificate": root_cert_pem,
            "RootPrivateKey": root_key_pem,
            "WiFiMACAddress": self.wifi_mac_address,
            "SystemBUID": self.system_buid,
        }

        pair_options = {
            "HostName": socket.gethostname(),
            "PairRecord": pair_record,
            "ProtocolVersion": "2",
            "PairingOptions": {"ExtendedPairingErrors": True},
        }

        pair = await self._request_pair(pair_options, timeout=timeout)

        pair_record["HostPrivateKey"] = host_key_pem
        escrow_bag = pair.get("EscrowBag")

        if escrow_bag is not None:
            pair_record["EscrowBag"] = pair.get("EscrowBag")

        self.pair_record = pair_record
        await self.save_pair_record()
        self.paired = True

    async def pair_supervised(self, keybag_file: Path, timeout: Optional[float] = None) -> None:
        """Pair this host with a supervised device using a supervision identity.

        Loads the supervisor private key and certificate from ``keybag_file`` and performs the supervised
        pairing flow: it sends an initial ``Pair`` request carrying the supervisor certificate and, if the
        device responds with an ``MCChallengeRequired`` challenge, signs the challenge (PKCS#7) and sends a
        second request with the challenge response. On success the pair record (including any returned escrow
        bag) is saved and the client is marked paired. Because supervision authorizes the host, this does not
        require the user to accept an on-device dialog.

        :param keybag_file: Path to a PEM file containing both the supervisor private key and certificate.
        :param timeout: Maximum time in seconds to wait for each pairing request; ``None`` waits indefinitely.
        :raises PairingError: The device public key could not be retrieved.
        """
        keybag_data = Path(keybag_file).read_bytes()
        private_key = serialization.load_pem_private_key(keybag_data, password=None)
        if not isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey)):
            raise PairingError(f"unsupported supervisor private key type: {type(private_key).__name__}")
        cer = x509.load_pem_x509_certificate(keybag_data)
        public_key = cer.public_bytes(Encoding.DER)

        self.device_public_key = await self.get_value("", "DevicePublicKey")
        if not self.device_public_key:
            self.logger.error("Unable to retrieve DevicePublicKey")
            await self.service.close()
            raise PairingError()

        self.logger.info("Creating host key & certificate")
        host_cert_pem, host_key_pem, device_cert_pem, root_cert_pem, root_key_pem = generate_pairing_cert_chain(
            self.device_public_key
            # TODO: consider parsing product_version to support iOS < 4
        )

        pair_record = {
            "DeviceCertificate": device_cert_pem,
            "HostCertificate": host_cert_pem,
            "HostID": self.host_id,
            "RootCertificate": root_cert_pem,
            "RootPrivateKey": root_key_pem,
            "WiFiMACAddress": self.wifi_mac_address,
            "SystemBUID": self.system_buid,
        }

        pair_options = {
            "PairRecord": pair_record,
            "ProtocolVersion": "2",
            "PairingOptions": {"SupervisorCertificate": public_key, "ExtendedPairingErrors": True},
        }

        # first pair with SupervisorCertificate as PairingOptions to get PairingChallenge
        pair = await self._request_pair(pair_options, timeout=timeout)
        if pair.get("Error") == "MCChallengeRequired":
            extended_response = pair.get("ExtendedResponse")
            if extended_response is not None:
                pairing_challenge = extended_response.get("PairingChallenge")
                signed_response = (
                    PKCS7SignatureBuilder()
                    .set_data(pairing_challenge)
                    .add_signer(cer, private_key, hashes.SHA256())
                    .sign(Encoding.DER, [PKCS7Options.Binary])
                )
                pair_options = {
                    "PairRecord": pair_record,
                    "ProtocolVersion": "2",
                    "PairingOptions": {"ChallengeResponse": signed_response, "ExtendedPairingErrors": True},
                }
                # second pair with Response to Challenge
                pair = await self._request_pair(pair_options, timeout=timeout)

        pair_record["HostPrivateKey"] = host_key_pem
        escrow_bag = pair.get("EscrowBag")

        if escrow_bag is not None:
            pair_record["EscrowBag"] = pair.get("EscrowBag")

        self.pair_record = pair_record
        await self.save_pair_record()
        self.paired = True

    async def unpair(self, host_id: Optional[str] = None) -> None:
        """Remove a pairing from the device.

        Sends an ``Unpair`` request. With no ``host_id`` the current pair record is unpaired; otherwise the
        pairing identified by ``host_id`` is removed.

        :param host_id: HostID of the pairing to remove; defaults to the current pair record.
        """
        pair_record = self.pair_record if host_id is None else {"HostID": host_id}
        await self._request("Unpair", {"PairRecord": pair_record, "ProtocolVersion": "2"}, verify_request=False)

    async def reset_pairing(self):
        """Reset all pairings on the device.

        Sends a ``ResetPairing`` request with ``FullReset`` set, clearing the device's pairing state.

        :returns: The lockdownd response to the request.
        """
        return await self._request("ResetPairing", {"FullReset": True})

    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        """Read a value from the device via a ``GetValue`` request.

        With neither ``domain`` nor ``key`` given, returns the full values dict and also refreshes the cached
        `all_values`. Otherwise narrows the lookup to the given domain and/or key. Binary blobs are
        returned as their raw bytes.

        :param domain: Domain to read from, or ``None`` for the default domain.
        :param key: Specific key to read, or ``None`` to read the whole domain.
        :returns: The requested value, or ``None`` if nothing was returned.
        """
        options = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        result = await self._request("GetValue", options)
        if not result:
            return None
        r = result.get("Value")
        if r is None:
            return None
        if hasattr(r, "data"):
            return r.data
        if domain is None and key is None and isinstance(r, dict):
            self.all_values = r
        return r

    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        """Remove a value on the device via a ``RemoveValue`` request.

        :param domain: Domain to remove from, or ``None`` for the default domain.
        :param key: Specific key to remove, or ``None``.
        :returns: The lockdownd response to the request.
        """
        options = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        return await self._request("RemoveValue", options)

    async def set_value(self, value, domain: Optional[str] = None, key: Optional[str] = None) -> dict[str, Any]:
        """Write a value to the device via a ``SetValue`` request.

        :param value: The value to write.
        :param domain: Domain to write to, or ``None`` for the default domain.
        :param key: Specific key to write, or ``None``.
        :returns: The lockdownd response to the request.
        """
        options = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        options["Value"] = value
        return await self._request("SetValue", options)

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
        """Ask lockdownd to start a named service and return its connection attributes.

        Sends a ``StartService`` request for the given service. The returned dict includes the ``Port`` to
        connect on and whether SSL must be enabled (``EnableServiceSSL``). Use `start_lockdown_service`
        to also open the connection.

        :param name: The lockdownd service name to start (e.g. ``"com.apple.afc"``).
        :param include_escrow_bag: When True, include the pair record's escrow bag in the request (required by
            some services to operate while the device is locked).
        :returns: The service connection attributes (including ``Port`` and possibly ``EnableServiceSSL``).
        :raises NotPairedError: The client is not paired with the device.
        :raises PasswordRequiredError: The device is passcode-protected and must be unlocked first.
        :raises StartServiceError: lockdownd refused to start the service.
        """
        if not self.paired:
            raise NotPairedError()

        options = {"Service": name}
        if include_escrow_bag:
            if self.pair_record is None:
                raise NotPairedError()
            options["EscrowBag"] = self.pair_record["EscrowBag"]

        response = await self._request("StartService", options)
        if not response or response.get("Error"):
            if response.get("Error", "") == "PasswordProtected":
                raise PasswordRequiredError(
                    "your device is protected with password, please enter password in device and try again"
                )
            raise StartServiceError(name, response.get("Error", ""))
        return response

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """Start a named lockdownd service and open a connection to it.

        Asks lockdownd to start the service (see `get_service_connection_attributes`), opens a new
        connection to the reported port, and upgrades it to SSL when the service requires it.

        :param name: The lockdownd service name to start (e.g. ``"com.apple.afc"``).
        :param include_escrow_bag: When True, include the pair record's escrow bag in the start request
            (required by some services to operate while the device is locked).
        :returns: A connected `ServiceConnection` for the started service.
        :raises NotPairedError: The client is not paired with the device.
        :raises PasswordRequiredError: The device is passcode-protected and must be unlocked first.
        :raises StartServiceError: lockdownd refused to start the service.
        """
        attr = await self.get_service_connection_attributes(name, include_escrow_bag=include_escrow_bag)
        service_connection = await self.create_service_connection(attr["Port"])

        if attr.get("EnableServiceSSL", False):
            with self.ssl_file() as f:
                await service_connection.ssl_start(f)
        return service_connection

    async def close(self) -> None:
        """Close the underlying lockdownd connection.

        Called automatically when the client is used as an async context manager.
        """
        await self.service.close()

    @contextmanager
    def ssl_file(self) -> Generator[str, Any, None]:
        """Yield a temporary file holding the host certificate and private key for SSL handshakes.

        Writes the pair record's host certificate and private key (PEM) to a temporary file for the duration
        of the ``with`` block and deletes it on exit, even if an exception is raised.

        :yield: Path to the temporary PEM file containing the host certificate followed by its private key.
        """
        if self.pair_record is None:
            raise NotPairedError()
        cert_pem = self.pair_record["HostCertificate"]
        private_key_pem = self.pair_record["HostPrivateKey"]

        # use delete=False and manage the deletion ourselves because Windows
        # cannot use in-use files
        with tempfile.NamedTemporaryFile("w+b", delete=False) as f:
            f.write(cert_pem + b"\n" + private_key_pem)
            filename = f.name

        try:
            yield filename
        finally:
            os.unlink(filename)

    async def _handle_autopair(
        self, autopair: bool, timeout: Optional[float], private_key: Optional[RSAPrivateKey] = None
    ) -> None:
        """Internal helper for handle autopair.

        :param autopair: Autopair.
        :param timeout: Timeout.
        :param private_key: Private key. Defaults to None.

        :return: None.
        """
        if await self.validate_pairing():
            return

        # device is not paired yet
        if not autopair:
            # but pairing by default was not requested
            return
        await self.pair(timeout=timeout, private_key=private_key)
        # get session_id
        if not await self.validate_pairing():
            raise FatalPairingError()

    @abstractmethod
    async def create_service_connection(self, port: int) -> ServiceConnection:
        """Open a new connection to the device on the given port.

        Abstract: each concrete client implements this for its transport (usbmux, TCP, ...). Used to open
        service connections and to re-establish the lockdownd connection after it drops.

        :param port: The device-side port to connect to.
        :returns: A connected `ServiceConnection`.
        """
        pass

    async def _create_service_connection(self, port: int) -> ServiceConnection:
        """
        Establishes a service connection asynchronously.

        This function is used to create and establish a connection to a service
        using the specified port. It utilizes the `create_service_connection`
        method to perform the actual connection process.

        :param port: The port number to be used for the service connection.
        :return: An instance of ServiceConnection representing the established
            connection.
        """
        return await self.create_service_connection(port)

    async def _request(
        self, request: str, options: Optional[dict[str, Any]] = None, verify_request: bool = True
    ) -> dict[str, Any]:
        """
        Sends a request to the associated service, processes the response, and verifies
        the result. Reconnects and retries the request if a connection-related error
        occurs.

        :param request: The request string containing the operation or data to be sent.
        :param options: Additional options to include in the request message, defaults
            to None.
        :param verify_request: Indicates whether to verify the response after receiving
            it, defaults to True.
        :return: The processed response received from the service.
        :raises ConnectionResetError: If the connection is reset during the operation.
        :raises ConnectionTerminatedError: If the connection is terminated unexpectedly.
        :raises RuntimeError: If a runtime error occurs, that is not related to a
            different event loop.
        :raises InvalidConnectionError: If the connection is deemed invalid during
            verification.
        :raises LockdownError: If a lockdown-specific error occurs during verification.
        """
        message = {"Label": self.label, "Request": request}
        if options:
            message.update(options)

        try:
            try:
                response = await self.service.send_recv_plist(message)
            except (ConnectionResetError, ConnectionTerminatedError, RuntimeError) as e:
                # ServiceConnection streams are loop-bound; reconnect if this client was created in another loop.
                if isinstance(e, RuntimeError) and "different event loop" not in str(e):
                    raise
                await self.areestablish_connection()
                response = await self.service.send_recv_plist(message)
            try:
                return self._verify_request_response(request, response, verify_request=verify_request)
            except (InvalidConnectionError, LockdownError) as e:
                if not (isinstance(e, InvalidConnectionError) or str(e) == "SessionInactive"):
                    raise
                await self.areestablish_connection()
                response = await self.service.send_recv_plist(message)
                return self._verify_request_response(request, response, verify_request=verify_request)
        except asyncio.CancelledError:
            # Service connection is now in an inconsistent state.
            # Instead of calling `areestablish_connection` here, which is likely not desirable in a cancellation
            # scenario, simply close the connection and reconnect on the next call to `_request`.
            await self.service.close()
            raise

    def _verify_request_response(
        self, request: str, response: dict[str, Any], *, verify_request: bool = True
    ) -> dict[str, Any]:
        """Internal helper for verify request response.

        :param request: Request.
        :param response: Response.
        :param verify_request: Verify request. Defaults to True.

        :return: Result of the operation.
        """
        if verify_request and response.get("Request") != request:
            if response.get("Type") == RESTORED_SERVICE_TYPE:
                raise IncorrectModeError(f"Incorrect mode returned. Got: {response}")
            raise LockdownError(f"Incorrect response returned. Got: {response}", self.identifier, self.product_version)

        error = response.get("Error")
        if error is not None:
            # return response if supervisor cert challenge is required, to work with pair_supervisor
            if error == "MCChallengeRequired":
                return response
            exception_errors = {
                "PasswordProtected": PasswordRequiredError,
                "PairingDialogResponsePending": PairingDialogResponsePendingError,
                "UserDeniedPairing": UserDeniedPairingError,
                "InvalidHostID": InvalidHostIDError,
                "GetProhibited": GetProhibitedError,
                "SetProhibited": SetProhibitedError,
                "MissingValue": MissingValueError,
                "InvalidService": InvalidServiceError,
                "InvalidConnection": InvalidConnectionError,
            }
            raise exception_errors.get(error, LockdownError)(error, self.identifier, self.product_version)

        # iOS < 5: 'Error' is not present, so we need to check the 'Result' instead
        if response.get("Result") == "Failure":
            raise LockdownError("", self.identifier, self.product_version)

        return response

    async def _request_pair(self, pair_options: dict[str, Any], timeout: Optional[float] = None) -> dict[str, Any]:
        """
        Asynchronously requests pairing using the provided pair options. This method handles
        pairing dialog responses and waits for user input within the given timeout period.
        If the timeout elapses or certain conditions are met, it raises an error accordingly.

        :param pair_options: A dictionary containing the options required for the pairing request.
        :param timeout: An optional timeout value (in seconds) indicating how long
            to wait for user input. If None, waits indefinitely.
            A value of 0 skips waiting and raises an error immediately.
        :return: A dictionary representing the response of the pairing request.
        :raises PairingDialogResponsePendingError: Raised if the pairing dialog response is
            still pending and the timeout is exceeded.
        """
        try:
            return await self._request("Pair", pair_options)
        except PairingDialogResponsePendingError:
            if timeout == 0:
                raise

        self.logger.info("waiting user pairing dialog...")
        start = time.time()
        while timeout is None or time.time() <= start + timeout:
            with suppress(PairingDialogResponsePendingError):
                return await self._request("Pair", pair_options)
            await asyncio.sleep(1)
        raise PairingDialogResponsePendingError()

    async def fetch_pair_record(self) -> None:
        """Load the preferred pair record for this device into `pair_record`.

        Looks up the record matching `identifier` in the cache folder (and other known locations). Does
        nothing if `identifier` is not set.
        """
        if self.identifier is not None and self.pairing_records_cache_folder is not None:
            self.pair_record = await get_preferred_pair_record(self.identifier, self.pairing_records_cache_folder)

    async def save_pair_record(self) -> None:
        """Persist the current pair record to the cache folder.

        Writes `pair_record` as a plist named ``<identifier>.plist`` in the pairing-records cache folder.
        When running under sudo, the file's ownership is handed back to the invoking user so a later
        unprivileged run can rewrite it.
        """
        assert self.pairing_records_cache_folder is not None and self.pair_record is not None
        pair_record_file = self.pairing_records_cache_folder / f"{self.identifier}.plist"
        pair_record_file.write_bytes(plistlib.dumps(self.pair_record))
        # When pairing under sudo, hand the record back to the invoking user (no-op otherwise),
        # so a later unprivileged run can still rewrite it. Without this, a sudo run leaves a
        # root-owned plist that breaks subsequent non-root pairing with EPERM.
        OSUTIL.chown_to_non_sudo_if_needed(pair_record_file)

    def _reestablish_connection(self) -> None:
        """Internal helper for reestablish connection.

        :return: None.
        """
        raise RuntimeError("Sync reconnection path was removed. Use asyncio APIs.")

    async def areestablish_connection(self) -> None:
        """Re-establish the lockdownd connection after it has dropped.

        Closes the current connection, clears the session, opens a fresh connection on `port`, and
        re-validates pairing if a pair record is present. Called internally to recover from connection
        errors mid-request.
        """
        await self.close()
        self.session_id = None
        self.service = await self.create_service_connection(self.port)
        self.paired = False
        if self.pair_record is not None:
            await self.validate_pairing()


class UsbmuxLockdownClient(LockdownClient):
    """Lockdown client that reaches the device through a usbmuxd connection (USB or network).

    Obtain an instance from `create_using_usbmux`. Service connections are opened through usbmuxd via
    `create_using_usbmux`.
    """

    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict[str, Any]] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
        usbmux_address: Optional[str] = None,
    ):
        """Initialize a new UsbmuxLockdownClient instance.

        Normally constructed by `create_using_usbmux` rather than directly.

        :param service: An already-established lockdownd connection (opened over usbmuxd).
        :param host_id: The HostID identifying this host to the device.
        :param identifier: Device identifier (typically its UDID) used to locate the matching pair record.
        :param label: User-agent label included in every request sent to lockdownd.
        :param system_buid: The host's SystemBUID, included when starting a session.
        :param pair_record: A pre-loaded pair record to use instead of looking one up.
        :param pairing_records_cache_folder: Directory used to search for and persist pair records.
        :param port: TCP port of the lockdownd service on the device.
        :param usbmux_address: Address of the usbmuxd socket to use, or ``None`` for the default.
        """
        self.usbmux_address = usbmux_address
        super().__init__(
            service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder, port
        )

    @property
    def short_info(self) -> dict[str, Any]:
        """A compact subset of the device's values, plus the usbmux connection type.

        :returns: The base `short_info` dict with an added ``ConnectionType`` key
            (e.g. ``"USB"`` or ``"Network"``).
        """
        short_info = super().short_info
        if self.service.mux_device is not None:
            short_info["ConnectionType"] = self.service.mux_device.connection_type
        return short_info

    async def fetch_pair_record(self) -> None:
        """Load the preferred pair record for this device into `pair_record`.

        Like `fetch_pair_record`, but also consults usbmuxd (at
        `usbmux_address`) as a source of pair records. Does nothing if `identifier` is not set.
        """
        if self.identifier is not None and self.pairing_records_cache_folder is not None:
            self.pair_record = await get_preferred_pair_record(
                self.identifier, self.pairing_records_cache_folder, usbmux_address=self.usbmux_address
            )

    async def create_service_connection(self, port: int) -> ServiceConnection:
        """Open a new connection to the device on the given port through usbmuxd.

        :param port: The device-side port to connect to.
        :returns: A connected `ServiceConnection` opened over usbmuxd, reusing this client's
            connection type and usbmux address.
        """
        connection_type = self.service.mux_device.connection_type if self.service.mux_device is not None else None
        return await ServiceConnection.create_using_usbmux(
            self.identifier, port, connection_type, usbmux_address=self.usbmux_address
        )


class PlistUsbmuxLockdownClient(UsbmuxLockdownClient):
    """Usbmux lockdown client used with the plist-protocol usbmuxd.

    Selected automatically by `create_using_usbmux` when the connected usbmuxd speaks the plist
    protocol. Differs from `UsbmuxLockdownClient` only in that it also stores the pair record with
    usbmuxd, not just on disk.
    """

    async def save_pair_record(self) -> None:
        """Persist the current pair record to disk and to usbmuxd.

        Saves the pair record to the cache folder (as in the base class) and additionally hands it to usbmuxd
        keyed by the device's usbmux id, so usbmuxd can use it for its own connections.
        """
        await super().save_pair_record()
        assert self.pair_record is not None and self.identifier is not None
        record_data = plistlib.dumps(self.pair_record)
        async with await usbmux.create_mux() as client:
            if isinstance(client, PlistMuxConnection) and self.service.mux_device is not None:
                await client.save_pair_record(self.identifier, self.service.mux_device.devid, record_data)


class TcpLockdownClient(LockdownClient):
    """Lockdown client that reaches the device over a direct TCP connection (Wi-Fi/network).

    Obtain an instance from `create_using_tcp`. The device is addressed by hostname; service
    connections are opened with `create_using_tcp`.
    """

    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        hostname: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict[str, Any]] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
        keep_alive: bool = True,
    ):
        """Initialize a new TcpLockdownClient instance.

        Normally constructed by `create_using_tcp` rather than directly. Note that
        `identifier` is overwritten with ``hostname``.

        :param service: An already-established lockdownd connection (opened over TCP).
        :param host_id: The HostID identifying this host to the device.
        :param hostname: The device's hostname or IP address; used to open further connections.
        :param identifier: Device identifier used to locate the matching pair record (overridden by
            ``hostname``).
        :param label: User-agent label included in every request sent to lockdownd.
        :param system_buid: The host's SystemBUID, included when starting a session.
        :param pair_record: A pre-loaded pair record to use instead of looking one up.
        :param pairing_records_cache_folder: Directory used to search for and persist pair records.
        :param port: TCP port of the lockdownd service on the device.
        :param keep_alive: Enable TCP keep-alive so a lost connection is detected.
        """
        super().__init__(
            service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder, port
        )
        self._keep_alive = keep_alive
        self.hostname = hostname
        self.identifier = hostname

    async def create_service_connection(self, port: int) -> ServiceConnection:
        """Open a new TCP connection to the device on the given port.

        :param port: The device-side port to connect to.
        :returns: A connected `ServiceConnection` to this client's hostname, honoring its keep-alive
            setting.
        """
        return await ServiceConnection.create_using_tcp(self.hostname, port, keep_alive=self._keep_alive)


class RemoteLockdownClient(LockdownClient):
    async def create_service_connection(self, port: int) -> ServiceConnection:
        """Create service connection.

        :param port: Port.

        :return: Result of the operation.
        """
        raise NotImplementedError(
            "RemoteXPC service connections should only be created using RemoteServiceDiscoveryService"
        )

    async def _handle_autopair(self, *args, **kwargs):
        # The RemoteXPC version of lockdown doesn't support pairing operations
        """Internal helper for handle autopair.

        :param *args: Additional positional arguments.
        :param **kwargs: Additional keyword arguments.

        :return: Result of the operation.
        """
        return None

    async def pair(self, *args, **kwargs) -> None:
        """Pair.

        :param *args: Additional positional arguments.
        :param **kwargs: Additional keyword arguments.

        :return: None.
        """
        raise NotImplementedError("RemoteXPC lockdown version does not support pairing operations")

    async def unpair(self, host_id: Optional[str] = None) -> None:
        """Unpair.

        :param host_id: Host ID. Defaults to None.

        :return: None.
        """
        raise NotImplementedError("RemoteXPC lockdown version does not support pairing operations")

    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict[str, Any]] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
    ):
        """Initialize a new RemoteLockdownClient instance.

        :param service: Service.
        :param host_id: Host id.
        :param identifier: Identifier. Defaults to None.
        :param label: Label. Defaults to DEFAULT_LABEL.
        :param system_buid: System buid. Defaults to SYSTEM_BUID.
        :param pair_record: Pair record. Defaults to None.
        :param pairing_records_cache_folder: Pairing records cache folder. Defaults to None.
        :param port: Port. Defaults to SERVICE_PORT.

        :return: Result of the operation.
        """
        super().__init__(
            service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder, port
        )


async def create_using_usbmux(
    serial: Optional[str] = None,
    identifier: Optional[str] = None,
    label: str = DEFAULT_LABEL,
    autopair: bool = True,
    connection_type: Optional[str] = None,
    pair_timeout: Optional[float] = None,
    local_hostname: Optional[str] = None,
    pair_record: Optional[dict[str, Any]] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    port: int = SERVICE_PORT,
    usbmux_address: Optional[str] = None,
) -> UsbmuxLockdownClient:
    """Connect to a device over usbmuxd and return a ready-to-use lockdown client.

    Opens a lockdownd connection through usbmuxd, queries the device's values, and (when ``autopair`` is set)
    validates an existing pairing or performs a new one. Returns a `PlistUsbmuxLockdownClient` when the
    connected usbmuxd speaks the plist protocol, otherwise a `UsbmuxLockdownClient`. The connection is
    closed automatically if setup fails.

    :param serial: usbmux serial of the target device, or ``None`` to use the first available device.
    :param identifier: Device identifier used to locate the matching pair record; defaults to the device's
        serial reported by usbmuxd.
    :param label: User-agent label included in every request sent to lockdownd.
    :param autopair: When True, pair with the device (blocking) if it is not already paired.
    :param connection_type: Restrict to a specific usbmux connection type (``"USB"`` or ``"Network"``).
    :param pair_timeout: Maximum time in seconds to wait for the user to accept the pairing dialog.
    :param local_hostname: Seed used to generate the HostID.
    :param pair_record: A pre-loaded pair record to use instead of looking one up.
    :param pairing_records_cache_folder: Directory used to search for and persist pair records.
    :param port: TCP port of the lockdownd service on the device.
    :param usbmux_address: Address of the usbmuxd socket to use, or ``None`` for the default.
    :returns: A connected usbmux lockdown client.
    """
    service = await ServiceConnection.create_using_usbmux(
        serial, port, connection_type=connection_type, usbmux_address=usbmux_address
    )
    try:
        cls = UsbmuxLockdownClient
        system_buid = SYSTEM_BUID
        async with await usbmux.create_mux(usbmux_address=usbmux_address) as client:
            if isinstance(client, PlistMuxConnection):
                # Only the Plist version of usbmuxd supports this message type
                system_buid = await client.get_buid()
                cls = PlistUsbmuxLockdownClient

        if identifier is None and service.mux_device is not None:
            # attempt get identifier from mux device serial
            identifier = service.mux_device.serial

        host_id = generate_host_id(local_hostname)
        pairing_records_cache_folder = create_pairing_records_cache_folder(pairing_records_cache_folder)
        lockdown_client = cls(
            service,
            host_id=host_id,
            identifier=identifier,
            label=label,
            system_buid=system_buid,
            pair_record=pair_record,
            pairing_records_cache_folder=pairing_records_cache_folder,
            port=port,
            usbmux_address=usbmux_address,
        )
        await lockdown_client._initialize()
        await lockdown_client._handle_autopair(autopair, pair_timeout)
    except Exception:
        await service.close()
        raise
    else:
        return lockdown_client


@overload
async def retry_create_using_usbmux(retry_timeout: None = ..., **kwargs) -> UsbmuxLockdownClient: ...


@overload
async def retry_create_using_usbmux(retry_timeout: float, **kwargs) -> Optional[UsbmuxLockdownClient]: ...


async def retry_create_using_usbmux(retry_timeout: Optional[float] = None, **kwargs) -> Optional[UsbmuxLockdownClient]:
    """Repeatedly call `create_using_usbmux` until it succeeds, tolerating transient errors.

    Useful while a device is rebooting or reconnecting: connection/device errors are swallowed and the
    attempt is retried after a short delay. All keyword arguments are forwarded to
    `create_using_usbmux`.

    :param retry_timeout: Maximum time in seconds to keep retrying, or ``None`` to retry indefinitely. With
        ``None`` the call cannot fail with a timeout, so it always returns a client (see the overloads);
        with a timeout it returns ``None`` if the timeout elapsed without success.
    :returns: A connected usbmux lockdown client, or ``None`` if the timeout elapsed without success.
    """
    start = time.time()
    while (retry_timeout is None) or (time.time() - start < retry_timeout):
        try:
            return await create_using_usbmux(**kwargs)
        except (
            NoDeviceConnectedError,
            ConnectionFailedError,
            BadDevError,
            MuxException,
            OSError,
            StreamError,
            DeviceNotFoundError,
            IncompleteReadError,
            ConnectionTerminatedError,
        ):
            await asyncio.sleep(RECONNECT_RETRY_INTERVAL_SECONDS)
    return None


async def create_using_tcp(
    hostname: str,
    identifier: Optional[str] = None,
    label: str = DEFAULT_LABEL,
    autopair: bool = True,
    pair_timeout: Optional[float] = None,
    local_hostname: Optional[str] = None,
    pair_record: Optional[dict[str, Any]] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    port: int = SERVICE_PORT,
    keep_alive: bool = False,
) -> TcpLockdownClient:
    """Connect to a device over TCP (Wi-Fi/network) and return a ready-to-use lockdown client.

    Opens a lockdownd connection to ``hostname``, queries the device's values, and (when ``autopair`` is set)
    validates an existing pairing or performs a new one. The connection is closed automatically if setup
    fails.

    :param hostname: The target device's hostname or IP address.
    :param identifier: Device identifier used to locate the matching pair record.
    :param label: User-agent label included in every request sent to lockdownd.
    :param autopair: When True, pair with the device (blocking) if it is not already paired.
    :param pair_timeout: Maximum time in seconds to wait for the user to accept the pairing dialog.
    :param local_hostname: Seed used to generate the HostID.
    :param pair_record: A pre-loaded pair record to use instead of looking one up.
    :param pairing_records_cache_folder: Directory used to search for and persist pair records.
    :param port: TCP port of the lockdownd service on the device.
    :param keep_alive: Enable TCP keep-alive so a lost connection is detected.
    :returns: A connected TCP lockdown client.
    """
    service = await ServiceConnection.create_using_tcp(hostname, port, keep_alive=keep_alive)
    try:
        return await TcpLockdownClient.create(
            service,
            identifier=identifier,
            label=label,
            local_hostname=local_hostname,
            pair_record=pair_record,
            pairing_records_cache_folder=pairing_records_cache_folder,
            pair_timeout=pair_timeout,
            autopair=autopair,
            port=port,
            hostname=hostname,
            keep_alive=keep_alive,
        )
    except Exception:
        await service.close()
        raise


async def create_using_remote(
    service: ServiceConnection,
    identifier: Optional[str] = None,
    label: str = DEFAULT_LABEL,
    autopair: bool = True,
    pair_timeout: Optional[float] = None,
    local_hostname: Optional[str] = None,
    pair_record: Optional[dict[str, Any]] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    port: int = SERVICE_PORT,
) -> RemoteLockdownClient:
    """Wrap an existing RemoteXPC (RSD) service connection in a lockdown client.

    Used with RemoteServiceDiscoveryService over the RemoteXPC tunnel. The supplied ``service`` is wrapped and
    initialized; note that the RemoteXPC variant does not support pairing operations (``autopair`` and the
    pairing parameters are accepted for signature compatibility but pairing is a no-op). The connection is
    closed automatically if setup fails.

    :param service: An already-established RemoteXPC service connection to lockdownd.
    :param identifier: Device identifier used to locate the matching pair record.
    :param label: User-agent label included in every request sent to lockdownd.
    :param autopair: Accepted for compatibility; pairing is not supported over RemoteXPC.
    :param pair_timeout: Accepted for compatibility; pairing is not supported over RemoteXPC.
    :param local_hostname: Seed used to generate the HostID.
    :param pair_record: A pre-loaded pair record to use instead of looking one up.
    :param pairing_records_cache_folder: Directory used to search for and persist pair records.
    :param port: TCP port of the lockdownd service on the device.
    :returns: A connected RemoteXPC lockdown client.
    """
    try:
        return await RemoteLockdownClient.create(
            service,
            identifier=identifier,
            label=label,
            local_hostname=local_hostname,
            pair_record=pair_record,
            pairing_records_cache_folder=pairing_records_cache_folder,
            pair_timeout=pair_timeout,
            autopair=autopair,
            port=port,
        )
    except Exception:
        await service.close()
        raise


async def get_mobdev2_lockdowns(
    udid: Optional[str] = None,
    pair_records: Optional[Path] = None,
    only_paired: bool = False,
    timeout: float = DEFAULT_BONJOUR_TIMEOUT,
) -> AsyncIterable[tuple[str, TcpLockdownClient]]:
    records = {}
    if pair_records is None:
        pair_records = get_home_folder()
    for file in pair_records.glob("*.plist"):
        if file.name.startswith("remote_"):
            # skip RemotePairing records
            continue
        record_udid = file.parts[-1].strip(".plist")
        if udid is not None and record_udid != udid:
            continue
        record = plistlib.loads(file.read_bytes())
        records[record["WiFiMACAddress"]] = record

    for answer in await browse_mobdev2(timeout=timeout):
        if "@" not in answer.instance:
            continue
        wifi_mac_address = answer.instance.split("@", 1)[0]
        record = records.get(wifi_mac_address)

        if only_paired and record is None:
            continue

        for address in answer.addresses:
            try:
                lockdown = await create_using_tcp(hostname=address.full_ip, autopair=False, pair_record=record)
            except Exception:
                continue
            if only_paired and not lockdown.paired:
                await lockdown.service.close()
                continue
            yield address.full_ip, lockdown
