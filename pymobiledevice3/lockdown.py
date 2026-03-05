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
from typing import Any, Optional

import construct
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7Options, PKCS7SignatureBuilder
from packaging.version import Version

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
from pymobiledevice3.pair_records import (
    create_pairing_records_cache_folder,
    generate_host_id,
    get_preferred_pair_record,
)
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.usbmux import PlistMuxConnection

SYSTEM_BUID = "30142955-444094379208051516"
RESTORED_SERVICE_TYPE = "com.apple.mobile.restored"

DEFAULT_LABEL = "pymobiledevice3"
SERVICE_PORT = 62078


class DeviceClass(Enum):
    IPHONE = "iPhone"
    IPAD = "iPad"
    IPOD = "iPod"
    WATCH = "Watch"
    APPLE_TV = "AppleTV"
    UNKNOWN = "Unknown"


class LockdownClient(ABC, LockdownServiceProvider):
    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
    ):
        """Initialize a new LockdownClient instance.

        :param service: Service.
        :type service: ServiceConnection
        :param host_id: Host id.
        :type host_id: str
        :param identifier: Identifier. Defaults to None.
        :type identifier: Optional[str]
        :param label: Label. Defaults to DEFAULT_LABEL.
        :type label: str
        :param system_buid: System buid. Defaults to SYSTEM_BUID.
        :type system_buid: str
        :param pair_record: Pair record. Defaults to None.
        :type pair_record: Optional[dict]
        :param pairing_records_cache_folder: Pairing records cache folder. Defaults to None.
        :type pairing_records_cache_folder: Optional[Path]
        :param port: Port. Defaults to SERVICE_PORT.
        :type port: int

        :return: Result of the operation.
        :rtype: Any
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
        self.unique_chip_id = None
        self.device_public_key = None
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
        pair_record: Optional[dict] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
        private_key: Optional[RSAPrivateKey] = None,
        **cls_specific_args,
    ):
        """Create.

        :param service: Service.
        :type service: ServiceConnection
        :param identifier: Identifier. Defaults to None.
        :type identifier: Optional[str]
        :param system_buid: System buid. Defaults to SYSTEM_BUID.
        :type system_buid: str
        :param label: Label. Defaults to DEFAULT_LABEL.
        :type label: str
        :param autopair: Autopair. Defaults to True.
        :type autopair: bool
        :param pair_timeout: Pair timeout. Defaults to None.
        :type pair_timeout: Optional[float]
        :param local_hostname: Local hostname. Defaults to None.
        :type local_hostname: Optional[str]
        :param pair_record: Pair record. Defaults to None.
        :type pair_record: Optional[dict]
        :param pairing_records_cache_folder: Pairing records cache folder. Defaults to None.
        :type pairing_records_cache_folder: Optional[Path]
        :param port: Port. Defaults to SERVICE_PORT.
        :type port: int
        :param private_key: Private key. Defaults to None.
        :type private_key: Optional[RSAPrivateKey]
        :param **cls_specific_args: Additional keyword arguments.
        :type **cls_specific_args: Any

        :return: Result of the operation.
        :rtype: Any
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
        :rtype: str
        """
        return (
            f"<{self.__class__.__name__} ID:{self.identifier} VERSION:{self.product_version} "
            f"TYPE:{self.product_type} PAIRED:{self.paired}>"
        )

    async def __aenter__(self) -> "LockdownClient":
        """Enter the async context manager and return this client.

        :return: Result of the operation.
        :rtype: 'LockdownClient'
        """
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the async context manager and close open resources.

        :param exc_type: Exc type.
        :type exc_type: Any
        :param exc_val: Exc val.
        :type exc_val: Any
        :param exc_tb: Exc tb.
        :type exc_tb: Any

        :return: None.
        :rtype: None
        """
        await self.close()

    @property
    def product_version(self) -> str:
        """
        Provides access to the product version from a predefined set of values. If no version value
        is found, it defaults to "1.0".

        :return: The version of the product as a string.
        :rtype: str
        """
        return self.all_values.get("ProductVersion") or "1.0"

    @property
    def product_build_version(self) -> str:
        """
        Gets the 'BuildVersion' from the collection of all values.

        This property provides access to the build version of the product, which is stored
        within the 'all_values' dictionary under the key "BuildVersion".

        :return: The build version as a string.
        :rtype: str
        """
        return self.all_values.get("BuildVersion")

    @property
    def device_class(self) -> DeviceClass:
        """
        Retrieves the device class associated with the current instance.

        :return: Returns a DeviceClass instance representing the device class
            retrieved from the `all_values` attribute. If the provided value cannot
            be resolved into a valid DeviceClass, returns a DeviceClass instance
            with the value "Unknown".
        :rtype: DeviceClass
        """
        try:
            return DeviceClass(self.all_values.get("DeviceClass"))
        except ValueError:
            return DeviceClass("Unknown")

    @property
    def wifi_mac_address(self) -> str:
        """
        Retrieves the WiFi MAC Address of the device.

        :returns: The WiFi MAC Address as a string.
        :rtype: str
        """
        return self.all_values.get("WiFiAddress")

    @property
    def short_info(self) -> dict:
        """
        Provides a dictionary containing concise information about the device,
        extracted from its full details.

        The returned dictionary includes a subset of key attributes from the
        device details, such as the identifier and other selected keys (e.g.,
        DeviceClass, DeviceName, BuildVersion, etc.) if available.

        :return: A dictionary containing the filtered device details. The
            dictionary includes the `Identifier` key and additional
            attributes derived from available keys in the device details.
        :rtype: dict
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
        """
        Provides a property to access the ECID (Exclusive Chip ID) from stored values.

        :rtype: int
        :return: The ECID (Exclusive Chip ID) extracted from ``all_values["UniqueChipID"]``.
        """
        return self.all_values["UniqueChipID"]

    @property
    def preflight_info(self) -> dict:
        """
        Provides access to the preflight information.

        This property fetches the preflight information from the internal state.
        The data is expected to be a dictionary representing preflight details.

        :return: A dictionary containing preflight information
        :rtype: dict
        """
        return self.all_values.get("PreflightInfo")

    @property
    def firmware_preflight_info(self) -> dict:
        """
        Provides access to the firmware preflight information.

        This property retrieves data related to firmware preflight checks,
        such as configurations or metadata relevant before a firmware update. The
        information is returned in the form of a dictionary and sourced from
        the attribute `all_values`.

        :return: A dictionary containing firmware preflight information.
        :rtype: dict
        """
        return self.all_values.get("FirmwarePreflightInfo")

    @property
    def display_name(self) -> Optional[str]:
        """
        Provides a readable name for the device associated with the given product type
        if a match is found in the predefined list of devices. If no match is found,
        returns None.

        :return: The display name of the device if a match is found, otherwise None.
        :rtype: Optional[str]
        """
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.display_name
        return None

    @property
    def hardware_model(self) -> Optional[str]:
        """
        Fetches the hardware model for the current device based on its product type.

        This method looks up the product type of the current device in a predefined
        list of devices, `IRECV_DEVICES`. If a matching product type is found, it
        returns the corresponding hardware model. If no matching product type is
        found, it returns None.

        :return: The hardware model corresponding to the device's product type if a
            match is found, otherwise None.
        :rtype: Optional[str]
        """
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.hardware_model
        return None

    @property
    def board_id(self) -> Optional[int]:
        """
        Retrieves the board ID associated with the device's product type.

        This property iterates over the predefined list of `IRECV_DEVICES`.
        If a matching device is found with a product type that corresponds to
        the current device's product type, it retrieves and returns the
        associated board ID. If no match is found, it returns None.

        :return: The board ID as an integer if a match is found, or None if
            no matching device exists in the `IRECV_DEVICES` list.
        :rtype: Optional[int]
        """
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.board_id
        return None

    @property
    def chip_id(self) -> Optional[int]:
        """
        Retrieves the chip ID associated with the current product type of the
        device. The chip ID is determined by checking the `product_type` attribute
        against known IRECV devices.

        :return: The chip ID of the device, or None if no matching device is found.
        :rtype: Optional[int]
        """
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.chip_id
        return None

    async def query_type(self) -> str:
        """Query type.

        :return: Result of the operation.
        :rtype: str
        """
        return (await self._request("QueryType")).get("Type")

    async def set_language(self, language: str) -> None:
        """
        Sets the system language setting asynchronously.

        This method updates the system language setting by invoking
        an asynchronous operation that modifies the language value in
        the specified key and domain for system preferences.

        :param language: A string representing the language to set.
        :return: None
        """
        await self.set_value(language, key="Language", domain="com.apple.international")

    async def get_language(self) -> str:
        """
        Asynchronously retrieves the system's preferred language setting.

        This method fetches the preferred language from a given domain and key. If the value
        retrieved is not of type `str`, an empty string will be returned instead.

        :return: The system's preferred language.
        :rtype: str
        """
        value = await self.get_value(domain="com.apple.international", key="Language")
        return value if isinstance(value, str) else ""

    async def set_locale(self, locale: str) -> None:
        """
        Sets the locale on the system using the specified value.

        This asynchronous method updates the system's locale setting by assigning
        the provided locale value. The change is made within the appropriate domain
        and with the corresponding key.

        :param locale: The desired locale string to be set, conforming to standard
            locale formats.
        :return: This method does not return any value.
        """
        await self.set_value(locale, key="Locale", domain="com.apple.international")

    async def get_locale(self) -> str:
        """
        Retrieve the locale configuration from the system.

        This asynchronous method fetches the locale setting associated with the
        "user's international preferences" from the system. If the retrieved value
        is not a string, an empty string is returned.

        :return: A `str` representing the locale configuration or an empty string
                 if the value is not of type `str`.
        :rtype: str
        """
        value = await self.get_value(domain="com.apple.international", key="Locale")
        return value if isinstance(value, str) else ""

    async def set_timezone(self, timezone: str) -> None:
        """
        Sets the timezone value for the system by utilizing the `set_value` method with
        the provided key "TimeZone". This is an asynchronous method and must be awaited.

        :param timezone: The timezone to be set as a string.
        :return: None.
        """
        await self.set_value(timezone, key="TimeZone")

    async def set_uses24h_clock(self, value: bool) -> None:
        """
        Sets whether the 24-hour clock format is used.

        This asynchronous method updates the clock format preference by setting the
        value for the key 'Uses24HourClock' accordingly.

        :param value: A boolean indicating whether to use a 24-hour clock format.
        :return: None
        """
        await self.set_value(value, key="Uses24HourClock")

    async def set_uses24hClock(self, value: bool) -> None:
        """
        Sets the clock display mode to 24-hour format or 12-hour format.

        This asynchronous method sets the clock display preference for 24-hour
        mode based on the given boolean value.

        :param value: A boolean indicating whether to enable 24-hour format
            (True for 24-hour format, False for 12-hour format).
        :return: None
        """
        await self.set_uses24h_clock(value)

    async def set_assistive_touch(self, value: bool) -> None:
        """
        Sets the assistive touch feature on or off for a device.

        This method modifies the AssistiveTouchEnabledByiTunes setting under the
        com.apple.Accessibility domain by setting its value to either enabled or
        disabled based on the provided input.

        :param value: A boolean indicating whether to enable (True) or disable
            (False) the assistive touch feature.
        :return: None
        """
        await self.set_value(int(value), "com.apple.Accessibility", "AssistiveTouchEnabledByiTunes")

    async def get_assistive_touch(self) -> bool:
        """
        Retrieves the status of the AssistiveTouch accessibility feature.

        This asynchronous method fetches the value of the AssistiveTouch setting
        from the specified domain and key related to accessibility preferences.
        The returned value indicates whether the AssistiveTouch feature is enabled
        or disabled.

        :return: True if AssistiveTouch is enabled, False otherwise
        :rtype: bool
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="AssistiveTouchEnabledByiTunes")
        return bool(value)

    async def set_voice_over(self, value: bool) -> None:
        """
        Sets the VoiceOver feature status on the device.

        This asynchronous method enables or disables the VoiceOver feature based on
        the provided boolean value. It interacts with the device by updating the
        relevant property key under the accessibility domain.

        :param value: A boolean indicating whether to enable (True) or disable (False)
            the VoiceOver feature.
        :return: None
        """
        await self.set_value(int(value), "com.apple.Accessibility", "VoiceOverTouchEnabledByiTunes")

    async def get_voice_over(self) -> bool:
        """
        Gets the status of the VoiceOver feature enabled by iTunes on the device.

        This method asynchronously retrieves the value of the
        ``VoiceOverTouchEnabledByiTunes`` key from the specified
        domain and interprets it as a boolean.

        :return: The status of VoiceOverTouchEnabledByiTunes as a boolean
        :rtype: bool
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="VoiceOverTouchEnabledByiTunes")
        return bool(value)

    async def set_invert_display(self, value: bool) -> None:
        """
        Sets the display inversion setting asynchronously.

        This method adjusts the display inversion setting on the device using the
        specified accessibility key and category. The value provided determines
        whether the display inversion is enabled or disabled.

        :param value: A boolean value indicating whether to enable (True) or
                      disable (False) the display inversion.
        :return: None
        """
        await self.set_value(int(value), "com.apple.Accessibility", "InvertDisplayEnabledByiTunes")

    async def get_invert_display(self) -> bool:
        """
        Retrieve the current status of the invert display setting.

        This asynchronous method retrieves whether the "Invert Display" option is enabled
        under the specified domain and key. It queries the associated configuration
        and casts the resulting value to a boolean for evaluation. The result indicates
        if the "Invert Display" feature is currently enabled.

        :rtype: bool
        :return: A boolean value indicating whether the "Invert Display" option is
            enabled.
        """
        value = await self.get_value(domain="com.apple.Accessibility", key="InvertDisplayEnabledByiTunes")
        return bool(value)

    async def set_enable_wifi_connections(self, value: bool) -> None:
        """
        Sets the status of Wi-Fi connections on the device.

        This method enables or disables Wi-Fi connections by setting an underlying
        value in the appropriate system configuration. The change is applied asynchronously.

        :param value: A boolean indicating whether Wi-Fi connections should be
            enabled (True) or disabled (False).
        :return: None
        """
        await self.set_value(value, "com.apple.mobile.wireless_lockdown", "EnableWifiConnections")

    async def get_enable_wifi_connections(self) -> bool:
        """
        Retrieves the status of the "Enable Wifi Connections" setting.

        This method asynchronously fetches the value of the "EnableWifiConnections"
        key from the "com.apple.mobile.wireless_lockdown" domain, which indicates
        whether wifi connections are enabled or not, and returns it as a boolean.

        :return: A boolean value indicating whether wifi connections are enabled.
        :rtype: bool
        """
        value = await self.get_value(domain="com.apple.mobile.wireless_lockdown", key="EnableWifiConnections")
        return bool(value)

    async def get_developer_mode_status(self) -> bool:
        """
        Retrieve the status of Developer Mode as a boolean value.

        This asynchronous method checks whether the Developer Mode is currently
        enabled or disabled on the macOS system. The checks are performed by
        fetching the system's value associated with the provided domain and key
        specific to macOS security configurations.

        :return: A boolean indicating whether Developer Mode is enabled.
        :rtype: bool
        """
        value = await self.get_value(domain="com.apple.security.mac.amfi", key="DeveloperModeStatus")
        return bool(value)

    async def get_date(self) -> datetime.datetime:
        """
        Retrieve the current date and time based on a timestamp retrieved from a key-value store.

        This asynchronous method fetches a timestamp associated with the key
        "TimeIntervalSince1970" and converts it into a `datetime.datetime` object.
        If no timestamp is found, it defaults to `0`, representing the Unix epoch
        (1970-01-01 00:00:00 UTC).

        :return: The converted date and time.
        :rtype: datetime.datetime
        """
        timestamp = await self.get_value(key="TimeIntervalSince1970")
        return datetime.datetime.fromtimestamp(timestamp or 0)

    async def enter_recovery(self):
        """
        Executes the "EnterRecovery" operation.

        This method sends an asynchronous request to trigger the "EnterRecovery"
        operation. The exact behavior of this operation depends on the server-side
        implementation of the "EnterRecovery" command.

        :return: Returns the result of the "EnterRecovery" operation as received
            from the server.
        :rtype: Any
        """
        return await self._request("EnterRecovery")

    async def stop_session(self) -> dict:
        """
        Stops the current active session if one exists and interacts with the service
        to perform the necessary cleanup.

        If there is no active session or the service fails to stop the session
        successfully, an exception will be raised.

        :raises CannotStopSessionError: If there is no active session or if the
            service fails to stop the session.
        :return: A dictionary containing the service response for the stop session
            operation.
        :rtype: dict
        """
        if self.session_id and self.service:
            response = await self._request("StopSession", {"SessionID": self.session_id})
            self.session_id = None
            if not response or response.get("Result") != "Success":
                raise CannotStopSessionError()
            return response
        raise CannotStopSessionError("No active session")

    async def validate_pairing(self) -> bool:
        """
        Validates the pairing process with the device. This includes fetching the pairing record if not already
        present, initiating a session with the device, and ensuring secure communication if SSL is enabled.

        This method handles different device and software versions, applying appropriate configurations, including
        handling specific conditions such as older protocol requirements for legacy devices. If the pairing and
        session establishment are successful, the method updates relevant session attributes and reloads device data.

        :raises PairingError: If there are issues validating the pairing record.
        :raises InvalidHostIDError: When the provided host ID is invalid.
        :raises InvalidConnectionError: When the connection to the device is invalid.
        :raises SSLZeroReturnError: When an SSL handshake fails due to missing or invalid SSL setup.

        :return: True if the pairing is validated successfully; False otherwise.
        :rtype: bool
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
                except SSLZeroReturnError:
                    # possible when we have a pair record, but it was removed on-device
                    await self.areestablish_connection()
                    return False

        self.paired = True

        # reload data after pairing
        self.all_values = await self.get_value()
        self.udid = self.all_values.get("UniqueDeviceID")

        return True

    async def pair(self, timeout: Optional[float] = None, private_key: Optional[RSAPrivateKey] = None) -> None:
        """
        Initiates the pairing process with the device and generates a pairing certificate chain. This process involves
        retrieving the device's public key, generating a host key and certificate, creating a pairing record, and sending
        a pairing request to the device. Upon successful pairing, the pairing record is saved, and the device is marked as paired.

        :param timeout: The maximum time to wait for the pairing process to complete, in seconds. If not specified, the default
            timeout will be used.
        :type timeout: Optional[float]
        :param private_key: The private RSA key to use during the pairing certificate chain generation. If not provided, a new
            private key will be generated.
        :type private_key: Optional[RSAPrivateKey]
        :return: None
        :raises PairingError: If the device public key cannot be retrieved or if the pairing process fails.
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
        """
        Performs a supervised pairing process with a device using the provided
        keybag file and optionally a timeout. The method manages the creation
        of certificates and keys, sends pairing requests, handles challenges
        during the pairing process, and finalizes the pairing record upon
        success.

        :param keybag_file: The path to the file containing the keybag used for the
            supervised pairing process.
        :type keybag_file: Path
        :param timeout: Optional timeout value in seconds for the pairing requests.
            Default is None.
        :type timeout: Optional[float]
        :return: None
        :raises PairingError: Raised when the device public key cannot be retrieved
            or in case of a failure during the pairing process.
        """
        with open(keybag_file, "rb") as keybag_file:
            keybag_file = keybag_file.read()
        private_key = serialization.load_pem_private_key(keybag_file, password=None)
        cer = x509.load_pem_x509_certificate(keybag_file)
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
        """
        Unpair a host or the currently paired host.

        This method sends an asynchronous request to unpair a specific host by its
        identifier or the currently paired host if no host ID is provided. The operation
        is processed according to the protocol version defined.

        :param host_id: Optional; ID of the host to be unpaired. If not provided, the
            method will attempt to unpair the currently paired host.
        :return: None
        """
        pair_record = self.pair_record if host_id is None else {"HostID": host_id}
        await self._request("Unpair", {"PairRecord": pair_record, "ProtocolVersion": "2"}, verify_request=False)

    async def reset_pairing(self):
        """
        Resets the pairing process by requesting a full reset of the pairing state.

        This asynchronous method triggers a reset request for pairing configurations,
        ensuring that the pairing state is fully cleared.

        :return: A coroutine that, when awaited, sends the pairing reset request and
            completes upon response.
        :rtype: Coroutine
        """
        return await self._request("ResetPairing", {"FullReset": True})

    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None):
        """
        Fetches a value asynchronously from a remote service based on the provided domain and key.

        If a domain is provided, it will be included in the request options. Similarly, if a key
        is provided, it will also be included. The method sends a request to the "GetValue"
        endpoint with these options. If a response is received, it extracts and returns the
        value from the response. If the response contains an object with a "data" attribute,
        it returns the value of that attribute. When both domain and key are not specified,
        and the response is a dictionary, the response is stored in the `all_values` attribute.

        :param domain: Specifies the domain for the value lookup, or None to omit this filter.
        :type domain: Optional[str]
        :param key: Specifies the key for the value lookup, or None to omit this filter.
        :type key: Optional[str]
        :return: The fetched value if found, or None if no value could be fetched.
        :rtype: Any
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
        if hasattr(r, "data"):
            return r.data
        if domain is None and key is None and isinstance(r, dict):
            self.all_values = r
        return r

    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        """
        Asynchronously removes a specific value or set of values based on the given domain and key.
        This function interacts with an external service or system to perform the removal process.

        :param domain: The domain to filter values for removal. Optional.
                       If not specified, no domain filter will be applied.
        :type domain: Optional[str]
        :param key: The specific key to identify the value to be removed. Optional.
                    If not specified, no key filter will be applied.
        :type key: Optional[str]
        :return: A dictionary with the result of the remove operation.
                 The structure and content of the response depend on the external service's implementation.
        :rtype: dict
        """
        options = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        return await self._request("RemoveValue", options)

    async def set_value(self, value, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        """
        Sets a value with optional domain and key parameters.

        This method allows for the setting of a value with an optional domain or key to provide additional
        context or categorization. The request is sent asynchronously to the corresponding service.

        :param value: The value to be set.
        :type value: Any
        :param domain: Optional domain to associate with the value.
        :type domain: Optional[str]
        :param key: Optional key to associate with the value.
        :type key: Optional[str]
        :return: A dictionary containing the response from the service.
        :rtype: dict
        """
        options = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        options["Value"] = value
        return await self._request("SetValue", options)

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict:
        """
        Retrieve the attributes of a service connection. This method allows querying the specific
        connection attributes for a given service on a paired device. It optionally includes
        the escrow bag in the request, depending on the provided parameters.

        This method raises an error if the device is not paired or if the service cannot
        be started due to various conditions (e.g., password-protected device).

        :param name: The name of the service for which the connection attributes are being retrieved.
        :type name: str
        :param include_escrow_bag: Flag indicating whether to include the escrow bag in the request. Defaults to False.
        :type include_escrow_bag: bool
        :return: A dictionary containing the service connection attributes.
        :rtype: dict
        :raises NotPairedError: The device is not paired.
        :raises PasswordRequiredError: The device is password-protected, and a password needs to be entered.
        :raises StartServiceError: The service could not be started due to an error.
        """
        if not self.paired:
            raise NotPairedError()

        options = {"Service": name}
        if include_escrow_bag:
            options["EscrowBag"] = self.pair_record["EscrowBag"]

        response = await self._request("StartService", options)
        if not response or response.get("Error"):
            if response.get("Error", "") == "PasswordProtected":
                raise PasswordRequiredError(
                    "your device is protected with password, please enter password in device and try again"
                )
            raise StartServiceError(name, response.get("Error"))
        return response

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        """
        Starts a lockdown service connection using the specified service name and optional escrow bag setting.

        This asynchronous method retrieves the service connection attributes using the service name and
        escrow bag flag, creates a new service connection using the specified port, and optionally
        configures SSL if enabled for the service.

        :param name: The name of the service to start the lockdown connection for.
        :param include_escrow_bag: Determines whether the escrow bag should be included when retrieving
            service connection attributes. Default is False.
        :return: An instance of ServiceConnection representing the established connection.
        :rtype: ServiceConnection
        """
        attr = await self.get_service_connection_attributes(name, include_escrow_bag=include_escrow_bag)
        service_connection = await self.create_service_connection(attr["Port"])

        if attr.get("EnableServiceSSL", False):
            with self.ssl_file() as f:
                await service_connection.ssl_start(f)
        return service_connection

    async def close(self) -> None:
        """
        Closes the associated service.

        This method is used to close and clean up any resources associated with
        the service being used. It is intended to be invoked when the service
        is no longer needed, ensuring that resources are released properly.

        This is an asynchronous operation.

        :return: None
        """
        await self.service.close()

    @contextmanager
    def ssl_file(self) -> Generator[str, Any, None]:
        """
        Context manager that temporarily creates a file containing both the
        certificate and private key PEM data from the pair_record for SSL usage.

        The context manager ensures that the file is cleaned up after use,
        even in the event of an exception. On Windows systems, it avoids
        issues with in-use files by managing the file deletion manually.

        :param Generator[str, Any, None]: A generator that yields the filename
            of the temporary SSL file.

        :yield: The path to the temporary file containing the concatenated
            certificate and private key PEM data.
        """
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
        :type autopair: bool
        :param timeout: Timeout.
        :type timeout: Optional[float]
        :param private_key: Private key. Defaults to None.
        :type private_key: Optional[RSAPrivateKey]

        :return: None.
        :rtype: None
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
        """
        Abstract method responsible for establishing a service connection to a specified
        port. This method must be implemented by subclasses and is used to create a
        connection to a service, enabling communication or data transfer between systems.
        The implementation is expected to handle the required connection protocols
        specific to the service.

        :param port: The port number to which the service connection should be established.
                     Must be a valid integer representing a network/service port.
        :type port: int
        :return: An instance of ServiceConnection representing the established
                 connection to the desired port.
        :rtype: ServiceConnection
        """
        pass

    async def _create_service_connection(self, port: int) -> ServiceConnection:
        """
        Establishes a service connection asynchronously.

        This function is used to create and establish a connection to a service
        using the specified port. It utilizes the `create_service_connection`
        method to perform the actual connection process.

        :param port: The port number to be used for the service connection.
        :type port: int
        :return: An instance of ServiceConnection representing the established
            connection.
        :rtype: ServiceConnection
        """
        return await self.create_service_connection(port)

    async def _request(self, request: str, options: Optional[dict] = None, verify_request: bool = True) -> dict:
        """
        Sends a request to the associated service, processes the response, and verifies
        the result. Reconnects and retries the request if a connection-related error
        occurs.

        :param request: The request string containing the operation or data to be sent.
        :type request: str
        :param options: Additional options to include in the request message, defaults
            to None.
        :type options: Optional[dict]
        :param verify_request: Indicates whether to verify the response after receiving
            it, defaults to True.
        :type verify_request: bool
        :return: The processed response received from the service.
        :rtype: dict
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

    def _verify_request_response(self, request: str, response: dict, *, verify_request: bool = True) -> dict:
        """Internal helper for verify request response.

        :param request: Request.
        :type request: str
        :param response: Response.
        :type response: dict
        :param verify_request: Verify request. Defaults to True.
        :type verify_request: bool

        :return: Result of the operation.
        :rtype: dict
        """
        if verify_request and response.get("Request") != request:
            if response.get("Type") == RESTORED_SERVICE_TYPE:
                raise IncorrectModeError(f"Incorrect mode returned. Got: {response}")
            raise LockdownError(f"Incorrect response returned. Got: {response}")

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
            raise exception_errors.get(error, LockdownError)(error, self.identifier)

        # iOS < 5: 'Error' is not present, so we need to check the 'Result' instead
        if response.get("Result") == "Failure":
            raise LockdownError("", self.identifier)

        return response

    async def _request_pair(self, pair_options: dict, timeout: Optional[float] = None) -> dict:
        """
        Asynchronously requests pairing using the provided pair options. This method handles
        pairing dialog responses and waits for user input within the given timeout period.
        If the timeout elapses or certain conditions are met, it raises an error accordingly.

        :param pair_options: A dictionary containing the options required for the pairing request.
        :type pair_options: dict
        :param timeout: An optional timeout value (in seconds) indicating how long
            to wait for user input. If None, waits indefinitely.
            A value of 0 skips waiting and raises an error immediately.
        :type timeout: Optional[float]
        :return: A dictionary representing the response of the pairing request.
        :rtype: dict
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
        """
        Fetches the record for the specified pairing identifier and assigns it to the
        `pair_record` attribute. This method retrieves the preferred pairing record
        asynchronously and stores it for subsequent use. If the `identifier` attribute
        is not set, the method will not perform any action.

        :param self: Instance of the class containing the attributes required
            for this operation.

        :return: This method does not return any value.
        """
        if self.identifier is not None:
            self.pair_record = await get_preferred_pair_record(self.identifier, self.pairing_records_cache_folder)

    async def save_pair_record(self) -> None:
        """
        Saves the pairing record to a specified file in the pairing records cache folder.

        The method builds the file path using the `pairing_records_cache_folder` and
        the `identifier`, and then writes the serialized pairing record data to this file
        in plist format. This helps in persisting the pairing record for future use.

        :return: None
        """
        pair_record_file = self.pairing_records_cache_folder / f"{self.identifier}.plist"
        pair_record_file.write_bytes(plistlib.dumps(self.pair_record))

    def _reestablish_connection(self) -> None:
        """Internal helper for reestablish connection.

        :return: None.
        :rtype: None
        """
        raise RuntimeError("Sync reconnection path was removed. Use asyncio APIs.")

    async def areestablish_connection(self) -> None:
        """
        Reestablishes the connection by closing the current session, resetting the session,
        and initiating a new service connection. The pairing status is also revalidated if
        a pair record exists.

        :return: None
        """
        await self.close()
        self.session_id = None
        self.service = await self.create_service_connection(self.port)
        self.paired = False
        if self.pair_record is not None:
            await self.validate_pairing()


class UsbmuxLockdownClient(LockdownClient):
    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
        usbmux_address: Optional[str] = None,
    ):
        """Initialize a new UsbmuxLockdownClient instance.

        :param service: Service.
        :type service: ServiceConnection
        :param host_id: Host id.
        :type host_id: str
        :param identifier: Identifier. Defaults to None.
        :type identifier: Optional[str]
        :param label: Label. Defaults to DEFAULT_LABEL.
        :type label: str
        :param system_buid: System buid. Defaults to SYSTEM_BUID.
        :type system_buid: str
        :param pair_record: Pair record. Defaults to None.
        :type pair_record: Optional[dict]
        :param pairing_records_cache_folder: Pairing records cache folder. Defaults to None.
        :type pairing_records_cache_folder: Optional[Path]
        :param port: Port. Defaults to SERVICE_PORT.
        :type port: int
        :param usbmux_address: Usbmux address. Defaults to None.
        :type usbmux_address: Optional[str]

        :return: Result of the operation.
        :rtype: Any
        """
        self.usbmux_address = usbmux_address
        super().__init__(
            service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder, port
        )

    @property
    def short_info(self) -> dict:
        """Short info.

        :return: Result of the operation.
        :rtype: dict
        """
        short_info = super().short_info
        short_info["ConnectionType"] = self.service.mux_device.connection_type
        return short_info

    async def fetch_pair_record(self) -> None:
        """
        Fetches and sets the preferred pair record for the current identifier.

        This asynchronous method attempts to retrieve the preferred pair record
        associated with the given identifier. If the identifier is not ``None``, it
        fetches the pair record using the provided cache folder and usbmux address
        (if specified) and assigns it to the `pair_record` attribute.

        :return: None
        """
        if self.identifier is not None:
            self.pair_record = await get_preferred_pair_record(
                self.identifier, self.pairing_records_cache_folder, usbmux_address=self.usbmux_address
            )

    async def create_service_connection(self, port: int) -> ServiceConnection:
        """
        Establishes an asynchronous service connection using USBMux. This method initializes
        a ServiceConnection instance by leveraging the `create_using_usbmux` factory method.

        :param port: The port number to establish the service connection on.
        :type port: int
        :return: An instance of ServiceConnection established using USBMux.
        :rtype: ServiceConnection
        """
        return await ServiceConnection.create_using_usbmux(
            self.identifier, port, self.service.mux_device.connection_type, usbmux_address=self.usbmux_address
        )


class PlistUsbmuxLockdownClient(UsbmuxLockdownClient):
    async def save_pair_record(self) -> None:
        """
        Saves the current pair record for the device asynchronously.

        This method serializes the pair record using the `plistlib` library and then
        saves it using the USBMux client. The operation is performed asynchronously
        to ensure the system remains responsive during the IO process.

        Raises an exception if the pair record cannot be serialized or saved
        successfully.

        :return: None
        """
        await super().save_pair_record()
        record_data = plistlib.dumps(self.pair_record)
        async with await usbmux.create_mux() as client:
            await client.save_pair_record(self.identifier, self.service.mux_device.devid, record_data)


class TcpLockdownClient(LockdownClient):
    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        hostname: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
        keep_alive: bool = True,
    ):
        """Initialize a new TcpLockdownClient instance.

        :param service: Service.
        :type service: ServiceConnection
        :param host_id: Host id.
        :type host_id: str
        :param hostname: Hostname.
        :type hostname: str
        :param identifier: Identifier. Defaults to None.
        :type identifier: Optional[str]
        :param label: Label. Defaults to DEFAULT_LABEL.
        :type label: str
        :param system_buid: System buid. Defaults to SYSTEM_BUID.
        :type system_buid: str
        :param pair_record: Pair record. Defaults to None.
        :type pair_record: Optional[dict]
        :param pairing_records_cache_folder: Pairing records cache folder. Defaults to None.
        :type pairing_records_cache_folder: Optional[Path]
        :param port: Port. Defaults to SERVICE_PORT.
        :type port: int
        :param keep_alive: Keep alive. Defaults to True.
        :type keep_alive: bool

        :return: Result of the operation.
        :rtype: Any
        """
        super().__init__(
            service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder, port
        )
        self._keep_alive = keep_alive
        self.hostname = hostname
        self.identifier = hostname

    async def create_service_connection(self, port: int) -> ServiceConnection:
        """Create service connection.

        :param port: Port.
        :type port: int

        :return: Result of the operation.
        :rtype: ServiceConnection
        """
        return await ServiceConnection.create_using_tcp(self.hostname, port, keep_alive=self._keep_alive)


class RemoteLockdownClient(LockdownClient):
    async def create_service_connection(self, port: int) -> ServiceConnection:
        """Create service connection.

        :param port: Port.
        :type port: int

        :return: Result of the operation.
        :rtype: ServiceConnection
        """
        raise NotImplementedError(
            "RemoteXPC service connections should only be created using RemoteServiceDiscoveryService"
        )

    async def _handle_autopair(self, *args, **kwargs):
        # The RemoteXPC version of lockdown doesn't support pairing operations
        """Internal helper for handle autopair.

        :param *args: Additional positional arguments.
        :type *args: Any
        :param **kwargs: Additional keyword arguments.
        :type **kwargs: Any

        :return: Result of the operation.
        :rtype: Any
        """
        return None

    async def pair(self, *args, **kwargs) -> None:
        """Pair.

        :param *args: Additional positional arguments.
        :type *args: Any
        :param **kwargs: Additional keyword arguments.
        :type **kwargs: Any

        :return: None.
        :rtype: None
        """
        raise NotImplementedError("RemoteXPC lockdown version does not support pairing operations")

    async def unpair(self, timeout: Optional[float] = None) -> None:
        """Unpair.

        :param timeout: Timeout. Defaults to None.
        :type timeout: Optional[float]

        :return: None.
        :rtype: None
        """
        raise NotImplementedError("RemoteXPC lockdown version does not support pairing operations")

    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier: Optional[str] = None,
        label: str = DEFAULT_LABEL,
        system_buid: str = SYSTEM_BUID,
        pair_record: Optional[dict] = None,
        pairing_records_cache_folder: Optional[Path] = None,
        port: int = SERVICE_PORT,
    ):
        """Initialize a new RemoteLockdownClient instance.

        :param service: Service.
        :type service: ServiceConnection
        :param host_id: Host id.
        :type host_id: str
        :param identifier: Identifier. Defaults to None.
        :type identifier: Optional[str]
        :param label: Label. Defaults to DEFAULT_LABEL.
        :type label: str
        :param system_buid: System buid. Defaults to SYSTEM_BUID.
        :type system_buid: str
        :param pair_record: Pair record. Defaults to None.
        :type pair_record: Optional[dict]
        :param pairing_records_cache_folder: Pairing records cache folder. Defaults to None.
        :type pairing_records_cache_folder: Optional[Path]
        :param port: Port. Defaults to SERVICE_PORT.
        :type port: int

        :return: Result of the operation.
        :rtype: Any
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
    pair_record: Optional[dict] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    port: int = SERVICE_PORT,
    usbmux_address: Optional[str] = None,
) -> UsbmuxLockdownClient:
    """
    Create a UsbmuxLockdownClient instance

    :param serial: Usbmux serial identifier
    :param identifier: Used as an identifier to look for the device pair record
    :param label: lockdownd user-agent
    :param autopair: Attempt to pair with device (blocking) if not already paired
    :param connection_type: Force a specific type of usbmux connection (USB/Network)
    :param pair_timeout: Timeout for autopair
    :param local_hostname: Used as a seed to generate the HostID
    :param pair_record: Use this pair record instead of the default behavior (search in host/create our own)
    :param pairing_records_cache_folder: Use the following location to search and save pair records
    :param port: lockdownd service port
    :param usbmux_address: usbmuxd address
    :return: UsbmuxLockdownClient instance
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

        if identifier is None:
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


async def retry_create_using_usbmux(retry_timeout: Optional[float] = None, **kwargs) -> UsbmuxLockdownClient:
    """
    Repeatedly retry to create a UsbmuxLockdownClient instance while dismissing different errors that might occur
    while device is rebooting

    :param retry_timeout: Retry timeout in seconds or None for no timeout
    :return: UsbmuxLockdownClient instance
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
            construct.core.StreamError,
            DeviceNotFoundError,
            IncompleteReadError,
        ):
            pass


async def create_using_tcp(
    hostname: str,
    identifier: Optional[str] = None,
    label: str = DEFAULT_LABEL,
    autopair: bool = True,
    pair_timeout: Optional[float] = None,
    local_hostname: Optional[str] = None,
    pair_record: Optional[dict] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    port: int = SERVICE_PORT,
    keep_alive: bool = False,
) -> TcpLockdownClient:
    """
    Create a TcpLockdownClient instance

    :param hostname: The target device hostname
    :param identifier: Used as an identifier to look for the device pair record
    :param label: lockdownd user-agent
    :param autopair: Attempt to pair with device (blocking) if not already paired
    :param pair_timeout: Timeout for autopair
    :param local_hostname: Used as a seed to generate the HostID
    :param pair_record: Use this pair record instead of the default behavior (search in host/create our own)
    :param pairing_records_cache_folder: Use the following location to search and save pair records
    :param port: lockdownd service port
    :param keep_alive: use keep-alive to get notified when the connection is lost
    :return: TcpLockdownClient instance
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
    pair_record: Optional[dict] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    port: int = SERVICE_PORT,
) -> RemoteLockdownClient:
    """
    Create a TcpLockdownClient instance over RSD

    :param service: service connection to use
    :param identifier: Used as an identifier to look for the device pair record
    :param label: lockdownd user-agent
    :param autopair: Attempt to pair with device (blocking) if not already paired
    :param pair_timeout: Timeout for autopair
    :param local_hostname: Used as a seed to generate the HostID
    :param pair_record: Use this pair record instead of the default behavior (search in host/create our own)
    :param pairing_records_cache_folder: Use the following location to search and save pair records
    :param port: lockdownd service port
    :return: TcpLockdownClient instance
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
