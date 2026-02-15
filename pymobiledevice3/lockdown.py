#!/usr/bin/env python3
import asyncio
import datetime
import logging
import os
import plistlib
import socket
import tempfile
import time
from abc import ABC, abstractmethod
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
    PyMobileDevice3Exception,
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
        """
        Create a LockdownClient instance

        :param service: lockdownd connection handler
        :param host_id: Used as the host identifier for the handshake
        :param identifier: Used as an identifier to look for the device pair record
        :param label: lockdownd user-agent
        :param system_buid: System's unique identifier
        :param pair_record: Use this pair record instead of the default behavior (search in host/create our own)
        :param pairing_records_cache_folder: Use the following location to search and save pair records
        :param port: lockdownd service port
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
        """
        Create a LockdownClient instance

        :param service: lockdownd connection handler
        :param identifier: Used as an identifier to look for the device pair record
        :param system_buid: System's unique identifier
        :param label: lockdownd user-agent
        :param autopair: Attempt to pair with device (blocking) if not already paired
        :param pair_timeout: Timeout for autopair
        :param local_hostname: Used as a seed to generate the HostID
        :param pair_record: Use this pair record instead of the default behavior (search in host/create our own)
        :param pairing_records_cache_folder: Use the following location to search and save pair records
        :param port: lockdownd service port
        :param private_key: Used to pass custom RSA key for pairing purposes, if None it will be autogenerated
        :param cls_specific_args: Additional members to pass into LockdownClient subclasses
        :return: LockdownClient subclass
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
        if (await self.query_type()) != "com.apple.mobile.lockdown":
            raise IncorrectModeError()
        self.all_values = await self.get_value()
        self.udid = self.all_values.get("UniqueDeviceID")
        self.unique_chip_id = self.all_values.get("UniqueChipID")
        self.device_public_key = self.all_values.get("DevicePublicKey")
        self.product_type = self.all_values.get("ProductType")

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} ID:{self.identifier} VERSION:{self.product_version} "
            f"TYPE:{self.product_type} PAIRED:{self.paired}>"
        )

    async def __aenter__(self) -> "LockdownClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    @property
    def product_version(self) -> str:
        return self.all_values.get("ProductVersion") or "1.0"

    @property
    def product_build_version(self) -> str:
        return self.all_values.get("BuildVersion")

    @property
    def device_class(self) -> DeviceClass:
        try:
            return DeviceClass(self.all_values.get("DeviceClass"))
        except ValueError:
            return DeviceClass("Unknown")

    @property
    def wifi_mac_address(self) -> str:
        return self.all_values.get("WiFiAddress")

    @property
    def short_info(self) -> dict:
        keys_to_copy = ["DeviceClass", "DeviceName", "BuildVersion", "ProductVersion", "ProductType", "UniqueDeviceID"]
        result = {
            "Identifier": self.identifier,
        }
        for key in keys_to_copy:
            result[key] = self.all_values.get(key)
        return result

    @property
    def share_iphone_analytics_enabled(self) -> bool:
        return bool(self._domain_values("com.apple.MobileDeviceCrashCopy").get("ShouldSubmit", False))

    @property
    def assistive_touch(self) -> bool:
        """AssistiveTouch (the on-screen software home button)"""
        return bool(self._domain_values("com.apple.Accessibility").get("AssistiveTouchEnabledByiTunes", 0))

    @assistive_touch.setter
    def assistive_touch(self, value: bool) -> None:
        raise RuntimeError("Use async set_assistive_touch()")

    @property
    def voice_over(self) -> bool:
        return bool(self._domain_values("com.apple.Accessibility").get("VoiceOverTouchEnabledByiTunes", 0))

    @voice_over.setter
    def voice_over(self, value: bool) -> None:
        raise RuntimeError("Use async set_voice_over()")

    @property
    def invert_display(self) -> bool:
        return bool(self._domain_values("com.apple.Accessibility").get("InvertDisplayEnabledByiTunes", 0))

    @invert_display.setter
    def invert_display(self, value: bool) -> None:
        raise RuntimeError("Use async set_invert_display()")

    @property
    def enable_wifi_connections(self) -> bool:
        return self._domain_values("com.apple.mobile.wireless_lockdown").get("EnableWifiConnections", False)

    @enable_wifi_connections.setter
    def enable_wifi_connections(self, value: bool) -> None:
        raise RuntimeError("Use async set_enable_wifi_connections()")

    @property
    def ecid(self) -> int:
        return self.all_values["UniqueChipID"]

    def language(self) -> str:
        return self._domain_values("com.apple.international").get("Language", "")

    @property
    def locale(self) -> str:
        return self._domain_values("com.apple.international").get("Locale", "")

    @property
    def preflight_info(self) -> dict:
        return self.all_values.get("PreflightInfo")

    @property
    def firmware_preflight_info(self) -> dict:
        return self.all_values.get("FirmwarePreflightInfo")

    @property
    def display_name(self) -> str:
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.display_name

    @property
    def hardware_model(self) -> str:
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.hardware_model

    @property
    def board_id(self) -> int:
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.board_id

    @property
    def chip_id(self) -> int:
        for irecv_device in IRECV_DEVICES:
            if irecv_device.product_type == self.product_type:
                return irecv_device.chip_id

    def _domain_values(self, domain: str) -> dict:
        values = self.all_values.get(domain, {})
        return values if isinstance(values, dict) else {}

    async def query_type(self) -> str:
        return (await self._request_async("QueryType")).get("Type")

    async def set_language(self, language: str) -> None:
        await self.set_value(language, key="Language", domain="com.apple.international")

    async def get_language(self) -> str:
        value = await self.get_value(domain="com.apple.international", key="Language")
        return value if isinstance(value, str) else ""

    async def set_locale(self, locale: str) -> None:
        await self.set_value(locale, key="Locale", domain="com.apple.international")

    async def get_locale(self) -> str:
        value = await self.get_value(domain="com.apple.international", key="Locale")
        return value if isinstance(value, str) else ""

    async def set_timezone(self, timezone: str) -> None:
        await self.set_value(timezone, key="TimeZone")

    async def set_uses24h_clock(self, value: bool) -> None:
        await self.set_value(value, key="Uses24HourClock")

    async def set_uses24hClock(self, value: bool) -> None:
        await self.set_uses24h_clock(value)

    async def set_assistive_touch(self, value: bool) -> None:
        await self.set_value(int(value), "com.apple.Accessibility", "AssistiveTouchEnabledByiTunes")

    async def get_assistive_touch(self) -> bool:
        value = await self.get_value(domain="com.apple.Accessibility", key="AssistiveTouchEnabledByiTunes")
        return bool(value)

    async def set_voice_over(self, value: bool) -> None:
        await self.set_value(int(value), "com.apple.Accessibility", "VoiceOverTouchEnabledByiTunes")

    async def get_voice_over(self) -> bool:
        value = await self.get_value(domain="com.apple.Accessibility", key="VoiceOverTouchEnabledByiTunes")
        return bool(value)

    async def set_invert_display(self, value: bool) -> None:
        await self.set_value(int(value), "com.apple.Accessibility", "InvertDisplayEnabledByiTunes")

    async def get_invert_display(self) -> bool:
        value = await self.get_value(domain="com.apple.Accessibility", key="InvertDisplayEnabledByiTunes")
        return bool(value)

    async def set_enable_wifi_connections(self, value: bool) -> None:
        await self.set_value(value, "com.apple.mobile.wireless_lockdown", "EnableWifiConnections")

    async def get_enable_wifi_connections(self) -> bool:
        value = await self.get_value(domain="com.apple.mobile.wireless_lockdown", key="EnableWifiConnections")
        return bool(value)

    async def get_developer_mode_status(self) -> bool:
        value = await self.get_value(domain="com.apple.security.mac.amfi", key="DeveloperModeStatus")
        return bool(value)

    async def get_date(self) -> datetime.datetime:
        timestamp = await self.get_value(key="TimeIntervalSince1970")
        return datetime.datetime.fromtimestamp(timestamp or 0)

    async def enter_recovery(self):
        return await self._request_async("EnterRecovery")

    async def stop_session(self) -> dict:
        if self.session_id and self.service:
            response = await self._request_async("StopSession", {"SessionID": self.session_id})
            self.session_id = None
            if not response or response.get("Result") != "Success":
                raise CannotStopSessionError()
            return response
        raise PyMobileDevice3Exception("No active session")

    async def validate_pairing(self) -> bool:
        if self.pair_record is None:
            await self.fetch_pair_record()

        if self.pair_record is None:
            return False

        if (Version(self.product_version) < Version("7.0")) and (self.device_class != DeviceClass.WATCH):
            try:
                await self._request_async("ValidatePair", {"PairRecord": self.pair_record})
            except PairingError:
                return False

        self.host_id = self.pair_record.get("HostID", self.host_id)
        self.system_buid = self.pair_record.get("SystemBUID", self.system_buid)

        try:
            start_session = await self._request_async(
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
        pair_record = self.pair_record if host_id is None else {"HostID": host_id}
        await self._request_async("Unpair", {"PairRecord": pair_record, "ProtocolVersion": "2"}, verify_request=False)

    async def reset_pairing(self):
        return await self._request_async("ResetPairing", {"FullReset": True})

    async def get_value(self, domain: Optional[str] = None, key: Optional[str] = None):
        options = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        res = await self._request_async("GetValue", options)
        if res:
            r = res.get("Value")
            if hasattr(r, "data"):
                return r.data
            if domain is None and key is None and isinstance(r, dict):
                self.all_values = r
            return r

    async def remove_value(self, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        options = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        result = await self._request_async("RemoveValue", options)
        if domain and key:
            domain_values = self._domain_values(domain)
            domain_values.pop(key, None)
            self.all_values[domain] = domain_values
        elif key:
            self.all_values.pop(key, None)
        return result

    async def set_value(self, value, domain: Optional[str] = None, key: Optional[str] = None) -> dict:
        options = {}
        if domain:
            options["Domain"] = domain
        if key:
            options["Key"] = key
        options["Value"] = value
        result = await self._request_async("SetValue", options)
        if domain and key:
            domain_values = self._domain_values(domain)
            domain_values[key] = value
            self.all_values[domain] = domain_values
        elif key:
            self.all_values[key] = value
        return result

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict:
        if not self.paired:
            raise NotPairedError()

        options = {"Service": name}
        if include_escrow_bag:
            options["EscrowBag"] = self.pair_record["EscrowBag"]

        response = await self._request_async("StartService", options)
        if not response or response.get("Error"):
            if response.get("Error", "") == "PasswordProtected":
                raise PasswordRequiredError(
                    "your device is protected with password, please enter password in device and try again"
                )
            raise StartServiceError(name, response.get("Error"))
        return response

    async def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        attr = await self.get_service_connection_attributes(name, include_escrow_bag=include_escrow_bag)
        service_connection = await self.create_service_connection(attr["Port"])

        if attr.get("EnableServiceSSL", False):
            with self.ssl_file() as f:
                await service_connection.ssl_start(f)
        return service_connection

    async def close(self) -> None:
        await self.service.close()

    @contextmanager
    def ssl_file(self) -> Generator[str, Any, None]:
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
        """Used to establish a new ServiceConnection to a given port."""
        pass

    async def _create_service_connection(self, port: int) -> ServiceConnection:
        """Backward-compatible alias. Prefer `create_service_connection()`."""
        return await self.create_service_connection(port)

    async def _request_async(self, request: str, options: Optional[dict] = None, verify_request: bool = True) -> dict:
        message = {"Label": self.label, "Request": request}
        if options:
            message.update(options)
        try:
            response = await self.service.send_recv_plist(message)
        except (ConnectionResetError, ConnectionAbortedError, RuntimeError) as e:
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
        try:
            return await self._request_async("Pair", pair_options)
        except PairingDialogResponsePendingError:
            if timeout == 0:
                raise

        self.logger.info("waiting user pairing dialog...")
        start = time.time()
        while timeout is None or time.time() <= start + timeout:
            with suppress(PairingDialogResponsePendingError):
                return await self._request_async("Pair", pair_options)
            await asyncio.sleep(1)
        raise PairingDialogResponsePendingError()

    async def fetch_pair_record(self) -> None:
        if self.identifier is not None:
            self.pair_record = await get_preferred_pair_record(self.identifier, self.pairing_records_cache_folder)

    async def save_pair_record(self) -> None:
        pair_record_file = self.pairing_records_cache_folder / f"{self.identifier}.plist"
        pair_record_file.write_bytes(plistlib.dumps(self.pair_record))

    def _reestablish_connection(self) -> None:
        raise RuntimeError("Sync reconnection path was removed. Use asyncio APIs.")

    async def areestablish_connection(self) -> None:
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
        self.usbmux_address = usbmux_address
        super().__init__(
            service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder, port
        )

    @property
    def short_info(self) -> dict:
        short_info = super().short_info
        short_info["ConnectionType"] = self.service.mux_device.connection_type
        return short_info

    async def fetch_pair_record(self) -> None:
        if self.identifier is not None:
            self.pair_record = await get_preferred_pair_record(
                self.identifier, self.pairing_records_cache_folder, usbmux_address=self.usbmux_address
            )

    async def create_service_connection(self, port: int) -> ServiceConnection:
        return await ServiceConnection.create_using_usbmux(
            self.identifier, port, self.service.mux_device.connection_type, usbmux_address=self.usbmux_address
        )


class PlistUsbmuxLockdownClient(UsbmuxLockdownClient):
    async def save_pair_record(self) -> None:
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
        """
        Create a LockdownClient instance

        :param service: lockdownd connection handler
        :param host_id: Used as the host identifier for the handshake
        :param hostname: The target hostname
        :param identifier: Used as an identifier to look for the device pair record
        :param label: lockdownd user-agent
        :param system_buid: System's unique identifier
        :param pair_record: Use this pair record instead of the default behavior (search in host/create our own)
        :param pairing_records_cache_folder: Use the following location to search and save pair records
        :param port: lockdownd service port
        :param keep_alive: use keep-alive to get notified when the connection is lost
        """
        super().__init__(
            service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder, port
        )
        self._keep_alive = keep_alive
        self.hostname = hostname
        self.identifier = hostname

    async def create_service_connection(self, port: int) -> ServiceConnection:
        return await ServiceConnection.create_using_tcp(self.hostname, port, keep_alive=self._keep_alive)


class RemoteLockdownClient(LockdownClient):
    async def create_service_connection(self, port: int) -> ServiceConnection:
        raise NotImplementedError(
            "RemoteXPC service connections should only be created using RemoteServiceDiscoveryService"
        )

    async def _handle_autopair(self, *args, **kwargs):
        # The RemoteXPC version of lockdown doesn't support pairing operations
        return None

    async def pair(self, *args, **kwargs) -> None:
        raise NotImplementedError("RemoteXPC lockdown version does not support pairing operations")

    async def unpair(self, timeout: Optional[float] = None) -> None:
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
        """
        Create a LockdownClient instance

        :param service: lockdownd connection handler
        :param host_id: Used as the host identifier for the handshake
        :param identifier: Used as an identifier to look for the device pair record
        :param label: lockdownd user-agent
        :param system_buid: System's unique identifier
        :param pair_record: Use this pair record instead of the default behavior (search in host/create our own)
        :param pairing_records_cache_folder: Use the following location to search and save pair records
        :param port: lockdownd service port
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
