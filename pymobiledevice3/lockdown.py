#!/usr/bin/env python3
import datetime
import logging
import os
import plistlib
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager, suppress
from enum import Enum
from functools import wraps
from pathlib import Path
from ssl import SSLError, SSLZeroReturnError
from typing import AsyncIterable, Optional

import construct
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder
from packaging.version import Version

from pymobiledevice3 import usbmux
from pymobiledevice3.bonjour import DEFAULT_BONJOUR_TIMEOUT, browse_mobdev2
from pymobiledevice3.ca import ca_do_everything
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import BadDevError, CannotStopSessionError, ConnectionFailedError, \
    ConnectionTerminatedError, DeviceNotFoundError, FatalPairingError, GetProhibitedError, IncorrectModeError, \
    InvalidConnectionError, InvalidHostIDError, InvalidServiceError, LockdownError, MissingValueError, \
    NoDeviceConnectedError, NotPairedError, PairingDialogResponsePendingError, PairingError, PasswordRequiredError, \
    SetProhibitedError, StartServiceError, UserDeniedPairingError
from pymobiledevice3.irecv_devices import IRECV_DEVICES
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.pair_records import create_pairing_records_cache_folder, generate_host_id, \
    get_preferred_pair_record
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.usbmux import PlistMuxConnection

SYSTEM_BUID = '30142955-444094379208051516'
RESTORED_SERVICE_TYPE = 'com.apple.mobile.restored'

DEFAULT_LABEL = 'pymobiledevice3'
SERVICE_PORT = 62078


class DeviceClass(Enum):
    IPHONE = 'iPhone'
    IPAD = 'iPad'
    IPOD = 'iPod'
    WATCH = 'Watch'
    APPLE_TV = 'AppleTV'
    UNKNOWN = 'Unknown'


def _reconnect_on_remote_close(f):
    """
    lockdownd's _socket_select will close the connection after 60 seconds of "radio-silent" (no data has been
    transmitted). When this happens, we'll attempt to reconnect.
    """

    def _reconnect(self: 'LockdownClient'):
        self._reestablish_connection()
        self.validate_pairing()

    @wraps(f)
    def _inner_reconnect_on_remote_close(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (BrokenPipeError, ConnectionTerminatedError, SSLError):
            _reconnect(args[0])
            return f(*args, **kwargs)
        except ConnectionAbortedError:
            if sys.platform != 'win32':
                raise
            _reconnect(args[0])
            return f(*args, **kwargs)

    return _inner_reconnect_on_remote_close


class LockdownClient(ABC, LockdownServiceProvider):
    def __init__(self, service: ServiceConnection, host_id: str, identifier: str = None,
                 label: str = DEFAULT_LABEL, system_buid: str = SYSTEM_BUID, pair_record: Optional[dict] = None,
                 pairing_records_cache_folder: Path = None, port: int = SERVICE_PORT):
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

        if self.query_type() != 'com.apple.mobile.lockdown':
            raise IncorrectModeError()

        self.all_values = self.get_value()
        self.udid = self.all_values.get('UniqueDeviceID')
        self.unique_chip_id = self.all_values.get('UniqueChipID')
        self.device_public_key = self.all_values.get('DevicePublicKey')
        self.product_type = self.all_values.get('ProductType')

    @classmethod
    def create(cls, service: ServiceConnection, identifier: str = None, system_buid: str = SYSTEM_BUID,
               label: str = DEFAULT_LABEL, autopair: bool = True, pair_timeout: float = None,
               local_hostname: str = None,
               pair_record: Optional[dict] = None, pairing_records_cache_folder: Path = None, port: int = SERVICE_PORT,
               private_key: Optional[RSAPrivateKey] = None, **cls_specific_args):
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
            service, host_id=host_id, identifier=identifier, label=label, system_buid=system_buid,
            pair_record=pair_record, pairing_records_cache_folder=pairing_records_cache_folder, port=port,
            **cls_specific_args)
        lockdown_client._handle_autopair(autopair, pair_timeout, private_key=private_key)
        return lockdown_client

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} ID:{self.identifier} VERSION:{self.product_version} ' \
               f'TYPE:{self.product_type} PAIRED:{self.paired}>'

    def __enter__(self) -> 'LockdownClient':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    async def __aenter__(self) -> 'LockdownClient':
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @property
    def product_version(self) -> str:
        return self.all_values.get('ProductVersion')

    @property
    def device_class(self) -> DeviceClass:
        try:
            return DeviceClass(self.all_values.get('DeviceClass'))
        except ValueError:
            return DeviceClass('Unknown')

    @property
    def wifi_mac_address(self) -> str:
        return self.all_values.get('WiFiAddress')

    @property
    def short_info(self) -> dict:
        keys_to_copy = ['DeviceClass', 'DeviceName', 'BuildVersion', 'ProductVersion', 'ProductType', 'UniqueDeviceID']
        result = {
            'Identifier': self.identifier,
        }
        for key in keys_to_copy:
            result[key] = self.all_values.get(key)
        return result

    @property
    def share_iphone_analytics_enabled(self) -> bool:
        return self.get_value('com.apple.MobileDeviceCrashCopy', 'ShouldSubmit')

    @property
    def assistive_touch(self) -> bool:
        """AssistiveTouch (the on-screen software home button)"""
        return bool(self.get_value('com.apple.Accessibility').get('AssistiveTouchEnabledByiTunes', 0))

    @assistive_touch.setter
    def assistive_touch(self, value: bool) -> None:
        """AssistiveTouch (the on-screen software home button)"""
        self.set_value(int(value), 'com.apple.Accessibility', 'AssistiveTouchEnabledByiTunes')

    @property
    def voice_over(self) -> bool:
        return bool(self.get_value('com.apple.Accessibility').get('VoiceOverTouchEnabledByiTunes', 0))

    @voice_over.setter
    def voice_over(self, value: bool) -> None:
        self.set_value(int(value), 'com.apple.Accessibility', 'VoiceOverTouchEnabledByiTunes')

    @property
    def invert_display(self) -> bool:
        return bool(self.get_value('com.apple.Accessibility').get('InvertDisplayEnabledByiTunes', 0))

    @invert_display.setter
    def invert_display(self, value: bool) -> None:
        self.set_value(int(value), 'com.apple.Accessibility', 'InvertDisplayEnabledByiTunes')

    @property
    def enable_wifi_connections(self) -> bool:
        return self.get_value('com.apple.mobile.wireless_lockdown').get('EnableWifiConnections', False)

    @enable_wifi_connections.setter
    def enable_wifi_connections(self, value: bool) -> None:
        self.set_value(value, 'com.apple.mobile.wireless_lockdown', 'EnableWifiConnections')

    @property
    def ecid(self) -> int:
        return self.all_values['UniqueChipID']

    @property
    def date(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.get_value(key='TimeIntervalSince1970'))

    @property
    def language(self) -> str:
        return self.get_value(key='Language', domain='com.apple.international')

    @property
    def locale(self) -> str:
        return self.get_value(key='Locale', domain='com.apple.international')

    @property
    def preflight_info(self) -> dict:
        return self.get_value(key='FirmwarePreflightInfo')

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

    @property
    def developer_mode_status(self) -> bool:
        return self.get_value('com.apple.security.mac.amfi', 'DeveloperModeStatus')

    def query_type(self) -> str:
        return self._request('QueryType').get('Type')

    def set_language(self, language: str) -> None:
        self.set_value(language, key='Language', domain='com.apple.international')

    def set_locale(self, locale: str) -> None:
        self.set_value(locale, key='Locale', domain='com.apple.international')

    def set_timezone(self, timezone: str) -> None:
        self.set_value(timezone, key='TimeZone')

    def set_uses24hClock(self, value: bool) -> None:
        self.set_value(value, key='Uses24HourClock')

    @_reconnect_on_remote_close
    def enter_recovery(self):
        return self._request('EnterRecovery')

    def stop_session(self) -> dict:
        if self.session_id and self.service:
            response = self._request('StopSession', {'SessionID': self.session_id})
            self.session_id = None
            if not response or response.get('Result') != 'Success':
                raise CannotStopSessionError()
            return response

    def validate_pairing(self) -> bool:
        if self.pair_record is None:
            self.fetch_pair_record()

        if self.pair_record is None:
            return False

        if (Version(self.product_version) < Version('7.0')) and (self.device_class != DeviceClass.WATCH):
            try:
                self._request('ValidatePair', {'PairRecord': self.pair_record})
            except PairingError:
                return False

        self.host_id = self.pair_record.get('HostID', self.host_id)
        self.system_buid = self.pair_record.get('SystemBUID', self.system_buid)

        try:
            start_session = self._request('StartSession', {'HostID': self.host_id, 'SystemBUID': self.system_buid})
        except (InvalidHostIDError, InvalidConnectionError):
            # no host id means there is no such pairing record
            return False

        self.session_id = start_session.get('SessionID')
        if start_session.get('EnableSessionSSL'):
            with self.ssl_file() as f:
                try:
                    self.service.ssl_start(f)
                except SSLZeroReturnError:
                    # possible when we have a pair record, but it was removed on-device
                    self._reestablish_connection()
                    return False

        self.paired = True

        # reload data after pairing
        self.all_values = self.get_value()
        self.udid = self.all_values.get('UniqueDeviceID')

        return True

    @_reconnect_on_remote_close
    def pair(self, timeout: float = None, private_key: Optional[RSAPrivateKey] = None) -> None:
        self.device_public_key = self.get_value('', 'DevicePublicKey')
        if not self.device_public_key:
            self.logger.error('Unable to retrieve DevicePublicKey')
            self.service.close()
            raise PairingError()

        self.logger.info('Creating host key & certificate')
        cert_pem, private_key_pem, device_certificate = ca_do_everything(self.device_public_key,
                                                                         private_key=private_key)

        pair_record = {'DevicePublicKey': self.device_public_key,
                       'DeviceCertificate': device_certificate,
                       'HostCertificate': cert_pem,
                       'HostID': self.host_id,
                       'RootCertificate': cert_pem,
                       'RootPrivateKey': private_key_pem,
                       'WiFiMACAddress': self.wifi_mac_address,
                       'SystemBUID': self.system_buid}

        pair_options = {'PairRecord': pair_record, 'ProtocolVersion': '2',
                        'PairingOptions': {'ExtendedPairingErrors': True}}

        pair = self._request_pair(pair_options, timeout=timeout)

        pair_record['HostPrivateKey'] = private_key_pem
        escrow_bag = pair.get('EscrowBag')

        if escrow_bag is not None:
            pair_record['EscrowBag'] = pair.get('EscrowBag')

        self.pair_record = pair_record
        self.save_pair_record()
        self.paired = True

    @_reconnect_on_remote_close
    def pair_supervised(self, keybag_file: Path, timeout: Optional[float] = None) -> None:
        with open(keybag_file, 'rb') as keybag_file:
            keybag_file = keybag_file.read()
        private_key = serialization.load_pem_private_key(keybag_file, password=None)
        cer = x509.load_pem_x509_certificate(keybag_file)
        public_key = cer.public_bytes(Encoding.DER)

        self.device_public_key = self.get_value('', 'DevicePublicKey')
        if not self.device_public_key:
            self.logger.error('Unable to retrieve DevicePublicKey')
            self.service.close()
            raise PairingError()

        self.logger.info('Creating host key & certificate')
        cert_pem, private_key_pem, device_certificate = ca_do_everything(self.device_public_key)

        pair_record = {'DevicePublicKey': self.device_public_key,
                       'DeviceCertificate': device_certificate,
                       'HostCertificate': cert_pem,
                       'HostID': self.host_id,
                       'RootCertificate': cert_pem,
                       'RootPrivateKey': private_key_pem,
                       'WiFiMACAddress': self.wifi_mac_address,
                       'SystemBUID': self.system_buid}

        pair_options = {'PairRecord': pair_record, 'ProtocolVersion': '2',
                        'PairingOptions': {
                            'SupervisorCertificate': public_key,
                            'ExtendedPairingErrors': True}}

        # first pair with SupervisorCertificate as PairingOptions to get PairingChallenge
        pair = self._request_pair(pair_options, timeout=timeout)
        if pair.get('Error') == 'MCChallengeRequired':
            extended_response = pair.get('ExtendedResponse')
            if extended_response is not None:
                pairing_challenge = extended_response.get('PairingChallenge')
                signed_response = PKCS7SignatureBuilder().set_data(pairing_challenge).add_signer(
                    cer, private_key, hashes.SHA256()).sign(Encoding.DER, [])
                pair_options = {'PairRecord': pair_record, 'ProtocolVersion': '2', 'PairingOptions': {
                    'ChallengeResponse': signed_response, 'ExtendedPairingErrors': True}}
                # second pair with Response to Challenge
                pair = self._request_pair(pair_options, timeout=timeout)

        pair_record['HostPrivateKey'] = private_key_pem
        escrow_bag = pair.get('EscrowBag')

        if escrow_bag is not None:
            pair_record['EscrowBag'] = pair.get('EscrowBag')

        self.pair_record = pair_record
        self.save_pair_record()
        self.paired = True

    @_reconnect_on_remote_close
    def unpair(self, host_id: str = None) -> None:
        pair_record = self.pair_record if host_id is None else {'HostID': host_id}
        self._request('Unpair', {'PairRecord': pair_record, 'ProtocolVersion': '2'}, verify_request=False)

    @_reconnect_on_remote_close
    def reset_pairing(self):
        return self._request('ResetPairing', {'FullReset': True})

    @_reconnect_on_remote_close
    def get_value(self, domain: str = None, key: str = None):
        options = {}

        if domain:
            options['Domain'] = domain
        if key:
            options['Key'] = key

        res = self._request('GetValue', options)
        if res:
            r = res.get('Value')
            if hasattr(r, 'data'):
                return r.data
            return r

    @_reconnect_on_remote_close
    def remove_value(self, domain: str = None, key: str = None) -> dict:
        options = {}

        if domain:
            options['Domain'] = domain
        if key:
            options['Key'] = key

        return self._request('RemoveValue', options)

    @_reconnect_on_remote_close
    def set_value(self, value, domain: str = None, key: str = None) -> dict:
        options = {}

        if domain:
            options['Domain'] = domain
        if key:
            options['Key'] = key

        options['Value'] = value
        return self._request('SetValue', options)

    def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict:
        if not self.paired:
            raise NotPairedError()

        options = {'Service': name}
        if include_escrow_bag:
            options['EscrowBag'] = self.pair_record['EscrowBag']

        response = self._request('StartService', options)
        if not response or response.get('Error'):
            if response.get('Error', '') == 'PasswordProtected':
                raise PasswordRequiredError(
                    'your device is protected with password, please enter password in device and try again')
            raise StartServiceError(response.get('Error'))
        return response

    @_reconnect_on_remote_close
    def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        attr = self.get_service_connection_attributes(name, include_escrow_bag=include_escrow_bag)
        service_connection = self._create_service_connection(attr['Port'])

        if attr.get('EnableServiceSSL', False):
            with self.ssl_file() as f:
                service_connection.ssl_start(f)
        return service_connection

    async def aio_start_lockdown_service(
            self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        attr = self.get_service_connection_attributes(name, include_escrow_bag=include_escrow_bag)
        service_connection = self._create_service_connection(attr['Port'])

        if attr.get('EnableServiceSSL', False):
            with self.ssl_file() as f:
                await service_connection.aio_ssl_start(f)
        return service_connection

    def close(self) -> None:
        self.service.close()

    @contextmanager
    def ssl_file(self) -> str:
        cert_pem = self.pair_record['HostCertificate']
        private_key_pem = self.pair_record['HostPrivateKey']

        # use delete=False and manage the deletion ourselves because Windows
        # cannot use in-use files
        with tempfile.NamedTemporaryFile('w+b', delete=False) as f:
            f.write(cert_pem + b'\n' + private_key_pem)
            filename = f.name

        try:
            yield filename
        finally:
            os.unlink(filename)

    def _handle_autopair(self, autopair: bool, timeout: float, private_key: Optional[RSAPrivateKey] = None) -> None:
        if self.validate_pairing():
            return

        # device is not paired yet
        if not autopair:
            # but pairing by default was not requested
            return
        self.pair(timeout=timeout, private_key=private_key)
        # get session_id
        if not self.validate_pairing():
            raise FatalPairingError()

    @abstractmethod
    def _create_service_connection(self, port: int) -> ServiceConnection:
        """ Used to establish a new ServiceConnection to a given port """
        pass

    def _request(self, request: str, options: Optional[dict] = None, verify_request: bool = True) -> dict:
        message = {'Label': self.label, 'Request': request}
        if options:
            message.update(options)
        response = self.service.send_recv_plist(message)

        if verify_request and response.get('Request') != request:
            if response.get('Type') == RESTORED_SERVICE_TYPE:
                raise IncorrectModeError(f'Incorrect mode returned. Got: {response}')
            raise LockdownError(f'Incorrect response returned. Got: {response}')

        error = response.get('Error')
        if error is not None:
            # return response if supervisor cert challenge is required, to work with pair_supervisor
            if error == 'MCChallengeRequired':
                return response
            exception_errors = {'PasswordProtected': PasswordRequiredError,
                                'PairingDialogResponsePending': PairingDialogResponsePendingError,
                                'UserDeniedPairing': UserDeniedPairingError,
                                'InvalidHostID': InvalidHostIDError,
                                'GetProhibited': GetProhibitedError,
                                'SetProhibited': SetProhibitedError,
                                'MissingValue': MissingValueError,
                                'InvalidService': InvalidServiceError,
                                'InvalidConnection': InvalidConnectionError, }
            raise exception_errors.get(error, LockdownError)(error, self.identifier)

        # iOS < 5: 'Error' is not present, so we need to check the 'Result' instead
        if response.get('Result') == 'Failure':
            raise LockdownError('', self.identifier)

        return response

    def _request_pair(self, pair_options: dict, timeout: Optional[float] = None) -> dict:
        try:
            return self._request('Pair', pair_options)
        except PairingDialogResponsePendingError:
            if timeout == 0:
                raise

        self.logger.info('waiting user pairing dialog...')
        start = time.time()
        while timeout is None or time.time() <= start + timeout:
            with suppress(PairingDialogResponsePendingError):
                return self._request('Pair', pair_options)
            time.sleep(1)
        raise PairingDialogResponsePendingError()

    def fetch_pair_record(self) -> None:
        if self.identifier is not None:
            self.pair_record = get_preferred_pair_record(self.identifier, self.pairing_records_cache_folder)

    def save_pair_record(self) -> None:
        pair_record_file = self.pairing_records_cache_folder / f'{self.identifier}.plist'
        pair_record_file.write_bytes(plistlib.dumps(self.pair_record))

    def _reestablish_connection(self) -> None:
        self.close()
        self.service = self._create_service_connection(self.port)


class UsbmuxLockdownClient(LockdownClient):
    def __init__(self, service: ServiceConnection, host_id: str, identifier: str = None,
                 label: str = DEFAULT_LABEL, system_buid: str = SYSTEM_BUID, pair_record: Optional[dict] = None,
                 pairing_records_cache_folder: Path = None, port: int = SERVICE_PORT,
                 usbmux_address: Optional[str] = None):
        self.usbmux_address = usbmux_address
        super().__init__(service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder,
                         port)

    @property
    def short_info(self) -> dict:
        short_info = super().short_info
        short_info['ConnectionType'] = self.service.mux_device.connection_type
        return short_info

    def fetch_pair_record(self) -> None:
        if self.identifier is not None:
            self.pair_record = get_preferred_pair_record(self.identifier, self.pairing_records_cache_folder,
                                                         usbmux_address=self.usbmux_address)

    def _create_service_connection(self, port: int) -> ServiceConnection:
        return ServiceConnection.create_using_usbmux(self.identifier, port,
                                                     self.service.mux_device.connection_type,
                                                     usbmux_address=self.usbmux_address)


class PlistUsbmuxLockdownClient(UsbmuxLockdownClient):
    def save_pair_record(self) -> None:
        super().save_pair_record()
        record_data = plistlib.dumps(self.pair_record)
        with usbmux.create_mux() as client:
            client.save_pair_record(self.identifier, self.service.mux_device.devid, record_data)


class TcpLockdownClient(LockdownClient):
    def __init__(self, service: ServiceConnection, host_id: str, hostname: str, identifier: str = None,
                 label: str = DEFAULT_LABEL, system_buid: str = SYSTEM_BUID, pair_record: Optional[dict] = None,
                 pairing_records_cache_folder: Path = None, port: int = SERVICE_PORT, keep_alive: bool = True):
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
        super().__init__(service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder,
                         port)
        self._keep_alive = keep_alive
        self.hostname = hostname

    def _create_service_connection(self, port: int) -> ServiceConnection:
        return ServiceConnection.create_using_tcp(self.hostname, port, keep_alive=self._keep_alive)


class RemoteLockdownClient(LockdownClient):
    def _create_service_connection(self, port: int) -> ServiceConnection:
        raise NotImplementedError(
            'RemoteXPC service connections should only be created using RemoteServiceDiscoveryService')

    def _handle_autopair(self, *args, **kwargs):
        # The RemoteXPC version of lockdown doesn't support pairing operations
        return None

    def pair(self, *args, **kwargs) -> None:
        raise NotImplementedError('RemoteXPC lockdown version does not support pairing operations')

    def unpair(self, timeout: float = None) -> None:
        raise NotImplementedError('RemoteXPC lockdown version does not support pairing operations')

    def __init__(self, service: ServiceConnection, host_id: str, identifier: str = None,
                 label: str = DEFAULT_LABEL, system_buid: str = SYSTEM_BUID, pair_record: Optional[dict] = None,
                 pairing_records_cache_folder: Path = None, port: int = SERVICE_PORT):
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
        super().__init__(service, host_id, identifier, label, system_buid, pair_record, pairing_records_cache_folder,
                         port)


def create_using_usbmux(serial: str = None, identifier: str = None, label: str = DEFAULT_LABEL, autopair: bool = True,
                        connection_type: str = None, pair_timeout: float = None, local_hostname: str = None,
                        pair_record: Optional[dict] = None, pairing_records_cache_folder: Path = None,
                        port: int = SERVICE_PORT, usbmux_address: Optional[str] = None) -> UsbmuxLockdownClient:
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
    service = ServiceConnection.create_using_usbmux(serial, port, connection_type=connection_type,
                                                    usbmux_address=usbmux_address)
    try:
        cls = UsbmuxLockdownClient
        with usbmux.create_mux(usbmux_address=usbmux_address) as client:
            if isinstance(client, PlistMuxConnection):
                # Only the Plist version of usbmuxd supports this message type
                system_buid = client.get_buid()
                cls = PlistUsbmuxLockdownClient

        if identifier is None:
            # attempt get identifier from mux device serial
            identifier = service.mux_device.serial

        return cls.create(
            service, identifier=identifier, label=label, system_buid=system_buid, local_hostname=local_hostname,
            pair_record=pair_record, pairing_records_cache_folder=pairing_records_cache_folder,
            pair_timeout=pair_timeout,
            autopair=autopair, usbmux_address=usbmux_address)
    except Exception:
        service.close()
        raise


def retry_create_using_usbmux(retry_timeout: Optional[float] = None, **kwargs) -> UsbmuxLockdownClient:
    """
    Repeatedly retry to create a UsbmuxLockdownClient instance while dismissing different errors that might occur
    while device is rebooting

    :param retry_timeout: Retry timeout in seconds or None for no timeout
    :return: UsbmuxLockdownClient instance
    """
    start = time.time()
    while (retry_timeout is None) or (time.time() - start < retry_timeout):
        try:
            return create_using_usbmux(**kwargs)
        except (NoDeviceConnectedError, ConnectionFailedError, BadDevError, OSError, construct.core.StreamError,
                DeviceNotFoundError):
            pass


def create_using_tcp(hostname: str, identifier: str = None, label: str = DEFAULT_LABEL, autopair: bool = True,
                     pair_timeout: float = None, local_hostname: str = None, pair_record: Optional[dict] = None,
                     pairing_records_cache_folder: Path = None, port: int = SERVICE_PORT,
                     keep_alive: bool = False) -> TcpLockdownClient:
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
    service = ServiceConnection.create_using_tcp(hostname, port, keep_alive=keep_alive)
    try:
        return TcpLockdownClient.create(
            service, identifier=identifier, label=label, local_hostname=local_hostname, pair_record=pair_record,
            pairing_records_cache_folder=pairing_records_cache_folder, pair_timeout=pair_timeout, autopair=autopair,
            port=port, hostname=hostname, keep_alive=keep_alive)
    except Exception:
        service.close()
        raise


def create_using_remote(service: ServiceConnection, identifier: str = None, label: str = DEFAULT_LABEL,
                        autopair: bool = True, pair_timeout: float = None, local_hostname: str = None,
                        pair_record: Optional[dict] = None, pairing_records_cache_folder: Path = None,
                        port: int = SERVICE_PORT) -> RemoteLockdownClient:
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
        return RemoteLockdownClient.create(
            service, identifier=identifier, label=label, local_hostname=local_hostname, pair_record=pair_record,
            pairing_records_cache_folder=pairing_records_cache_folder, pair_timeout=pair_timeout, autopair=autopair,
            port=port)
    except Exception:
        service.close()
        raise


async def get_mobdev2_lockdowns(
        udid: Optional[str] = None, pair_records: Optional[Path] = None, only_paired: bool = False,
        timeout: float = DEFAULT_BONJOUR_TIMEOUT) \
        -> AsyncIterable[tuple[str, TcpLockdownClient]]:
    records = {}
    if pair_records is None:
        pair_records = get_home_folder()
    for file in pair_records.glob('*.plist'):
        if file.name.startswith('remote_'):
            # skip RemotePairing records
            continue
        record_udid = file.parts[-1].strip('.plist')
        if udid is not None and record_udid != udid:
            continue
        record = plistlib.loads(file.read_bytes())
        records[record['WiFiMACAddress']] = record

    iterated_ips = set()
    for answer in await browse_mobdev2(timeout=timeout):
        if '@' not in answer.name:
            continue
        wifi_mac_address = answer.name.split('@', 1)[0]
        record = records.get(wifi_mac_address)

        if only_paired and record is None:
            continue

        for ip in answer.ips:
            if ip in iterated_ips:
                # skip ips we already iterated over, possibly from previous queries
                continue
            iterated_ips.add(ip)
            try:
                lockdown = create_using_tcp(hostname=ip, autopair=False, pair_record=record)
            except Exception:
                continue
            if only_paired and not lockdown.paired:
                lockdown.close()
                continue
            yield ip, lockdown
